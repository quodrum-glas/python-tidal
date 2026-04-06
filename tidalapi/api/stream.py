"""Stream manifest fetching, MPEG-DASH / BTS parsing, URL extraction.

Parses TIDAL's base64-encoded manifests without external dependencies
(no mpegdash, no isodate).
"""

from __future__ import annotations

import base64
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..client import Client
from ..exceptions import ManifestError, StreamError


class Quality(str, Enum):
    LOW = "LOW"
    HIGH = "HIGH"
    LOSSLESS = "LOSSLESS"
    HI_RES_LOSSLESS = "HI_RES_LOSSLESS"
    HIRES_LOSSLESS = "HIRES_LOSSLESS"
    # Compat aliases (python-tidal style)
    hi_res_lossless = "HI_RES_LOSSLESS"


class ManifestType(str, Enum):
    MPD = "application/dash+xml"
    BTS = "application/vnd.tidal.bts"


# Compat alias for mopidy-tidal
ManifestMimeType = ManifestType


class _BTSManifest:
    """Parsed BTS manifest — compat with python-tidal's manifest.get_codecs()/get_urls()."""
    def __init__(self, data: dict):
        self._data = data
    def get_codecs(self) -> str:
        return self._data.get("codecs", "")
    def get_urls(self) -> list[str]:
        return self._data.get("urls", [])


@dataclass(frozen=True, slots=True)
class StreamInfo:
    """Parsed stream: everything needed to play a track."""

    track_id: int
    audio_quality: str
    audio_mode: str
    manifest_mime_type: str
    bit_depth: int
    sample_rate: int
    codec: str
    urls: tuple[str, ...]  # media segment URLs (numbered from startNumber)
    init_url: str = ""     # DASH init segment URL (empty for BTS)
    album_replay_gain: float = 0.0
    album_peak_amplitude: float = 1.0
    track_replay_gain: float = 0.0
    track_peak_amplitude: float = 1.0
    raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @property
    def is_mpd(self) -> bool:
        return ManifestType.MPD.value in self.manifest_mime_type

    @property
    def is_bts(self) -> bool:
        return ManifestType.BTS.value in self.manifest_mime_type

    @property
    def mime_type(self) -> str:
        c = self.codec.upper()
        if c == "FLAC":
            return "audio/flac"
        if c in ("EAC3",):
            return "audio/eac3"
        return "audio/mp4"

    @property
    def file_extension(self) -> str:
        c = self.codec.upper()
        if c == "FLAC":
            return ".flac"
        if c == "MP3":
            return ".mp3"
        return ".m4a"

    def get_manifest_data(self) -> str | None:
        """Return raw MPD XML string (for MPD manifests), or None."""
        if not self.is_mpd:
            return None
        manifest_b64 = self.raw.get("manifest", "")
        try:
            return base64.b64decode(manifest_b64).decode("utf-8")
        except Exception:
            return None

    def get_stream_manifest(self) -> _BTSManifest | None:
        """Return parsed BTS manifest, or None."""
        if not self.is_bts:
            return None
        manifest_b64 = self.raw.get("manifest", "")
        try:
            data = json.loads(base64.b64decode(manifest_b64).decode("utf-8"))
        except Exception:
            return None
        return _BTSManifest(data)


# ---------------------------------------------------------------------------
# MPD parsing (self-contained, no mpegdash dependency)
# ---------------------------------------------------------------------------

_NS = {"mpd": "urn:mpeg:dash:schema:mpd:2011"}


def _parse_mpd(xml_text: str) -> tuple[str, str, tuple[str, ...], int]:
    """Parse an MPEG-DASH MPD → (codec, init_url, media_segment_urls, sample_rate)."""
    if "<?xml" in xml_text:
        idx = xml_text.index("?>") + 2
        xml_text = xml_text[idx:].strip()

    root = ET.fromstring(xml_text)

    period = root.find("mpd:Period", _NS)
    if period is None:
        raise ManifestError("No Period in MPD")
    adapt = period.find("mpd:AdaptationSet", _NS)
    if adapt is None:
        raise ManifestError("No AdaptationSet in MPD")
    rep = adapt.find("mpd:Representation", _NS)
    if rep is None:
        raise ManifestError("No Representation in MPD")

    codec = rep.get("codecs", "")
    sample_rate = int(rep.get("audioSamplingRate", "44100"))

    seg_tpl = rep.find("mpd:SegmentTemplate", _NS)
    if seg_tpl is None:
        raise ManifestError("No SegmentTemplate in MPD")

    init_url = seg_tpl.get("initialization", "")
    media_tpl = seg_tpl.get("media", "")
    start_number = int(seg_tpl.get("startNumber", "1"))

    # Count segments from SegmentTimeline
    timeline = seg_tpl.find("mpd:SegmentTimeline", _NS)
    seg_count = 0
    if timeline is not None:
        for s in timeline.findall("mpd:S", _NS):
            seg_count += int(s.get("r", "0")) + 1

    urls = tuple(
        media_tpl.replace("$Number$", str(i))
        for i in range(start_number, start_number + seg_count)
    )

    # Normalise codec
    if "flac" in codec.lower():
        codec = "FLAC"
    elif "mp4a" in codec.lower():
        codec = "AAC"
    elif "eac3" in codec.lower():
        codec = "EAC3"

    return codec, init_url, urls, sample_rate


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_stream(client: Client, track_id: int, quality: Quality | str = Quality.HIGH) -> StreamInfo:
    """Fetch playback info and parse the manifest into a StreamInfo."""
    q = quality.value if isinstance(quality, Quality) else quality
    raw = client.v1(f"tracks/{track_id}/playbackinfopostpaywall", {
        "playbackmode": "STREAM",
        "audioquality": q,
        "assetpresentation": "FULL",
    })
    return _build_stream_info(raw, track_id)


_OAPI_FORMATS = {
    Quality.LOW: ["AACLC"],
    Quality.HIGH: ["AACLC", "HEAACV1"],
    Quality.LOSSLESS: ["AACLC", "HEAACV1", "FLAC"],
    Quality.HI_RES_LOSSLESS: ["AACLC", "HEAACV1", "FLAC"],
}


def get_stream_oapi(client: Client, track_id: int, quality: Quality | str = Quality.HIGH) -> StreamInfo:
    """Fetch stream via OpenAPI v2 trackManifests endpoint."""
    q = Quality(quality) if isinstance(quality, str) else quality
    formats = _OAPI_FORMATS.get(q, ["AACLC", "HEAACV1", "FLAC"])
    
    # Build params dict with repeated formats
    params = {
        "adaptive": "true",
        "manifestType": "MPEG_DASH",
        "uriScheme": "DATA",
        "usage": "PLAYBACK",
        "formats": formats,  # oapi method will handle repeated params
    }

    resp = client.oapi(f"trackManifests/{track_id}", params=params)
    raw_outer = resp
    attrs = raw_outer.get("data", {}).get("attributes", {})

    # uri is "data:{mime};base64,{payload}"
    uri = attrs.get("uri", "")
    if uri.startswith("data:"):
        header, _, payload = uri.partition(",")
        # header = "data:application/dash+xml;base64"
        mime = header.removeprefix("data:").removesuffix(";base64")
        manifest_b64 = payload
    else:
        mime = ""
        manifest_b64 = ""

    norm_album = attrs.get("albumAudioNormalizationData", {})
    norm_track = attrs.get("trackAudioNormalizationData", {})

    raw = {
        "trackId": track_id,
        "audioQuality": q.value,
        "audioMode": "STEREO",
        "manifestMimeType": mime,
        "manifest": manifest_b64,
        "bitDepth": 16,
        "sampleRate": 44100,
        "albumReplayGain": norm_album.get("replayGain", 0.0),
        "albumPeakAmplitude": norm_album.get("peakAmplitude", 1.0),
        "trackReplayGain": norm_track.get("replayGain", 0.0),
        "trackPeakAmplitude": norm_track.get("peakAmplitude", 1.0),
    }
    return _build_stream_info(raw, track_id)

def _build_stream_info(raw: dict, track_id: int) -> StreamInfo:
    """Parse a playbackinfo response dict into a StreamInfo."""
    manifest_b64 = raw.get("manifest", "")
    mime = raw.get("manifestMimeType", "")

    try:
        manifest_text = base64.b64decode(manifest_b64).decode("utf-8")
    except Exception as e:
        raise ManifestError(f"Failed to decode manifest: {e}")

    init_url = ""
    if ManifestType.MPD.value in mime:
        codec, init_url, urls, sr = _parse_mpd(manifest_text)
    elif ManifestType.BTS.value in mime:
        bts = json.loads(manifest_text)
        urls = tuple(bts.get("urls", []))
        codec = bts.get("codecs", "").upper().split(".")[0]
        sr = raw.get("sampleRate", 44100)
    else:
        raise ManifestError(f"Unknown manifest type: {mime}")

    return StreamInfo(
        track_id=raw.get("trackId", track_id),
        audio_quality=raw.get("audioQuality", ""),
        audio_mode=raw.get("audioMode", "STEREO"),
        manifest_mime_type=mime,
        bit_depth=raw.get("bitDepth", 16),
        sample_rate=sr,
        codec=codec,
        urls=urls,
        init_url=init_url,
        album_replay_gain=raw.get("albumReplayGain", 0.0),
        album_peak_amplitude=raw.get("albumPeakAmplitude", 1.0),
        track_replay_gain=raw.get("trackReplayGain", 0.0),
        track_peak_amplitude=raw.get("trackPeakAmplitude", 1.0),
        raw=raw,
    )


def get_video_url(client: Client, video_id: int, quality: str = "HIGH") -> str:
    """Get the HLS playlist URL for a video."""
    raw = client.v1(f"videos/{video_id}/urlpostpaywall", {
        "urlusagemode": "STREAM",
        "videoquality": quality,
        "assetpresentation": "FULL",
    })
    urls = raw.get("urls", [])
    if not urls:
        raise StreamError("No video URL returned")
    return urls[0]
