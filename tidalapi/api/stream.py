"""Stream manifest fetching, MPEG-DASH / BTS parsing, URL extraction.

Parses TIDAL's base64-encoded manifests without external dependencies
(no mpegdash, no isodate).
"""

from __future__ import annotations

import base64
import json
import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..client import Client
from ..exceptions import ManifestError, StreamError

try:
    from pywidevine import PSSH
except ImportError:
    PSSH = None

logger = logging.getLogger(__name__)

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
    drm_system: str = ""          # "WIDEVINE" | "FAIRPLAY" | "" (no DRM)
    license_url: str = ""         # Widevine license server URL
    init_data: tuple[str, ...] = ()  # PSSH base64 strings from drmData
    formats: tuple[str, ...] = ()    # formats present in manifest (from oapi)
    track_presentation: str = ""     # "FULL" | "PREVIEW"
    preview_reason: str = ""         # why preview was served instead of full
    manifest_hash: str = ""          # unique manifest hash
    representation_id: str = ""       # e.g. "FLAC_HIRES,96000,24"
    duration: float = 0.0             # track duration in seconds (from MPD)
    raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @property
    def is_mpd(self) -> bool:
        return ManifestType.MPD.value in self.manifest_mime_type

    @property
    def is_bts(self) -> bool:
        return ManifestType.BTS.value in self.manifest_mime_type

    @property
    def is_drm(self) -> bool:
        return bool(self.drm_system)

    @property
    def is_preview(self) -> bool:
        return self.track_presentation == "PREVIEW"

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

_NS = {
    "mpd": "urn:mpeg:dash:schema:mpd:2011",
    "cenc": "urn:mpeg:cenc:2013",
}

# Widevine system ID
_WIDEVINE_URN = "urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"


@dataclass(frozen=True, slots=True)
class _MpdInfo:
    """Parsed MPD data."""
    codec: str
    init_url: str
    urls: tuple[str, ...]
    sample_rate: int
    bit_depth: int
    pssh_b64: str          # Widevine PSSH from ContentProtection (base64)
    default_kid: str       # default_KID from mp4protection
    encryption_scheme: str # e.g. "cbcs" or "cenc"
    representation_id: str # e.g. "FLAC_HIRES,96000,24"
    duration: float        # mediaPresentationDuration in seconds


def _parse_mpd(xml_text: str) -> _MpdInfo:
    """Parse an MPEG-DASH MPD into structured info.

    When the MPD contains multiple Representations (adaptive), picks the
    highest bandwidth (best quality).
    """
    if "<?xml" in xml_text:
        idx = xml_text.index("?>") + 2
        xml_text = xml_text[idx:].strip()

    root = ET.fromstring(xml_text)

    # Parse duration from mediaPresentationDuration="PT3M27.438S"
    import re
    duration = 0.0
    dur_str = root.get("mediaPresentationDuration", "")
    dur_match = re.match(r"PT(?:(\d+)H)?(?:(\d+)M)?(?:([\d.]+)S)?", dur_str)
    if dur_match:
        duration = (
            int(dur_match.group(1) or 0) * 3600
            + int(dur_match.group(2) or 0) * 60
            + float(dur_match.group(3) or 0)
        )

    period = root.find("mpd:Period", _NS)
    if period is None:
        raise ManifestError("No Period in MPD")
    adapt = period.find("mpd:AdaptationSet", _NS)
    if adapt is None:
        raise ManifestError("No AdaptationSet in MPD")

    # --- ContentProtection (on AdaptationSet level) -----------------------
    pssh_b64 = ""
    default_kid = ""
    encryption_scheme = ""
    for cp in adapt.findall("mpd:ContentProtection", _NS):
        scheme = cp.get("schemeIdUri", "")
        if scheme == "urn:mpeg:dash:mp4protection:2011":
            encryption_scheme = cp.get("value", "")
            kid = cp.get(f"{{{_NS['cenc']}}}default_KID", "")
            if kid:
                default_kid = kid
        elif scheme.lower() == _WIDEVINE_URN:
            pssh_el = cp.find("cenc:pssh", _NS)
            if pssh_el is not None and pssh_el.text:
                pssh_b64 = pssh_el.text.strip()

    # --- Pick Representation ----------------------------------------------
    reps = adapt.findall("mpd:Representation", _NS)
    if not reps:
        raise ManifestError("No Representation in MPD")

    rep = max(reps, key=lambda r: int(r.get("bandwidth", "0")))

    codec = rep.get("codecs", "")
    sample_rate = int(rep.get("audioSamplingRate", "44100"))

    # Bit depth from @id convention (e.g. "FLAC_HIRES,96000,24")
    bit_depth = 16
    rep_id = rep.get("id", "")
    parts = rep_id.split(",")
    if len(parts) >= 3:
        try:
            bit_depth = int(parts[2])
        except ValueError:
            pass

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

    return _MpdInfo(
        codec=codec,
        init_url=init_url,
        urls=urls,
        sample_rate=sample_rate,
        bit_depth=bit_depth,
        pssh_b64=pssh_b64,
        default_kid=default_kid,
        encryption_scheme=encryption_scheme,
        representation_id=rep_id,
        duration=duration,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_stream_v1(client: Client, track_id: int, quality: Quality | str = Quality.HIGH) -> StreamInfo:
    """Fetch playback info and parse the manifest into a StreamInfo."""
    q = quality.value if isinstance(quality, Quality) else quality
    raw = client.v1(f"tracks/{track_id}/playbackinfopostpaywall", {
        "playbackmode": "STREAM",
        "audioquality": q,
        "assetpresentation": "FULL",
    })
    return _build_stream_info(raw, track_id)


# OAS enum: HEAACV1, AACLC, FLAC, FLAC_HIRES, EAC3_JOC
_OAPI_FORMATS: dict[Quality, list[str]] = {
    Quality.LOW: ["AACLC"],
    Quality.HIGH: ["AACLC", "HEAACV1"],
    Quality.LOSSLESS: ["AACLC", "HEAACV1", "FLAC"],
    Quality.HI_RES_LOSSLESS: ["AACLC", "HEAACV1", "FLAC", "FLAC_HIRES"],
    Quality.HIRES_LOSSLESS: ["AACLC", "HEAACV1", "FLAC", "FLAC_HIRES"],
}


def get_stream_oapi(
    client: Client,
    track_id: int,
    quality: Quality | str = Quality.HIGH,
    *,
    usage: str = "PLAYBACK",
) -> StreamInfo:
    """Fetch stream via OpenAPI v2 trackManifests endpoint.

    OAS parameters (all required):
      manifestType: HLS | MPEG_DASH
      formats:      HEAACV1 | AACLC | FLAC | FLAC_HIRES | EAC3_JOC
      uriScheme:    HTTPS | DATA
      usage:        PLAYBACK | DOWNLOAD
      adaptive:     boolean
    """
    q = Quality(quality) if isinstance(quality, str) else quality
    formats = _OAPI_FORMATS.get(q, ["AACLC", "HEAACV1", "FLAC"])

    params = {
        "adaptive": "true",
        "manifestType": "MPEG_DASH",
        "uriScheme": "DATA",
        "usage": usage,
        "formats": formats,
    }

    resp = client.oapi(f"trackManifests/{track_id}", params=params)
    attrs = resp.get("data", {}).get("attributes", {})

    # uri is "data:{mime};base64,{payload}" (DATA scheme) or plain URL (HTTPS)
    uri = attrs.get("uri", "")
    if uri.startswith("data:"):
        header, _, payload = uri.partition(",")
        mime = header.removeprefix("data:").removesuffix(";base64")
        manifest_b64 = payload
    else:
        mime = ""
        manifest_b64 = ""

    norm_album = attrs.get("albumAudioNormalizationData") or {}
    norm_track = attrs.get("trackAudioNormalizationData") or {}
    drm = attrs.get("drmData") or {}

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
        "drmSystem": drm.get("drmSystem", ""),
        "licenseUrl": drm.get("licenseUrl", ""),
        "initData": drm.get("initData", []),
        "formats": attrs.get("formats", []),
        "trackPresentation": attrs.get("trackPresentation", ""),
        "previewReason": attrs.get("previewReason", ""),
        "manifestHash": attrs.get("hash", ""),
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
    bit_depth = raw.get("bitDepth", 16)
    pssh_from_mpd = ""
    default_kid = ""
    encryption_scheme = ""
    representation_id = ""
    duration = 0.0

    if ManifestType.MPD.value in mime:
        mpd = _parse_mpd(manifest_text)
        codec = mpd.codec
        init_url = mpd.init_url
        urls = mpd.urls
        sr = mpd.sample_rate
        bit_depth = mpd.bit_depth
        pssh_from_mpd = mpd.pssh_b64
        default_kid = mpd.default_kid
        encryption_scheme = mpd.encryption_scheme
        representation_id = mpd.representation_id
        duration = mpd.duration
    elif ManifestType.BTS.value in mime:
        bts = json.loads(manifest_text)
        urls = tuple(bts.get("urls", []))
        codec = bts.get("codecs", "").upper().split(".")[0]
        sr = raw.get("sampleRate", 44100)
    else:
        raise ManifestError(f"Unknown manifest type: {mime}")

    # init_data: prefer API drmData, fall back to MPD PSSH
    init_data = raw.get("initData") or []
    if not init_data and pssh_from_mpd:
        init_data = [pssh_from_mpd]

    return StreamInfo(
        track_id=raw.get("trackId", track_id),
        audio_quality=raw.get("audioQuality", ""),
        audio_mode=raw.get("audioMode", "STEREO"),
        manifest_mime_type=mime,
        bit_depth=bit_depth,
        sample_rate=sr,
        codec=codec,
        urls=urls,
        init_url=init_url,
        album_replay_gain=raw.get("albumReplayGain", 0.0),
        album_peak_amplitude=raw.get("albumPeakAmplitude", 1.0),
        track_replay_gain=raw.get("trackReplayGain", 0.0),
        track_peak_amplitude=raw.get("trackPeakAmplitude", 1.0),
        drm_system=raw.get("drmSystem", ""),
        license_url=raw.get("licenseUrl", ""),
        init_data=tuple(init_data),
        formats=tuple(raw.get("formats") or ()),
        track_presentation=raw.get("trackPresentation", ""),
        preview_reason=raw.get("previewReason", ""),
        manifest_hash=raw.get("manifestHash", ""),
        representation_id=representation_id,
        duration=duration,
        raw=raw,
    )


# ---------------------------------------------------------------------------
# Widevine DRM key exchange
# ---------------------------------------------------------------------------

_CERT_REQUEST = bytes([0x08, 0x04])


def fetch_service_certificate(client: Client, license_url: str) -> bytes:
    """Fetch the Widevine service certificate from the license server."""
    resp = client.request(
        "POST", license_url,
        data=_CERT_REQUEST,
        headers={"Content-Type": "application/octet-stream"},
    )
    logger.debug(f"cert resp len: {len(resp.content)}")
    return resp.content


def get_decryption_keys(
    client: Client,
    stream: StreamInfo,
    *,
    cdm: Any,
    service_cert: bytes,
) -> list[tuple[str, str]]:
    """Exchange with TIDAL's Widevine license server, return (kid, key) hex pairs."""
    logger.debug(f"get_decryption_keys: {stream.track_id}")

    if not cdm:
        raise RuntimeError("No Widevine CDM loaded on session")
    session_id = cdm.open()
    logger.debug(f"cdm session_id: {session_id}")

    try:
        cdm.set_service_certificate(session_id, service_cert)
        challenge = cdm.get_license_challenge(session_id, PSSH(stream.init_data[0]))
        logger.debug(f"built challenge of len: {len(challenge)}")

        resp = client.request(
            "POST", stream.license_url,
            data=challenge,
            headers={"Content-Type": "application/octet-stream"},
        )
        logger.debug(f"licence resp len: {len(resp.content)}")

        cdm.parse_license(session_id, resp.content)
        logger.debug(f"cdm parsed licence")
        return [
            (key.kid.hex, key.key.hex())
            for key in cdm.get_keys(session_id)
            if key.type == "CONTENT"
        ]
    finally:
        cdm.close(session_id)


# ---------------------------------------------------------------------------
# Video
# ---------------------------------------------------------------------------

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
