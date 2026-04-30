"""Stream manifest fetching, MPEG-DASH / BTS parsing, URL extraction.

Parses TIDAL's base64-encoded manifests without external dependencies
(no mpegdash, no isodate).
"""

from __future__ import annotations

import base64
import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from enum import Enum
from typing import Any

from ..client import Client
from ..exceptions import ManifestError, StreamError

try:
    from pywidevine import PSSH
except ImportError:
    PSSH = None


class Quality(str, Enum):
    LOW = "LOW"
    HIGH = "HIGH"
    LOSSLESS = "LOSSLESS"
    HI_RES_LOSSLESS = "HI_RES_LOSSLESS"
    HIRES_LOSSLESS = "HIRES_LOSSLESS"


class ManifestType(str, Enum):
    MPD = "application/dash+xml"
    BTS = "application/vnd.tidal.bts"


# Compat alias for mopidy-tidal
ManifestMimeType = ManifestType


class BTSManifest:
    """Parsed BTS manifest."""
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
    manifest_mime_type: str
    mpd: MpdInfo | None = None           # parsed MPD (None for BTS)
    bts: BTSManifest | None = None       # parsed BTS (None for MPD)
    # DRM
    drm_system: str = ""                 # "WIDEVINE" | "FAIRPLAY" | ""
    license_url: str = ""                # Widevine license server URL
    init_data: tuple[str, ...] = ()      # PSSH base64 strings

    @property
    def is_mpd(self) -> bool:
        return self.mpd is not None

    @property
    def is_bts(self) -> bool:
        return self.bts is not None

    @property
    def is_drm(self) -> bool:
        return bool(self.drm_system)


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
class MpdRepresentation:
    """Single Representation within an AdaptationSet."""
    id: str                # e.g. "FLAC,44100,16", "AACLC", "HEAACV1"
    codec: str             # normalised: "FLAC", "AAC", "EAC3"
    raw_codec: str         # original codecs attr: "flac", "mp4a.40.2"
    bandwidth: int
    sample_rate: int
    bit_depth: int
    init_url: str
    urls: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class MpdInfo:
    """Parsed MPD — mirrors the actual XML structure."""
    xml: str                                 # raw MPD XML string
    pssh_b64: str                            # Widevine PSSH base64
    default_kid: str                         # default_KID from mp4protection
    encryption_scheme: str                   # e.g. "cbcs" or "cenc"
    representations: tuple[MpdRepresentation, ...]  # all reps, highest bandwidth first


def _normalise_codec(raw: str) -> str:
    """Normalise a DASH codecs string to a short label."""
    low = raw.lower()
    if "flac" in low:
        return "FLAC"
    if "mp4a" in low:
        return "AAC"
    if "eac3" in low:
        return "EAC3"
    return raw.upper()


def _parse_representation(rep: ET.Element) -> MpdRepresentation:
    """Parse a single <Representation> element."""
    raw_codec = rep.get("codecs", "")
    rep_id = rep.get("id", "")

    bit_depth = 16
    parts = rep_id.split(",")
    if len(parts) >= 3:
        try:
            bit_depth = int(parts[2])
        except ValueError:
            pass

    seg_tpl = rep.find("mpd:SegmentTemplate", _NS)
    if seg_tpl is None:
        raise ManifestError("No SegmentTemplate in Representation")

    media_tpl = seg_tpl.get("media", "")
    start_number = int(seg_tpl.get("startNumber", "1"))

    timeline = seg_tpl.find("mpd:SegmentTimeline", _NS)
    seg_count = 0
    if timeline is not None:
        for s in timeline.findall("mpd:S", _NS):
            seg_count += int(s.get("r", "0")) + 1

    return MpdRepresentation(
        id=rep_id,
        codec=_normalise_codec(raw_codec),
        raw_codec=raw_codec,
        bandwidth=int(rep.get("bandwidth", "0")),
        sample_rate=int(rep.get("audioSamplingRate", "44100")),
        bit_depth=bit_depth,
        init_url=seg_tpl.get("initialization", ""),
        urls=tuple(
            media_tpl.replace("$Number$", str(i))
            for i in range(start_number, start_number + seg_count)
        ),
    )


def parse_mpd(xml_text: str) -> MpdInfo:
    """Parse an MPEG-DASH MPD into structured info.

    All Representations are preserved, sorted by bandwidth descending.
    """
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

    # --- Parse all Representations ----------------------------------------
    reps = adapt.findall("mpd:Representation", _NS)
    if not reps:
        raise ManifestError("No Representation in MPD")

    parsed = sorted(
        (_parse_representation(r) for r in reps),
        key=lambda r: r.bandwidth,
        reverse=True,
    )

    return MpdInfo(
        xml=xml_text,
        pssh_b64=pssh_b64,
        default_kid=default_kid,
        encryption_scheme=encryption_scheme,
        representations=tuple(parsed),
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
    quality: Quality | str = Quality.LOSSLESS,
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
    formats = _OAPI_FORMATS.get(q, _OAPI_FORMATS[Quality.LOSSLESS])

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

    drm = attrs.get("drmData") or {}

    raw = {
        "trackId": track_id,
        "manifestMimeType": mime,
        "manifest": manifest_b64,
        "drmSystem": drm.get("drmSystem", ""),
        "licenseUrl": drm.get("licenseUrl", ""),
        "initData": drm.get("initData", []),
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

    mpd: MpdInfo | None = None
    bts: BTSManifest | None = None

    if ManifestType.MPD.value in mime:
        mpd = parse_mpd(manifest_text)
    elif ManifestType.BTS.value in mime:
        bts = BTSManifest(json.loads(manifest_text))
    else:
        raise ManifestError(f"Unknown manifest type: {mime}")

    init_data = raw.get("initData") or []
    if not init_data and mpd and mpd.pssh_b64:
        init_data = [mpd.pssh_b64]

    return StreamInfo(
        track_id=raw.get("trackId", track_id),
        manifest_mime_type=mime,
        mpd=mpd,
        bts=bts,
        drm_system=raw.get("drmSystem", ""),
        license_url=raw.get("licenseUrl", ""),
        init_data=tuple(init_data),
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
    return resp.content


def get_decryption_keys(
    client: Client,
    stream: StreamInfo,
    *,
    cdm: Any,
    service_cert: bytes,
) -> list[tuple[str, str]]:
    """Exchange with TIDAL's Widevine license server, return (kid, key) hex pairs."""

    if not cdm:
        raise RuntimeError("No Widevine CDM loaded on session")
    session_id = cdm.open()

    try:
        cdm.set_service_certificate(session_id, service_cert)
        challenge = cdm.get_license_challenge(session_id, PSSH(stream.init_data[0]))

        resp = client.request(
            "POST", stream.license_url,
            data=challenge,
            headers={"Content-Type": "application/octet-stream"},
        )

        cdm.parse_license(session_id, resp.content)
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
