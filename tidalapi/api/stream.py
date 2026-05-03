"""Stream manifest fetching, MPEG-DASH / BTS parsing, URL extraction."""

from __future__ import annotations

import base64
import json
from enum import Enum
from typing import Any

from mpegdash.nodes import MPEGDASH
from mpegdash.parser import MPEGDASHParser

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


class StreamInfo:
    """Parsed stream: everything needed to play a track."""

    def __init__(
        self,
        track_id: int,
        manifest_mime_type: str,
        mpd: MPEGDASH | None = None,
        bts: BTSManifest | None = None,
        drm_system: str = "",
        license_url: str = "",
        init_data: tuple[str, ...] = (),
        **_: object,
    ) -> None:
        self.track_id = track_id
        self.manifest_mime_type = manifest_mime_type
        self.mpd = mpd
        self.bts = bts
        self.drm_system = drm_system
        self.license_url = license_url
        self.init_data = init_data

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
# MPD helpers
# ---------------------------------------------------------------------------

_WIDEVINE_URN = "urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_stream_v1(client: Client, track_id: int, quality: Quality | str = Quality.HIGH) -> StreamInfo:
    """Fetch playback info and parse the manifest into a StreamInfo."""
    q = quality.value if isinstance(quality, Quality) else quality
    raw = client.v1(
        f"tracks/{track_id}/playbackinfopostpaywall",
        {
            "playbackmode": "STREAM",
            "audioquality": q,
            "assetpresentation": "FULL",
        },
    )
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
    adaptive: bool = False,
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
        "adaptive": str(adaptive).lower(),
        "manifestType": "MPEG_DASH",  # For widevine
        "uriScheme": "DATA",  # For parsing in single request
        "usage": "PLAYBACK",
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
        raise ManifestError(f"Failed to decode manifest: {e}") from e

    mpd: MPEGDASH | None = None
    bts: BTSManifest | None = None

    if ManifestType.MPD.value in mime:
        mpd = MPEGDASHParser.parse(manifest_text)
        mpd.xml = manifest_text
    elif ManifestType.BTS.value in mime:
        bts = BTSManifest(json.loads(manifest_text))
    else:
        raise ManifestError(f"Unknown manifest type: {mime}")

    init_data = raw.get("initData") or []
    if not init_data and mpd:
        init_data = [
            cp.pssh[0].pssh
            for cp in mpd.periods[0].adaptation_sets[0].content_protections or []
            if (cp.scheme_id_uri or "").lower() == _WIDEVINE_URN and cp.pssh
        ]

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
        "POST",
        license_url,
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
            "POST",
            stream.license_url,
            data=challenge,
            headers={"Content-Type": "application/octet-stream"},
        )

        cdm.parse_license(session_id, resp.content)
        return [(key.kid.hex, key.key.hex()) for key in cdm.get_keys(session_id) if key.type == "CONTENT"]
    finally:
        cdm.close(session_id)


# ---------------------------------------------------------------------------
# Video
# ---------------------------------------------------------------------------


def get_video_url(client: Client, video_id: int, quality: str = "HIGH") -> str:
    """Get the HLS playlist URL for a video."""
    raw = client.v1(
        f"videos/{video_id}/urlpostpaywall",
        {
            "urlusagemode": "STREAM",
            "videoquality": quality,
            "assetpresentation": "FULL",
        },
    )
    urls = raw.get("urls", [])
    if not urls:
        raise StreamError("No video URL returned")
    return urls[0]
