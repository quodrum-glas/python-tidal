from __future__ import annotations

import base64
import json

import pytest

from tidalapi.api.stream import BTSManifest, ManifestMimeType, ManifestType, Quality, StreamInfo, _build_stream_info
from tidalapi.exceptions import (
    AuthError,
    ManifestError,
    NotFoundError,
    ObjectNotFound,
    RateLimitError,
    StreamError,
    TidalError,
    TooManyRequests,
)
from tidalapi.utils import chunked_fetch, lazy, paginated_fetch

# -- lazy descriptor ----------------------------------------------------------


class TestLazy:
    def test_computes_once(self):
        calls = 0

        class Foo:
            @lazy
            def val(self):
                nonlocal calls
                calls += 1
                return 42

        f = Foo()
        assert f.val == 42
        assert f.val == 42
        assert calls == 1

    def test_per_instance(self):
        class Foo:
            @lazy
            def val(self):
                return id(self)

        a, b = Foo(), Foo()
        assert a.val != b.val

    def test_deletable(self):
        calls = 0

        class Foo:
            @lazy
            def val(self):
                nonlocal calls
                calls += 1
                return calls

        f = Foo()
        assert f.val == 1
        del f.val
        assert f.val == 2

    def test_class_access_returns_descriptor(self):
        class Foo:
            @lazy
            def val(self):
                return 1

        assert isinstance(Foo.__dict__["val"], lazy)


# -- chunked_fetch ------------------------------------------------------------


class TestChunkedFetch:
    def test_single_chunk(self):
        results = list(chunked_fetch(lambda ids: ids, [1, 2, 3], chunk_size=10))
        assert results == [[1, 2, 3]]

    def test_multiple_chunks(self):
        results = list(chunked_fetch(lambda ids: ids, list(range(5)), chunk_size=2))
        assert results == [[0, 1], [2, 3], [4]]

    def test_empty(self):
        results = list(chunked_fetch(lambda ids: ids, []))
        assert results == []


# -- paginated_fetch ----------------------------------------------------------


class TestPaginatedFetch:
    def test_single_page(self):
        def fn(params):
            return {"data": [1, 2], "links": {}}

        results = list(paginated_fetch(fn))
        assert len(results) == 1
        assert results[0]["data"] == [1, 2]

    def test_follows_cursor(self):
        call_count = 0

        def fn(params):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {"data": ["a"], "links": {"next": "https://api.tidal.com?page[cursor]=abc"}}
            return {"data": ["b"], "links": {}}

        results = list(paginated_fetch(fn))
        assert len(results) == 2
        assert call_count == 2


# -- exceptions ---------------------------------------------------------------


class TestExceptions:
    def test_hierarchy(self):
        assert issubclass(AuthError, TidalError)
        assert issubclass(NotFoundError, TidalError)
        assert issubclass(RateLimitError, TidalError)
        assert issubclass(StreamError, TidalError)
        assert issubclass(ManifestError, StreamError)

    def test_compat_aliases(self):
        assert ObjectNotFound is NotFoundError
        assert TooManyRequests is RateLimitError

    def test_tidal_error_attrs(self):
        e = TidalError("msg", status=404, payload={"x": 1})
        assert str(e) == "msg"
        assert e.status == 404
        assert e.payload == {"x": 1}

    def test_rate_limit_retry_after(self):
        e = RateLimitError("slow down", retry_after=30)
        assert e.retry_after == 30


# -- Quality enum -------------------------------------------------------------


class TestQuality:
    def test_values(self):
        assert Quality.LOW == "LOW"
        assert Quality.LOSSLESS == "LOSSLESS"
        assert Quality.HI_RES_LOSSLESS == "HI_RES_LOSSLESS"

    def test_compat_alias(self):
        assert Quality.HIRES_LOSSLESS.value == "HIRES_LOSSLESS"
        assert Quality.HI_RES_LOSSLESS.value == "HI_RES_LOSSLESS"

    def test_is_string(self):
        assert isinstance(Quality.HIGH, str)


class TestManifestType:
    def test_values(self):
        assert ManifestType.MPD.value == "application/dash+xml"
        assert ManifestType.BTS.value == "application/vnd.tidal.bts"

    def test_compat_alias(self):
        assert ManifestMimeType is ManifestType


# -- StreamInfo ---------------------------------------------------------------


class TestStreamInfo:
    def test_is_bts(self):
        info = StreamInfo(track_id=1, manifest_mime_type=ManifestType.BTS.value, bts=BTSManifest({}))
        assert info.is_bts
        assert not info.is_mpd

    def test_is_mpd(self):
        from mpegdash.parser import MPEGDASHParser

        mpd = MPEGDASHParser.parse(_MINIMAL_MPD)
        info = StreamInfo(track_id=2, manifest_mime_type=ManifestType.MPD.value, mpd=mpd)
        assert info.is_mpd
        assert not info.is_bts

    def test_is_drm(self):
        info = StreamInfo(track_id=1, manifest_mime_type=ManifestType.BTS.value)
        assert not info.is_drm
        info = StreamInfo(track_id=1, manifest_mime_type=ManifestType.BTS.value, drm_system="WIDEVINE")
        assert info.is_drm


# -- BTSManifest -------------------------------------------------------------


class TestBTSManifest:
    def test_get_codecs(self):
        m = BTSManifest({"codecs": "flac", "urls": []})
        assert m.get_codecs() == "flac"

    def test_get_urls(self):
        m = BTSManifest({"urls": ["a", "b"]})
        assert m.get_urls() == ["a", "b"]

    def test_empty(self):
        m = BTSManifest({})
        assert m.get_codecs() == ""
        assert m.get_urls() == []


# -- _build_stream_info -------------------------------------------------------


_MINIMAL_MPD = """\
<?xml version="1.0" encoding="UTF-8"?>
<MPD xmlns="urn:mpeg:dash:schema:mpd:2011">
  <Period>
    <AdaptationSet>
      <Representation codecs="flac" audioSamplingRate="96000">
        <SegmentTemplate initialization="init.mp4" media="seg-$Number$.m4f" startNumber="1">
          <SegmentTimeline>
            <S d="1000" r="2"/>
          </SegmentTimeline>
        </SegmentTemplate>
      </Representation>
    </AdaptationSet>
  </Period>
</MPD>
"""


class TestBuildStreamInfo:
    def test_bts_manifest(self):
        bts_json = json.dumps({"codecs": "flac", "urls": ["https://stream.tidal.com/track.flac"]})
        raw = {
            "trackId": 1,
            "manifestMimeType": ManifestType.BTS.value,
            "manifest": base64.b64encode(bts_json.encode()).decode(),
        }
        info = _build_stream_info(raw, 1)
        assert info.is_bts
        assert not info.is_mpd
        assert info.bts.get_urls() == ["https://stream.tidal.com/track.flac"]

    def test_mpd_manifest(self):
        raw = {
            "trackId": 2,
            "manifestMimeType": ManifestType.MPD.value,
            "manifest": base64.b64encode(_MINIMAL_MPD.encode()).decode(),
        }
        info = _build_stream_info(raw, 2)
        assert info.is_mpd
        assert not info.is_bts
        assert info.mpd is not None

    def test_unknown_manifest_raises(self):
        raw = {"trackId": 3, "manifestMimeType": "application/unknown", "manifest": base64.b64encode(b"data").decode()}
        with pytest.raises(ManifestError, match="Unknown manifest type"):
            _build_stream_info(raw, 3)

    def test_bad_base64_raises(self):
        raw = {"trackId": 4, "manifestMimeType": ManifestType.BTS.value, "manifest": "not-valid-base64!!!"}
        with pytest.raises(ManifestError, match="Failed to decode"):
            _build_stream_info(raw, 4)
