from __future__ import annotations

import base64
import json

import pytest

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
from tidalapi.stream import (
    ManifestMimeType,
    ManifestType,
    Quality,
    StreamInfo,
    _BTSManifest,
    _parse_mpd,
)
from tidalapi.utils import lazy


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
        assert Quality.hi_res_lossless == Quality.HI_RES_LOSSLESS

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
    def _bts_info(self, **kw) -> StreamInfo:
        defaults = dict(
            track_id=1, audio_quality="HIGH", audio_mode="STEREO",
            manifest_mime_type=ManifestType.BTS.value,
            bit_depth=16, sample_rate=44100, codec="AAC",
            urls=("https://stream/1.m4a",),
        )
        defaults.update(kw)
        return StreamInfo(**defaults)

    def _mpd_info(self, **kw) -> StreamInfo:
        defaults = dict(
            track_id=2, audio_quality="LOSSLESS", audio_mode="STEREO",
            manifest_mime_type=ManifestType.MPD.value,
            bit_depth=16, sample_rate=44100, codec="FLAC",
            urls=("seg-1", "seg-2"), init_url="init.mp4",
        )
        defaults.update(kw)
        return StreamInfo(**defaults)

    def test_is_bts(self):
        assert self._bts_info().is_bts
        assert not self._bts_info().is_mpd

    def test_is_mpd(self):
        assert self._mpd_info().is_mpd
        assert not self._mpd_info().is_bts

    def test_mime_type_flac(self):
        assert self._mpd_info(codec="FLAC").mime_type == "audio/flac"

    def test_mime_type_aac(self):
        assert self._bts_info(codec="AAC").mime_type == "audio/mp4"

    def test_file_extension(self):
        assert self._mpd_info(codec="FLAC").file_extension == ".flac"
        assert self._bts_info(codec="MP3").file_extension == ".mp3"
        assert self._bts_info(codec="AAC").file_extension == ".m4a"

    def test_get_manifest_data_mpd(self):
        xml = "<MPD>test</MPD>"
        b64 = base64.b64encode(xml.encode()).decode()
        info = self._mpd_info(raw={"manifest": b64})
        assert info.get_manifest_data() == xml

    def test_get_manifest_data_bts_returns_none(self):
        assert self._bts_info().get_manifest_data() is None

    def test_get_stream_manifest_bts(self):
        data = {"codecs": "flac", "urls": ["https://a.flac"]}
        b64 = base64.b64encode(json.dumps(data).encode()).decode()
        info = self._bts_info(raw={"manifest": b64})
        m = info.get_stream_manifest()
        assert m.get_codecs() == "flac"
        assert m.get_urls() == ["https://a.flac"]

    def test_get_stream_manifest_mpd_returns_none(self):
        assert self._mpd_info().get_stream_manifest() is None


# -- BTSManifest -------------------------------------------------------------


class TestBTSManifest:
    def test_get_codecs(self):
        m = _BTSManifest({"codecs": "flac", "urls": []})
        assert m.get_codecs() == "flac"

    def test_get_urls(self):
        m = _BTSManifest({"urls": ["a", "b"]})
        assert m.get_urls() == ["a", "b"]

    def test_empty(self):
        m = _BTSManifest({})
        assert m.get_codecs() == ""
        assert m.get_urls() == []


# -- MPD parsing --------------------------------------------------------------


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


class TestParseMpd:
    def test_basic(self):
        codec, init_url, urls, sr = _parse_mpd(_MINIMAL_MPD)
        assert codec == "FLAC"
        assert init_url == "init.mp4"
        assert len(urls) == 3
        assert urls[0] == "seg-1.m4f"
        assert sr == 96000

    def test_aac_codec(self):
        mpd = _MINIMAL_MPD.replace("flac", "mp4a.40.2")
        codec, _, _, _ = _parse_mpd(mpd)
        assert codec == "AAC"

    def test_missing_period_raises(self):
        with pytest.raises(Exception):
            _parse_mpd('<MPD xmlns="urn:mpeg:dash:schema:mpd:2011"></MPD>')
