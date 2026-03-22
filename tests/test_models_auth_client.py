from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from tidalapi.auth import Auth, LinkLogin, _make_pkce
from tidalapi.client import Client
from tidalapi.models._base import _Model
from tidalapi.models.album import Album
from tidalapi.models.artist import Artist
from tidalapi.models.track import Track


# -- _Model base -------------------------------------------------------------


class TestModelBase:
    def test_repr(self):
        session = MagicMock()
        m = _Model({"id": 1, "name": "Test"}, session)
        # _Model doesn't parse fields, but repr uses getattr
        assert "_Model" in repr(m)

    def test_raw_stored(self):
        session = MagicMock()
        raw = {"id": 42}
        m = _Model(raw, session)
        assert m.raw is raw


# -- Artist -------------------------------------------------------------------


_ARTIST_RAW = {"id": 100, "name": "Radiohead", "picture": "abc-def", "popularity": 90}


class TestArtist:
    def test_fields(self):
        a = Artist(_ARTIST_RAW, MagicMock())
        assert a.id == 100
        assert a.name == "Radiohead"
        assert a.picture == "abc-def"

    def test_image(self):
        a = Artist(_ARTIST_RAW, MagicMock())
        url = a.image(320, 320)
        assert "abc/def" in url
        assert "320x320" in url

    def test_image_no_picture_raises(self):
        a = Artist({"id": 1, "name": "X"}, MagicMock())
        with pytest.raises(AttributeError):
            a.image()

    def test_repr(self):
        a = Artist(_ARTIST_RAW, MagicMock())
        assert "Radiohead" in repr(a)


# -- Album --------------------------------------------------------------------


_ALBUM_RAW = {
    "id": 200, "title": "OK Computer", "numberOfTracks": 12, "numberOfVolumes": 1,
    "duration": 3200, "releaseDate": "1997-06-16", "cover": "aa-bb-cc",
    "audioQuality": "LOSSLESS", "artists": [_ARTIST_RAW],
}


class TestAlbum:
    def test_fields(self):
        a = Album(_ALBUM_RAW, MagicMock())
        assert a.id == 200
        assert a.name == "OK Computer"
        assert a.num_tracks == 12
        assert a.release_date == "1997-06-16"

    def test_artist_from_artists_list(self):
        a = Album(_ALBUM_RAW, MagicMock())
        assert a.artist.name == "Radiohead"
        assert len(a.artists) == 1

    def test_image(self):
        a = Album(_ALBUM_RAW, MagicMock())
        url = a.image(640, 640)
        assert "aa/bb/cc" in url
        assert "640x640" in url

    def test_image_no_cover(self):
        a = Album({"id": 1, "title": "X"}, MagicMock())
        assert a.image() == ""


# -- Track --------------------------------------------------------------------


_TRACK_RAW = {
    "id": 300, "title": "Paranoid Android", "duration": 384,
    "trackNumber": 2, "volumeNumber": 1, "audioQuality": "LOSSLESS",
    "artists": [_ARTIST_RAW], "album": _ALBUM_RAW,
    "mediaMetadata": {"tags": ["LOSSLESS", "HIRES_LOSSLESS"]},
}


class TestTrack:
    def test_fields(self):
        t = Track(_TRACK_RAW, MagicMock())
        assert t.id == 300
        assert t.name == "Paranoid Android"
        assert t.duration == 384
        assert t.track_num == 2
        assert t.audio_quality == "LOSSLESS"

    def test_artists(self):
        t = Track(_TRACK_RAW, MagicMock())
        assert len(t.artists) == 1
        assert t.artist.name == "Radiohead"

    def test_album(self):
        t = Track(_TRACK_RAW, MagicMock())
        assert t.album.name == "OK Computer"

    def test_media_metadata_tags(self):
        t = Track(_TRACK_RAW, MagicMock())
        assert "LOSSLESS" in t.media_metadata_tags

    def test_full_name_with_version(self):
        raw = {**_TRACK_RAW, "version": "Remastered"}
        t = Track(raw, MagicMock())
        assert t.full_name == "Paranoid Android (Remastered)"

    def test_full_name_without_version(self):
        t = Track(_TRACK_RAW, MagicMock())
        assert t.full_name == "Paranoid Android"

    def test_no_album(self):
        raw = {**_TRACK_RAW}
        del raw["album"]
        t = Track(raw, MagicMock())
        assert t.album is None


# -- PKCE helpers -------------------------------------------------------------


class TestPkce:
    def test_make_pkce_returns_pair(self):
        verifier, challenge = _make_pkce()
        assert len(verifier) > 20
        assert len(challenge) > 20
        assert verifier != challenge


# -- Auth persistence ---------------------------------------------------------


class TestAuth:
    def _auth(self, **kw) -> Auth:
        defaults = dict(
            token_type="Bearer", access_token="tok", refresh_token="ref",
            expiry_time=datetime.now() + timedelta(hours=1),
            client_id="cid", client_secret="csec",
        )
        defaults.update(kw)
        return Auth(**defaults)

    def test_valid(self):
        a = self._auth()
        assert a.valid
        assert not a.expired

    def test_expired(self):
        a = self._auth(expiry_time=datetime.now() - timedelta(hours=1))
        assert a.expired
        assert not a.valid

    def test_header(self):
        a = self._auth(access_token="mytoken")
        assert a.header == {"Authorization": "Bearer mytoken"}

    def test_save_and_load(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name

        a = self._auth()
        a.save(path)

        loaded = Auth.from_file(path, client_id="cid", client_secret="csec")
        assert loaded.access_token == "tok"
        assert loaded.refresh_token == "ref"
        assert loaded.token_type == "Bearer"
        Path(path).unlink()

    def test_is_pkce_inferred_from_secret(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name

        a = self._auth(is_pkce=True)
        a.save(path)

        loaded = Auth.from_file(path, client_id="cid", client_secret="")
        assert loaded.is_pkce is True
        Path(path).unlink()


# -- LinkLogin ----------------------------------------------------------------


class TestLinkLogin:
    def test_from_json(self):
        j = {
            "verificationUri": "https://link.tidal.com",
            "verificationUriComplete": "https://link.tidal.com/ABCDE",
            "userCode": "ABCDE",
            "deviceCode": "dev123",
            "expiresIn": 300,
            "interval": 2,
        }
        ll = LinkLogin.from_json(j)
        assert ll.user_code == "ABCDE"
        assert ll.expires_in == 300.0
        assert ll.interval == 2.0


# -- Client.image_url ---------------------------------------------------------


class TestClientImageUrl:
    def test_basic(self):
        url = Client.image_url("aa-bb-cc-dd", 320, 320)
        assert url == "https://resources.tidal.com/images/aa/bb/cc/dd/320x320.jpg"

    def test_empty_uuid(self):
        assert Client.image_url("") == ""
