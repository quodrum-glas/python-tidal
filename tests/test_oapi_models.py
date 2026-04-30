from __future__ import annotations

from unittest.mock import MagicMock

from tidalapi.jsonapi import Document, Resource
from tidalapi.models import Album, Artist, Model, Playlist, Track, Video, wrap
from tidalapi.types import ResourceType


def _doc(data: dict, included: list | None = None) -> Document:
    raw = {"data": data}
    if included:
        raw["included"] = included
    return Document(raw)


def _client() -> MagicMock:
    return MagicMock()


# -- Model base ---------------------------------------------------------------


class TestModelBase:
    def test_id(self):
        doc = _doc({"type": "tracks", "id": "42", "attributes": {"title": "Song"}})
        m = Model(doc.primary, doc, _client())
        assert m.id == "42"

    def test_repr(self):
        doc = _doc({"type": "tracks", "id": "1", "attributes": {"title": "Hello"}})
        m = Model(doc.primary, doc, _client())
        assert "Model" in repr(m)
        assert "Hello" in repr(m)

    def test_repr_name_fallback(self):
        doc = _doc({"type": "artists", "id": "1", "attributes": {"name": "Radiohead"}})
        m = Model(doc.primary, doc, _client())
        assert "Radiohead" in repr(m)


# -- Track --------------------------------------------------------------------


class TestOapiTrack:
    def _make(self, attrs=None, rels=None, included=None):
        data = {"type": "tracks", "id": "100", "attributes": attrs or {}, "relationships": rels or {}}
        doc = _doc(data, included)
        return Track(doc.primary, doc, _client())

    def test_title_and_name(self):
        t = self._make({"title": "Paranoid Android"})
        assert t.title == "Paranoid Android"
        assert t.name == "Paranoid Android"

    def test_version(self):
        t = self._make({"title": "Song", "version": "Remastered"})
        assert t.full_name == "Song (Remastered)"

    def test_no_version(self):
        t = self._make({"title": "Song"})
        assert t.full_name == "Song"

    def test_duration(self):
        t = self._make({"duration": "PT4M36S"})
        assert t.duration == 276

    def test_media_tags(self):
        t = self._make({"mediaTags": ["LOSSLESS", "HIRES_LOSSLESS"]})
        assert "LOSSLESS" in t.media_tags

    def test_track_num_from_meta(self):
        data = {"type": "tracks", "id": "1", "attributes": {}, "meta": {"trackNumber": 5}}
        doc = _doc(data)
        t = Track(doc.primary, doc, _client())
        assert t.track_num == 5

    def test_artists_relationship(self):
        t = self._make(
            rels={"artists": {"data": [{"type": "artists", "id": "10"}]}},
            included=[{"type": "artists", "id": "10", "attributes": {"name": "Radiohead"}}],
        )
        assert len(t.artists) == 1
        assert t.artist.name == "Radiohead"

    def test_album_relationship(self):
        t = self._make(
            rels={"albums": {"data": [{"type": "albums", "id": "20"}]}},
            included=[{"type": "albums", "id": "20", "attributes": {"title": "OK Computer"}}],
        )
        assert t.album.name == "OK Computer"

    def test_no_artist(self):
        t = self._make()
        assert t.artist is None

    def test_no_album(self):
        t = self._make()
        assert t.album is None

    def test_properties(self):
        t = self._make({"isrc": "US1234", "explicit": True, "popularity": 85.0, "bpm": 120.5})
        assert t.isrc == "US1234"
        assert t.explicit is True
        assert t.popularity == 85.0
        assert t.bpm == 120.5


# -- Album --------------------------------------------------------------------


class TestOapiAlbum:
    def _make(self, attrs=None, rels=None, included=None):
        data = {"type": "albums", "id": "200", "attributes": attrs or {}, "relationships": rels or {}}
        doc = _doc(data, included)
        return Album(doc.primary, doc, _client())

    def test_title_and_name(self):
        a = self._make({"title": "OK Computer"})
        assert a.name == "OK Computer"

    def test_num_tracks(self):
        a = self._make({"numberOfItems": 12})
        assert a.num_tracks == 12

    def test_release_date(self):
        a = self._make({"releaseDate": "1997-06-16"})
        assert a.release_date == "1997-06-16"

    def test_artists_relationship(self):
        a = self._make(
            rels={"artists": {"data": [{"type": "artists", "id": "10"}]}},
            included=[{"type": "artists", "id": "10", "attributes": {"name": "Radiohead"}}],
        )
        assert len(a.artists) == 1
        assert a.artist.name == "Radiohead"

    def test_tracks_relationship(self):
        a = self._make(
            rels={"items": {"data": [{"type": "tracks", "id": "1", "meta": {"trackNumber": 1}}]}},
            included=[{"type": "tracks", "id": "1", "attributes": {"title": "Song"}}],
        )
        assert len(a.tracks) == 1
        assert a.tracks[0].name == "Song"

    def test_properties(self):
        a = self._make({"explicit": True, "popularity": 90.0, "albumType": "ALBUM", "mediaTags": ["LOSSLESS"]})
        assert a.explicit is True
        assert a.popularity == 90.0
        assert a.album_type == "ALBUM"
        assert "LOSSLESS" in a.media_tags


# -- Artist -------------------------------------------------------------------


class TestOapiArtist:
    def _make(self, attrs=None, rels=None, included=None):
        data = {"type": "artists", "id": "300", "attributes": attrs or {}, "relationships": rels or {}}
        doc = _doc(data, included)
        return Artist(doc.primary, doc, _client())

    def test_name(self):
        a = self._make({"name": "Radiohead"})
        assert a.name == "Radiohead"

    def test_popularity(self):
        a = self._make({"popularity": 92.0})
        assert a.popularity == 92.0

    def test_albums_relationship(self):
        a = self._make(
            rels={"albums": {"data": [{"type": "albums", "id": "20"}]}},
            included=[{"type": "albums", "id": "20", "attributes": {"title": "OK Computer"}}],
        )
        assert len(a.albums) == 1

    def test_radio_relationship(self):
        a = self._make(
            rels={"radio": {"data": [{"type": "playlists", "id": "r1"}]}},
            included=[{"type": "playlists", "id": "r1", "attributes": {"name": "Radio"}}],
        )
        assert len(a.radio) == 1

    def test_biography(self):
        a = self._make(
            rels={"biography": {"data": [{"type": "artistBiographies", "id": "b1"}]}},
            included=[{"type": "artistBiographies", "id": "b1", "attributes": {"text": "Bio text"}}],
        )
        assert a.biography == "Bio text"

    def test_no_biography(self):
        a = self._make()
        assert a.biography == ""


# -- Playlist -----------------------------------------------------------------


class TestOapiPlaylist:
    def _make(self, attrs=None, rels=None, included=None):
        data = {"type": "playlists", "id": "400", "attributes": attrs or {}, "relationships": rels or {}}
        doc = _doc(data, included)
        return Playlist(doc.primary, doc, _client())

    def test_title_from_title(self):
        p = self._make({"title": "My Playlist"})
        assert p.name == "My Playlist"

    def test_title_from_name(self):
        p = self._make({"name": "Fallback Name"})
        assert p.name == "Fallback Name"

    def test_num_tracks(self):
        p = self._make({"numberOfItems": 25})
        assert p.num_tracks == 25

    def test_last_updated(self):
        p = self._make({"lastModifiedAt": "2024-06-01T00:00:00Z"})
        assert p.last_updated == "2024-06-01T00:00:00Z"

    def test_tracks_relationship(self):
        p = self._make(
            rels={"items": {"data": [{"type": "tracks", "id": "1"}]}},
            included=[{"type": "tracks", "id": "1", "attributes": {"title": "Song"}}],
        )
        assert len(p.tracks) == 1

    def test_tracks_filters_non_tracks(self):
        p = self._make(
            rels={"items": {"data": [
                {"type": "tracks", "id": "1"},
                {"type": "videos", "id": "2"},
            ]}},
            included=[
                {"type": "tracks", "id": "1", "attributes": {"title": "Song"}},
                {"type": "videos", "id": "2", "attributes": {"title": "Video"}},
            ],
        )
        assert len(p.tracks) == 1


# -- wrap() factory -----------------------------------------------------------


class TestWrap:
    def test_track(self):
        doc = _doc({"type": "tracks", "id": "1", "attributes": {"title": "T"}})
        m = wrap(doc.primary, doc, _client())
        assert isinstance(m, Track)

    def test_album(self):
        doc = _doc({"type": "albums", "id": "1", "attributes": {"title": "A"}})
        m = wrap(doc.primary, doc, _client())
        assert isinstance(m, Album)

    def test_artist(self):
        doc = _doc({"type": "artists", "id": "1", "attributes": {"name": "Ar"}})
        m = wrap(doc.primary, doc, _client())
        assert isinstance(m, Artist)

    def test_playlist(self):
        doc = _doc({"type": "playlists", "id": "1", "attributes": {"name": "P"}})
        m = wrap(doc.primary, doc, _client())
        assert isinstance(m, Playlist)

    def test_unknown_type_returns_base_model(self):
        doc = _doc({"type": "unknownType", "id": "1", "attributes": {}})
        m = wrap(doc.primary, doc, _client())
        assert isinstance(m, Model)
        assert not isinstance(m, Track)
