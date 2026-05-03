from __future__ import annotations

from tidalapi.jsonapi import Document, Resource, _parse_resource
from tidalapi.types import AlbumRel, ResourceType, TrackRel, parse_iso_duration

# -- parse_iso_duration -------------------------------------------------------


class TestParseIsoDuration:
    def test_minutes_and_seconds(self):
        assert parse_iso_duration("PT4M36S") == 276

    def test_seconds_only(self):
        assert parse_iso_duration("PT30S") == 30

    def test_minutes_only(self):
        assert parse_iso_duration("PT5M") == 300

    def test_hours(self):
        assert parse_iso_duration("PT1H2M3S") == 3723

    def test_empty(self):
        assert parse_iso_duration("") == 0

    def test_none(self):
        assert parse_iso_duration(None) == 0

    def test_no_pt_prefix(self):
        assert parse_iso_duration("4M36S") == 0

    def test_fractional_seconds(self):
        assert parse_iso_duration("PT4M36.5S") == 276


# -- ResourceType enum --------------------------------------------------------


class TestResourceType:
    def test_values(self):
        assert ResourceType.TRACKS == "tracks"
        assert ResourceType.ALBUMS == "albums"
        assert ResourceType.ARTISTS == "artists"

    def test_is_string(self):
        assert isinstance(ResourceType.TRACKS, str)


# -- Resource -----------------------------------------------------------------


class TestResource:
    def test_key(self):
        r = Resource(type=ResourceType.TRACKS, id="123", attributes={"title": "Song"})
        assert r.key == ("tracks", "123")

    def test_key_with_string_type(self):
        r = Resource(type="custom", id="1")
        assert r.key == ("custom", "1")

    def test_rel_keys_single(self):
        r = Resource(
            type=ResourceType.TRACKS, id="1", relationships={"albums": {"data": {"type": "albums", "id": "10"}}}
        )
        assert r.rel_keys("albums") == [("albums", "10")]

    def test_rel_keys_list(self):
        r = Resource(
            type=ResourceType.ALBUMS,
            id="1",
            relationships={"items": {"data": [{"type": "tracks", "id": "1"}, {"type": "tracks", "id": "2"}]}},
        )
        assert r.rel_keys("items") == [("tracks", "1"), ("tracks", "2")]

    def test_rel_keys_missing(self):
        r = Resource(type=ResourceType.TRACKS, id="1")
        assert r.rel_keys("nonexistent") == []

    def test_rel_keys_none_data(self):
        r = Resource(type=ResourceType.TRACKS, id="1", relationships={"albums": {"data": None}})
        assert r.rel_keys("albums") == []

    def test_rel_keys_with_enum(self):
        r = Resource(
            type=ResourceType.TRACKS, id="1", relationships={"albums": {"data": {"type": "albums", "id": "5"}}}
        )
        assert r.rel_keys(TrackRel.ALBUMS) == [("albums", "5")]

    def test_rel_meta(self):
        r = Resource(
            type=ResourceType.ALBUMS,
            id="1",
            relationships={
                "items": {
                    "data": [
                        {"type": "tracks", "id": "1", "meta": {"trackNumber": 1}},
                        {"type": "tracks", "id": "2", "meta": {"trackNumber": 2}},
                    ]
                }
            },
        )
        metas = r.rel_meta("items")
        assert metas == [{"trackNumber": 1}, {"trackNumber": 2}]


# -- _parse_resource ----------------------------------------------------------


class TestParseResource:
    def test_known_type(self):
        r = _parse_resource({"type": "tracks", "id": "42", "attributes": {"title": "X"}})
        assert r.type == ResourceType.TRACKS
        assert r.id == "42"
        assert r.attributes["title"] == "X"

    def test_unknown_type_kept_as_string(self):
        r = _parse_resource({"type": "unknownType", "id": "1"})
        assert r.type == "unknownType"


# -- Document -----------------------------------------------------------------


class TestDocument:
    def test_single_primary(self):
        raw = {"data": {"type": "tracks", "id": "1", "attributes": {"title": "Song"}}}
        doc = Document(raw)
        assert doc.primary.id == "1"
        assert doc.primary.attributes["title"] == "Song"

    def test_list_primary(self):
        raw = {
            "data": [
                {"type": "tracks", "id": "1", "attributes": {"title": "A"}},
                {"type": "tracks", "id": "2", "attributes": {"title": "B"}},
            ]
        }
        doc = Document(raw)
        assert len(doc.primary) == 2

    def test_none_primary(self):
        doc = Document({"data": None})
        assert doc.primary is None

    def test_included_resources(self):
        raw = {
            "data": {
                "type": "albums",
                "id": "10",
                "relationships": {"artists": {"data": [{"type": "artists", "id": "5"}]}},
            },
            "included": [{"type": "artists", "id": "5", "attributes": {"name": "Radiohead"}}],
        }
        doc = Document(raw)
        artist = doc.resolve(("artists", "5"))
        assert artist is not None
        assert artist.attributes["name"] == "Radiohead"

    def test_related(self):
        raw = {
            "data": {
                "type": "albums",
                "id": "10",
                "relationships": {"artists": {"data": [{"type": "artists", "id": "5"}]}},
            },
            "included": [{"type": "artists", "id": "5", "attributes": {"name": "Radiohead"}}],
        }
        doc = Document(raw)
        artists = doc.related(AlbumRel.ARTISTS)
        assert len(artists) == 1
        assert artists[0].attributes["name"] == "Radiohead"

    def test_related_with_meta(self):
        raw = {
            "data": {
                "type": "albums",
                "id": "10",
                "relationships": {"items": {"data": [{"type": "tracks", "id": "1", "meta": {"trackNumber": 1}}]}},
            },
            "included": [{"type": "tracks", "id": "1", "attributes": {"title": "Song"}}],
        }
        doc = Document(raw)
        items = doc.related_with_meta(AlbumRel.ITEMS)
        assert len(items) == 1
        resource, meta = items[0]
        assert resource.attributes["title"] == "Song"
        assert meta["trackNumber"] == 1

    def test_of_type(self):
        raw = {
            "data": {"type": "albums", "id": "1"},
            "included": [
                {"type": "tracks", "id": "1", "attributes": {"title": "A"}},
                {"type": "tracks", "id": "2", "attributes": {"title": "B"}},
                {"type": "artists", "id": "3", "attributes": {"name": "C"}},
            ],
        }
        doc = Document(raw)
        tracks = doc.of_type(ResourceType.TRACKS)
        assert len(tracks) == 2

    def test_merge(self):
        doc1 = Document({"data": {"type": "albums", "id": "1", "relationships": {}}})
        doc2 = Document(
            {
                "data": {
                    "type": "albums",
                    "id": "1",
                    "relationships": {"artists": {"data": [{"type": "artists", "id": "5"}]}},
                },
                "included": [{"type": "artists", "id": "5", "attributes": {"name": "X"}}],
            }
        )
        doc1.merge(doc2, target=doc1.primary)
        assert ("artists", "5") in doc1.resources
        assert "artists" in doc1.primary.relationships

    def test_bare_identifier_preserves_included(self):
        """When data has a bare resource identifier and included has the full resource,
        the full resource should be kept."""
        raw = {
            "data": [
                {"type": "tracks", "id": "1"}  # bare identifier
            ],
            "included": [{"type": "tracks", "id": "1", "attributes": {"title": "Full Track"}}],
        }
        doc = Document(raw)
        # The primary should reference the full included resource
        assert doc.primary[0].attributes.get("title") == "Full Track"
