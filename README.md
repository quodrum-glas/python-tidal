# TIDAL API Map — Endpoints + Response Schemas

Extracted from `listen.tidal.com` JS bundle + live API probing.

---

## Base URLs (Production)

| Name                  | URL                                        |
|-----------------------|--------------------------------------------|
| apiGateway (v2)       | `https://api.tidal.com/v2/`                |
| openApiGateway (v2)   | `https://openapi.tidal.com/v2/`            |
| cloudQueueUrl         | `https://connectqueue.tidal.com/v1/`       |
| oauthLoginUrl         | `https://login.tidal.com/`                 |
| sessionApiBaseUrl     | `https://tidal.com/api/session`            |
| creatorContentApi     | `https://api.tidal.com/v2/upload/`         |
| authUrl               | `https://auth.tidal.com/v1/`               |
| api_v1 (legacy)       | `https://api.tidal.com/v1/`                |

Auth header: `Authorization: Bearer <access_token>`

---

## Authentication Endpoints

- `POST https://auth.tidal.com/v1/oauth2/device_authorization` — device auth flow
- `POST https://auth.tidal.com/v1/oauth2/token` — token exchange / refresh
- `GET https://login.tidal.com/authorize` — PKCE browser login
- `GET https://tidal.com/api/session/hydrate` — session hydrate
- `GET https://login.tidal.com/oauth2/me` — current user info

---

## Error Response Format

```json
// v1/v2 gateway errors:
{ "error": "BAD_REQUEST", "description": "...", "httpStatus": 400, "subStatus": 1002 }

// OpenAPI v2 errors:
{ "errors": [{ "code": "MISSING_REQUIRED_PARAMETER", "detail": "...", "source": { "parameter": "..." } }] }
```

---

## Legacy v1 API (`https://api.tidal.com/v1/`)

### GET sessions
```json
{
    "sessionId": "uuid",
    "userId": 174712579,
    "countryCode": "IE",
    "channelId": 200,
    "partnerId": 1,
    "client": {
        "id": 541372293,
        "name": "174712579_3b1934710fb26ce7",
        "authorizedForOffline": false,
        "authorizedForOfflineDate": null
    }
}
```

### GET users/{userId}/subscription
```json
{
    "startDate": "2024-02-15T18:11:10.970+0000",
    "validUntil": "2026-03-22T08:31:55.670+0000",
    "status": "ACTIVE",
    "subscription": { "type": "PREMIUM", "offlineGracePeriod": 30 },
    "highestSoundQuality": "HI_RES",
    "premiumAccess": true,
    "canGetTrial": false,
    "paymentType": "ADYEN_CREDIT_CARD",
    "paymentOverdue": false
}
```

### GET pages/home?countryCode={cc}&locale={locale}&deviceType=BROWSER
```json
{
    "selfLink": null,
    "id": "base64-encoded-id",
    "title": "Home",
    "rows": [
        {
            "modules": [
                {
                    "id": "base64-encoded-id",
                    "type": "PLAYLIST_LIST",       // also: ALBUM_LIST, TRACK_LIST, MIX_LIST, etc.
                    "width": 100,
                    "scroll": "HORIZONTAL",
                    "title": "The Hits",
                    "description": "",
                    "showMore": { ... },
                    "pagedList": { ... },
                    "supportsPaging": false,
                    "quickPlay": false
                }
            ]
        }
    ]
}
```

### All v1 Page Endpoints
- `pages/home` — home feed
- `pages/explore` — explore (genres, moods, decades)
- `pages/hires` — hi-res content
- `pages/for_you` — personalized recommendations
- `pages/videos` — video content
- `pages/genre_page` — global genres list
- `pages/genre_page_local` — local genres
- `pages/genre_{name}` — specific genre (e.g. `genre_blues`, `genre_classical`)
- `pages/moods` — moods & activities
- `pages/mood_{name}` — specific mood (e.g. `mood_djselector`)
- `pages/my_collection_my_mixes` — user's mixes
- `pages/contributor` — contributor/credits page
- `pages/artist?artistId={id}` — full artist page
- `pages/single-module-page/{pageId}/{ver}/{moduleId}/{ver}?artistId={id}` — paginated "show more"

### v1 Page Module Types (all discovered)

| Module Type | Description | Key Fields |
|---|---|---|
| `ARTIST_HEADER` | Artist page header | `artist`, `bio`, `mixes`, `roleCategories`, `playbackControls` |
| `ALBUM_HEADER` | Album page header | `album` |
| `MIX_HEADER` | Mix page header | `mix` |
| `TRACK_LIST` | List of tracks | `pagedList.items[]` = track objects |
| `ALBUM_LIST` | List of albums | `pagedList.items[]` = album objects, `header` |
| `ARTIST_LIST` | List of artists | `pagedList.items[]` = artist objects |
| `VIDEO_LIST` | List of videos | `pagedList.items[]` = video objects |
| `PLAYLIST_LIST` | List of playlists | `pagedList.items[]` = playlist objects |
| `MIX_LIST` | List of mixes | `pagedList.items[]` = mix objects |
| `MIXED_TYPES_LIST` | Mixed content (playlists+mixes) | `pagedList.items[]` = `{type, item}` wrappers |
| `ITEM_LIST_WITH_ROLES` | Credits/contributions | `pagedList.items[]` = `{item, type, roles[]}`, `roleCategories`, `artistId` |
| `FEATURED_PROMOTIONS` | Featured items | `items[]` = PageItem objects |
| `MULTIPLE_TOP_PROMOTIONS` | Top featured items | `items[]` = PageItem objects |
| `HIGHLIGHT_MODULE` | Highlighted items | `highlights[]` |
| `PAGE_LINKS` | Navigation links | `pagedList.items[]` = `{title, icon, apiPath, imageId}` |
| `PAGE_LINKS_CLOUD` | Cloud-style nav links | same as PAGE_LINKS |
| `TEXT_BLOCK` | Text content | `text`, `icon` |
| `SOCIAL` | Social media links | `socialProfiles[]`, `socialLinks[]` |
| `ARTICLE_LIST` | Magazine articles | `pagedList.items[]` = `{title, link, date, images}` |
| `ALBUM_ITEMS` | Album track listing | `pagedList.items[]` |

### Module Common Fields
```json
{
    "id": "base64-encoded-id",
    "type": "MODULE_TYPE",
    "width": 100,
    "scroll": "HORIZONTAL",
    "title": "Section Title",
    "description": "",
    "showMore": { "apiPath": "pages/single-module-page/...", "title": "..." },
    "pagedList": {
        "dataApiPath": "...",
        "limit": 50,
        "offset": 0,
        "totalNumberOfItems": 300,
        "items": [ ... ]
    },
    "supportsPaging": false,
    "quickPlay": false,
    "preTitle": null
}
```

### ARTIST_HEADER Detail
```json
{
    "type": "ARTIST_HEADER",
    "artist": {
        "id": 8405, "name": "Metallica",
        "url": "http://www.tidal.com/artist/8405",
        "picture": "uuid", "selectedAlbumCoverFallback": null,
        "artistTypes": ["ARTIST", "CONTRIBUTOR"],
        "mixes": { "ARTIST_MIX": "hex-id" },
        "handle": null
    },
    "bio": { "text": "Biography text...", "source": "TiVo" },
    "mixes": { "ARTIST_MIX": "hex-id" },
    "roleCategories": [
        { "category": "Artist", "categoryId": -1 },
        { "category": "Songwriter", "categoryId": 2 },
        { "category": "Producer", "categoryId": 1 },
        { "category": "Performer", "categoryId": 11 },
        { "category": "Production team", "categoryId": 10 },
        { "category": "Misc", "categoryId": 99 }
    ],
    "playbackControls": [
        { "shuffle": true, "playbackMode": "SHUFFLE", "title": "Shuffle", "icon": "shuffle_tracks", "targetModuleId": "..." },
        { "shuffle": false, "playbackMode": "PLAY", "title": "Play", "icon": "play_tracks", "targetModuleId": "..." }
    ]
}
```

### SOCIAL Module Detail
```json
{
    "socialProfiles": [
        { "type": "FACEBOOK", "url": "https://facebook.com/..." },
        { "type": "INSTAGRAM", "url": "https://instagram.com/..." },
        { "type": "TWITTER", "url": "https://twitter.com/..." }
    ],
    "socialLinks": [
        { "type": "TWITTER", "url": "..." },
        { "type": "FACEBOOK", "url": "..." },
        { "type": "TIKTOK", "url": "..." },
        { "type": "OFFICIAL_HOMEPAGE", "url": "..." }
    ]
}
```

### ARTICLE_LIST Item Detail
```json
{
    "title": "Article Title",
    "link": "https://tidal.com/magazine/article/...",
    "date": "2026-03-03T14:39:29Z",
    "images": {
        "original": { "width": 1920, "height": 1090, "url": "https://magazine-resources.tidal.com/..." },
        "large": { "width": 1280, "height": 727, "url": "..." },
        "xlarge": { "width": 1920, "height": 1090, "url": "..." }
    }
}
```

### MULTIPLE_TOP_PROMOTIONS / FEATURED_PROMOTIONS Item Detail
```json
{
    "header": "WATCH: NEW SHORT FILM",
    "shortHeader": "The Beatles",
    "shortSubHeader": "Now and Then: The Last Beatles Song",
    "imageId": "uuid",
    "type": "VIDEO",       // or PLAYLIST, TRACK, ARTIST, ALBUM
    "artifactId": "325695459",
    "text": "",
    "featured": false
}
```

### ITEM_LIST_WITH_ROLES Item Detail
```json
{
    "item": { /* full track object */ },
    "type": "track",
    "roles": [{ "name": "Producer", "category": "Producer", "categoryId": 1 }]
}
```

### MIXED_TYPES_LIST Item Detail
```json
{
    "type": "PLAYLIST",
    "item": {
        "uuid": "...", "title": "Metallica Essentials",
        "type": "EDITORIAL",
        "url": "...", "image": "uuid", "squareImage": "uuid",
        "duration": 12345, "numberOfTracks": 50, "numberOfVideos": 0,
        "promotedArtists": [...], "creators": [...], "description": "..."
    }
}
```

### Metallica Artist Page — Full Row Listing (example)
```
row[ 0]: ARTIST_HEADER
row[ 1]: TRACK_LIST         "Top Tracks"        (4 items, showMore → 300 total)
row[ 2]: ALBUM_LIST         "Albums"             (20 items)
row[ 3]: ALBUM_LIST         "EP & Singles"       (38 items)
row[ 4]: ALBUM_LIST         "Compilations"       (1 item)
row[ 5]: ALBUM_LIST         "Live albums"        (9 items)
row[ 6]: MIXED_TYPES_LIST   "Playlists"          (28 items)
row[ 7]: VIDEO_LIST         "Videos"             (50 items)
row[ 8]: ALBUM_LIST         "Appears On"         (21 items)
row[ 9]: ITEM_LIST_WITH_ROLES "Credits"           (4 items, showMore → contributor page)
row[10]: ARTIST_LIST        "Fans Also Like"     (15 items)
row[11]: SOCIAL             "Social"             (3 profiles, 5 links)
row[12]: ARTICLE_LIST       "Articles"           (6 items)
```

---

## API v2 Gateway (`https://api.tidal.com/v2/`)

### GET search/?query={q}&limit={n}&types={ARTISTS,ALBUMS,TRACKS,VIDEOS,PLAYLISTS}&countryCode={cc}
```json
{
    "tracks": {
        "items": [
            {
                "artifactType": "CatalogueSuggestionsTrackDto",
                "id": 58990486,
                "title": "Creep",
                "album": {
                    "id": 58990484, "title": "Pablo Honey", "version": null,
                    "cover": "uuid", "vibrantColor": "#ecbf5c", "videoCover": null,
                    "releaseDate": "1993-04-20", "upload": false
                },
                "artists": [
                    { "id": 64518, "name": "Radiohead", "handle": null, "picture": "uuid", "userId": null, "type": "MAIN" }
                ],
                "version": null, "duration": 239, "popularity": 96,
                "doublePopularity": 0.96449, "trackNumber": 2, "volumeNumber": 1,
                "explicit": true, "replayGain": -8.66, "audioQuality": "LOSSLESS",
                "allowStreaming": true, "streamReady": true,
                "audioModes": ["STEREO"],
                "mixes": { "TRACK_MIX": "hex-id" },
                "mediaMetadata": { "tags": ["LOSSLESS"] },
                "providerName": "Beggars Group",
                "djReady": true, "stemReady": false, "payToStream": false,
                "audioAnalysisAttributes": { "scale": "minor", "bpm": "185.0", "key": "C", "keyScale": "MINOR" },
                "isrc": "GBAYE9200070", "peak": 0.984894,
                "prePaywallPresentation": "PREVIEW",
                "copyright": "...",
                "premiumStreamingOnly": false,
                "url": "http://www.tidal.com/track/58990486"
            }
        ]
    },
    "albums": { "items": [ ... ] },
    "artists": { "items": [ ... ] },
    "videos": { "items": [ ... ] },
    "playlists": { "items": [ ... ] }
}
```

### GET my-collection/playlists/folders?countryCode={cc}&folderId=root&offset=0&limit=50&order=DATE&orderDirection=DESC
```json
{
    "lastModifiedAt": "2026-02-20T15:58:16.882+0000",
    "items": [
        {
            "trn": "trn:playlist:uuid",
            "itemType": "PLAYLIST",          // or "FOLDER"
            "addedAt": "iso-datetime",
            "lastModifiedAt": "iso-datetime",
            "name": "TransientFavs",
            "parent": null,
            "data": {
                "uuid": "fce00514-...",
                "type": "USER",
                "creator": { ... },
                "contentBehavior": "UNRESTRICTED",
                "sharingLevel": "PRIVATE",
                "status": "READY",
                "title": "TransientFavs",
                "description": "",
                "image": "uuid", "squareImage": "uuid",
                "url": "http://www.tidal.com/playlist/uuid",
                "created": "iso-datetime",
                "lastUpdated": "iso-datetime",
                "duration": 407,
                "numberOfTracks": 2,
                "numberOfVideos": 0
            }
        }
    ],
    "totalNumberOfItems": 35,
    "cursor": null
}
```

### GET favorites/mixes?countryCode={cc}&limit={n}
```json
{
    "items": [
        {
            "dateAdded": "iso-datetime",
            "id": "hex-mix-id",
            "mixType": "ARTIST_MIX",
            "titleTextInfo": { "text": "Artist Name", "color": "#hex" },
            "subTitleTextInfo": { "text": "Artist Radio", "color": "#hex" },
            "updated": "iso-datetime",
            "images": {
                "SMALL":  { "width": 320,  "height": 320,  "url": "https://images.tidal.com/..." },
                "MEDIUM": { "width": 640,  "height": 640,  "url": "..." },
                "LARGE":  { "width": 1500, "height": 1500, "url": "..." }
            }
        }
    ]
}
```

### GET suggestions/?query={q}&limit={n}&countryCode={cc}
Autocomplete / search suggestions. tidalapi: `Session.suggest()`
```json
{
    "history": [
        { "query": "radiohead", "timestamp": "iso-datetime" }
    ],
    "suggestions": [
        {
            "type": "ARTIST",
            "value": "Radiohead",
            "id": 64518,
            "picture": "uuid"
        },
        {
            "type": "TRACK",
            "value": "Creep",
            "id": 58990486,
            "artist": { "id": 64518, "name": "Radiohead" }
        },
        {
            "type": "ALBUM",
            "value": "OK Computer",
            "id": 17813,
            "artist": { "id": 64518, "name": "Radiohead" }
        }
    ]
}
```

### GET artist/@{handle}?countryCode={cc}
Lookup artist by vanity handle. Returns same shape as v1 `artists/{id}`. tidalapi: `Session.get_artist_by_handle()`
```json
{
    "id": 64518,
    "name": "Radiohead",
    "artistTypes": ["ARTIST", "CONTRIBUTOR"],
    "url": "http://www.tidal.com/artist/64518",
    "picture": "uuid",
    "popularity": 82,
    "artistRoles": [
        { "categoryId": -1, "category": "Artist" },
        { "categoryId": 2, "category": "Songwriter" }
    ],
    "mixes": { "ARTIST_MIX": "hex-id" },
    "handle": "radiohead"
}
```

### POST favorites/mixes/add?mixId={id}&countryCode={cc}
Add a mix to favorites. Returns HTTP 200 with empty body on success. tidalapi: `Favorites.add_mix()`

### DELETE favorites/mixes/remove?mixIds={id1,id2}&countryCode={cc}
Remove mix(es) from favorites. Comma-separated IDs. Returns HTTP 200 with empty body on success. tidalapi: `Favorites.remove_mix()`

### GET feed/activities?userId={id}&limit={n}&countryCode={cc}
Recent activity feed (friend listening activity, new releases from followed artists). tidalapi: `Session.feed_activities()`
```json
{
    "items": [
        {
            "type": "STREAM",
            "timestamp": "iso-datetime",
            "user": { "id": 12345, "name": "...", "picture": "uuid" },
            "track": { "id": 58990486, "title": "Creep", "artists": [...], "album": {...} }
        },
        {
            "type": "NEW_RELEASE",
            "timestamp": "iso-datetime",
            "artist": { "id": 64518, "name": "Radiohead" },
            "album": { "id": 17813, "title": "OK Computer", "cover": "uuid" }
        }
    ]
}
```

### GET client-search/?query={q}&limit={n}&countryCode={cc}
Alternate search path used by the web client. Same response shape as `search/`. tidalapi: `Session.search_v2()`

### GET artist/{artistId}?countryCode={cc}
Artist by numeric ID via v2 gateway. Same response shape as v1 `artists/{id}`. tidalapi: `Session.get_artist_v2()`

### GET artist/{artistId}/playable?countryCode={cc}
Check whether an artist has streamable content. tidalapi: `Session.is_artist_playable()`
```json
{
    "playable": true
}
```

### GET my-collection/artists?countryCode={cc}&limit={n}&offset={o}
Favorite artists via v2 my-collection. Same item shape as v1 `users/{id}/favorites/artists`. tidalapi: `Favorites.artists_v2()`
```json
{
    "items": [
        {
            "item": {
                "id": 64518,
                "name": "Radiohead",
                "artistTypes": ["ARTIST", "CONTRIBUTOR"],
                "url": "http://www.tidal.com/artist/64518",
                "picture": "uuid",
                "popularity": 82,
                "mixes": { "ARTIST_MIX": "hex-id" }
            },
            "created": "iso-datetime",
            "type": "ARTIST"
        }
    ],
    "totalNumberOfItems": 42
}
```

### All v2 Endpoints
- `GET search/` — full search with type filtering → `Session.search()`
- `GET client-search/` — alternate search path → `Session.search_v2()`
- `GET suggestions/` — autocomplete suggestions → `Session.suggest()`
- `GET my-collection/playlists/folders` — playlist folders & playlists → `Favorites.playlists()`, `PlaylistFolders`
- `GET my-collection/artists` — favorite artists (v2) → `Favorites.artists_v2()`
- `GET favorites/mixes` — favorited mixes → `Favorites.mixes()`
- `POST favorites/mixes/add` — add mix to favorites → `Favorites.add_mix()`
- `DELETE favorites/mixes/remove` — remove mix from favorites → `Favorites.remove_mix()`
- `GET artist/{artistId}` — artist by ID (v2) → `Session.get_artist_v2()`
- `GET artist/{artistId}/playable` — playable check → `Session.is_artist_playable()`
- `GET artist/@{handle}` — artist by vanity handle → `Session.get_artist_by_handle()`
- `GET feed/activities` — friend/release activity feed → `Session.feed_activities()`
- `GET home/feed/static` — *(not implemented, returns 400, undocumented params)*
- `GET home/feed/{vibe}` — *(not implemented, v1 `pages/` covers this)*
- `POST feed/activities/seen` — *(not implemented, UI-only read receipt)*
- `POST chat/init`, `GET chat/` — *(not implemented, social chat)*
- `GET profile/@{handle}` — *(not implemented, social profile, not music content)*
- `GET marketplace/*` — *(not implemented, creator marketplace)*
- `POST onboarding/tasks/set-completed/{taskId}` — *(not implemented, first-run UI)*

---

## OpenAPI v2 Gateway (`https://openapi.tidal.com/v2/`)

All responses follow JSON:API spec:
```json
{
    "data": {
        "id": "string",
        "type": "resourceType",
        "attributes": { ... },
        "relationships": {
            "relName": { "links": { "self": "/resource/id/relationships/relName" } }
        }
    },
    "links": { "self": "/resource/id" }
}
```

Relationship endpoints return:
```json
{
    "data": [
        { "id": "string", "type": "resourceType", "meta": { "addedAt": "iso-datetime" } }
    ],
    "links": { "self": "/resource/id/relationships/relName" }
}
```

### GET tracks/{id}
```json
"attributes": {
    "title": "Creep",
    "version": null,
    "isrc": "GBAYE9200070",
    "duration": "PT3M59S",
    "copyright": { "text": "..." },
    "explicit": true,
    "key": "C", "keyScale": "MINOR", "bpm": 185.0,
    "popularity": 0.957,
    "accessType": "PUBLIC",
    "availability": ["STREAM", "DJ"],
    "mediaTags": ["LOSSLESS"],
    "toneTags": [],
    "externalLinks": [{ "href": "https://tidal.com/browse/track/...", "meta": { "type": "TIDAL_SHARING" } }],
    "spotlighted": false,
    "createdAt": "2016-04-02T08:18:54Z"
}
"relationships": albums, trackStatistics, similarTracks, owners, sourceFile, artists, credits,
                 download, genres, lyrics, metadataStatus, priceConfig, providers, radio,
                 replacement, shares, suggestedTracks, usageRules
```

### GET albums/{id}
```json
"attributes": {
    "title": "Pablo Honey",
    "barcodeId": "634904077969",
    "numberOfVolumes": 1, "numberOfItems": 12,
    "duration": "PT42M17S",
    "explicit": true,
    "releaseDate": "1993-04-20",
    "copyright": { "text": "..." },
    "popularity": 0.794,
    "accessType": "PUBLIC",
    "availability": ["STREAM", "DJ"],
    "mediaTags": ["LOSSLESS"],
    "externalLinks": [{ "href": "...", "meta": { "type": "TIDAL_SHARING" } }],
    "type": "ALBUM", "albumType": "ALBUM",
    "createdAt": "2016-04-02T08:18:54Z"
}
"relationships": similarAlbums, artists, genres, suggestedCoverArts, owners, coverArt,
                 items, providers, albumStatistics, priceConfig, replacement, usageRules
```

### GET artists/{id}
```json
"attributes": {
    "name": "Radiohead",
    "popularity": 0.920,
    "externalLinks": [{ "href": "...", "meta": { "type": "TIDAL_SHARING" } }],
    "spotlighted": false,
    "contributionsEnabled": false
}
"relationships": similarArtists, albums, followers, following, roles, videos, owners,
                 biography, profileArt, radio, trackProviders, tracks
```

### GET playlists/{uuid}
```json
"attributes": {
    "name": "TransientFavs",
    "description": "",
    "bounded": true,
    "duration": "PT6M47S",
    "numberOfItems": 2,
    "externalLinks": [
        { "href": "https://listen.tidal.com/playlist/...", "meta": { "type": "TIDAL_SHARING" } },
        { "href": "...?play=true", "meta": { "type": "TIDAL_AUTOPLAY_ANDROID" } },
        { "href": "...?play=true", "meta": { "type": "TIDAL_AUTOPLAY_IOS" } },
        { "href": "...?play=true", "meta": { "type": "TIDAL_AUTOPLAY_WEB" } }
    ],
    "createdAt": "iso-datetime",
    "lastModifiedAt": "iso-datetime",
    "accessType": "UNLISTED",
    "playlistType": "USER",
    "numberOfFollowers": 0
}
"relationships": ownerProfiles, owners, collaboratorProfiles, collaborators, coverArt, items
```

### GET lyrics/{id}
```json
"attributes": {
    "text": "plain text lyrics with \\n line breaks",
    "lrcText": "[00:19.85]timestamped lyrics in LRC format...",
    "technicalStatus": "OK",
    "provider": {
        "source": "THIRD_PARTY",
        "name": "MUSIXMATCH",
        "commonTrackId": "13616",
        "lyricsId": "44288617"
    },
    "direction": "LEFT_TO_RIGHT"
}
"relationships": owners, track
```

### GET searchResults/{query}
```json
"attributes": { "trackingId": "uuid" }
"relationships": albums, artists, playlists, videos, topHits, tracks
// Follow each relationship link to get actual results
```

### GET userCollections/{userId}
```json
"attributes": {}
"relationships": albums, artists, owners, playlists, tracks, videos
// Follow relationship links to get items, e.g.:
// GET userCollections/{userId}/relationships/tracks
// returns: { "data": [{ "id": "trackId", "type": "tracks", "meta": { "addedAt": "..." } }] }
```

### GET userRecommendations/{userId}
```json
"attributes": {}
"relationships": discoveryMixes, myMixes, newArrivalMixes
```

### GET trackManifests/{trackId}?adaptive=true&formats={...}&manifestType={MPEG_DASH}&uriScheme=DATA&usage=PLAYBACK
Stream manifest via OpenAPI. `formats` is repeated (not comma-separated). tidalapi: `get_stream_oapi()`
```
Params:
  adaptive       = true
  formats        = HEAACV1 | AACLC | FLAC  (repeated: formats=HEAACV1&formats=AACLC&formats=FLAC)
  manifestType   = MPEG_DASH
  uriScheme      = DATA
  usage          = PLAYBACK
```
Response follows JSON:API spec (same wrapper as other OpenAPI endpoints):
```json
{
    "data": {
        "id": "58990486",
        "type": "trackManifests",
        "attributes": {
            "trackPresentation": "FULL",
            "uri": "data:application/dash+xml;base64,PD94bWwg...base64-encoded-mpd...",
            "hash": "base64-hash",
            "formats": ["HEAACV1", "AACLC", "FLAC"],
            "drmData": {
                "drmSystem": "WIDEVINE",
                "licenseUrl": "https://api.tidal.com/v2/widevine",
                "certificateUrl": "https://api.tidal.com/v2/widevine/certificate"
            },
            "albumAudioNormalizationData": { "replayGain": -8.66, "peakAmplitude": 0.984894 },
            "trackAudioNormalizationData": { "replayGain": -8.66, "peakAmplitude": 0.984894 }
        }
    }
}
```
Note: `uri` is a `data:` URI — `data:{mime};base64,{payload}`. The mime type (e.g. `application/dash+xml`)
and base64 manifest are embedded together, unlike v1 which has separate `manifestMimeType` + `manifest` fields.

### Full resource list (OpenAPI v2)
acceptedTerms, albumStatistics, albums, appreciations, artistBiographies, artistClaims,
artistRoles, artists, artworks, clients, comments, contentClaims, credits, downloads,
dspSharingLinks, dynamicModules, dynamicPages, genres, installations, lyrics,
manualArtistClaims, offlineTasks, playlists, playQueues, priceConfigurations, providers,
reactions, savedShares, searchResults, searchSuggestions, shares, stripeConnections,
stripeDashboardLinks, terms, trackFiles, trackManifests, trackSourceFiles, trackStatistics,
tracks, tracksMetadataStatus, usageRules, userCollectionAlbums, userCollectionArtists,
userCollectionFolders, userCollectionPlaylists, userCollectionTracks, userCollectionVideos,
userCollections, userDataExportRequests, userRecommendations, userReports, users,
videoManifests, videos

---

## Cloud Queue API (`https://connectqueue.tidal.com/v1/`)

- `POST queues` — create queue
- `GET queues/{id}` — get queue
- `GET queues/{id}/items?limit={n}&offset={o}` — list items
- `POST queues/{id}/items` — add items
- `DELETE queues/{id}/items/{itemId}` — remove item
- `PUT queues/{id}/shuffle` — shuffle queue
- `GET content/{id}?offset={o}&limit={l}` — get content

---

## Image URLs

Pattern: `https://resources.tidal.com/images/{uuid}/{width}x{height}.jpg`
Origin: `https://resources.tidal.com/images/{uuid}/origin.jpg`
Video: `https://resources.tidal.com/videos/{uuid}/{width}x{height}.mp4`
