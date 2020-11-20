# -*- coding: utf-8 -*-
#
# Copyright (C) 2020 quodrumglas
# Copyright (C) 2019 morguldir
# Copyright (C) 2014 Thomas Amland
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import unicode_literals

import base64
import hashlib
import os
from time import time

from enum import Enum

import datetime
import json
import logging
import requests
from requests.exceptions import HTTPError

from .models import Artist, Album, Track, Video, Playlist, SearchResult, Category, Role, IMG_URL

try:
    from urlparse import parse_qs, urljoin, urlsplit
    from urllib import urlencode, unquote
except ImportError:
    from urllib.parse import parse_qs, urljoin, urlsplit, urlencode, unquote

log = logging.getLogger(__name__)


class AuthorizationError(Exception):
    pass


class AuthorizationNeeded(Exception):
    pass


class Quality(Enum):
    master = 'HI_RES'
    lossless = 'LOSSLESS'
    high = 'HIGH'
    low = 'LOW'


class VideoQuality(Enum):
    high = 'HIGH'
    medium = 'MEDIUM'
    low = 'LOW'


class Config(object):
    def __init__(self, api_token, auth_json_file, quality=Quality.master, video_quality=VideoQuality.high):
        self.quality = quality.value
        self.video_quality = video_quality.value
        self.api_location = 'https://api.tidalhifi.com/v1/'
        self.api_token = api_token
        self.auth_json_file = auth_json_file


class Session(object):
    _redirect_uri = "https://tidal.com/android/login/auth"  # or tidal://login/auth
    _oauth_authorize_url = "https://login.tidal.com/authorize"
    _oauth_token_url = "https://auth.tidal.com/v1/oauth2/token"

    def __init__(self, config):
        self.client_id = config.api_token
        self._config = config
        self._user = None
        self.auth_expire = 0
        self._auth_info = {}
        self._refresh_token = None
        self._token_expiry = 0

    @property
    def auth_info(self):
        if not self._auth_info:
            try:
                with open(self._config.auth_json_file, 'r') as f:
                    self._auth_info = json.load(f)
            except IOError:
                raise NotImplementedError
        return self._auth_info

    @auth_info.setter
    def auth_info(self, data):
        self._token_expiry = time() + int(data['expires_in'])
        self._auth_info.update(data)
        with open(self._config.auth_json_file, 'w') as f:
            json.dump(self._auth_info, f)

    @property
    def token_expiry(self):
        if not self._token_expiry:
            self._token_expiry = os.path.getmtime(self._config.auth_json_file) + int(self.auth_info['expires_in'])
        return self._token_expiry

    @property
    def refresh_token(self):
        return self.auth_info["refresh_token"]

    @property
    def country_code(self):
        return self.auth_info["user"]["countryCode"]

    @property
    def user_id(self):
        return self.auth_info["user"]["userId"]

    @property
    def user(self):
        if not self._user:
            self._user = User(self, id=self.user_id)
        return self._user

    def login(self, interactive_auth_url_getter=input, force_relogin=False):
        if self._auth_info is not None and not force_relogin:
            return
        code_verifier, authorization_url = self.login_part1()
        auth_url = interactive_auth_url_getter(authorization_url)
        self.login_part2(code_verifier, auth_url)

    def login_part1(self):
        # https://tools.ietf.org/html/rfc7636#appendix-B
        code_verifier = base64.urlsafe_b64encode(os.urandom(32))[:-1]
        code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier).digest())[:-1]
        qs = urlencode(
            {
                "response_type": "code",
                "redirect_uri": self._redirect_uri,
                "client_id": self.client_id,
                "appMode": "android",
                "code_challenge": code_challenge.decode("ascii"),
                "code_challenge_method": "S256",
                "restrict_signup": "true",
            }
        )
        authorization_url = urljoin(self._oauth_authorize_url, "?" + qs)
        return code_verifier.decode("ascii"), authorization_url

    def login_part2(self, code_verifier, auth_url):
        code = parse_qs(urlsplit(auth_url).query)["code"][0]
        resp = requests.post(
            self._oauth_token_url,
            data={
                "code": code,
                "client_id": self.client_id,
                "grant_type": "authorization_code",
                "redirect_uri": self._redirect_uri,
                "scope": "r_usr w_usr w_sub",
                "code_verifier": code_verifier.decode("ascii"),
            },
        )
        data = resp.json()
        if resp.status_code != 200:
            raise AuthorizationError(data["error"], data["error_description"])
        self.auth_info = data

    def refresh_session(self):
        if self.refresh_token is None:
            raise AuthorizationNeeded
        resp = requests.post(
            self._oauth_token_url,
            data={
                "client_id": self.client_id,
                "grant_type": "refresh_token",
                "scope": "r_usr w_usr w_sub",
                "refresh_token": self.refresh_token,
            },
        )
        data = resp.json()
        if resp.status_code != 200:
            raise AuthorizationError(data["error"], data["error_description"])
        self.auth_info = data

    def request(self, *args, **kwargs):
        resp = self._request(*args, **kwargs)
        try:
            return resp.json()
        except:
            return resp

    def _request(self, method, path, params=None, data=None, headers=None):
        logging.debug("REQUEST: %s %s", method, path)
        request_params = {
            'limit': '999',
            'deviceType': 'PHONE',
            'locale': 'en_GB',
            'countryCode': self.country_code,
        }
        if params:
            request_params.update(params)
        request_headers = headers or {}
        request_headers.update({
            "X-Tidal-Token": self.client_id,
            "Authorization": "{} {}".format(self.auth_info["token_type"], self.auth_info["access_token"]),
        })
        url = urljoin(self._config.api_location, path)
        request = requests.request(method, url, headers=request_headers, params=request_params, data=data)
        try:
            request.raise_for_status()
        except HTTPError as e:
            if request.status_code == 401:
                log.error(e)
                if self.token_expiry < time():
                    log.info("Token has expired. Refreshing session...")
                    self.refresh_session()
                    return self.request(method, path, params, data, headers)
                log.info("Token not expired yet. Valid until: {}".format(
                    datetime.datetime.fromtimestamp(self.token_expiry).isoformat()))
                raise NotImplementedError
            if request.status_code == 404:
                log.error(e)
                raise NotImplementedError
            raise
        if request.content:
            log.debug("Response: %s", json.dumps(request.json(), indent=4))
        return request

    def get_user(self, user_id):
        return self._map_request('users/%s' % user_id, ret='user')

    def get_user_playlists(self, user_id):
        return self._map_request('users/%s/playlists' % user_id, ret='playlists')

    def get_playlist(self, playlist_id):
        return self._map_request('playlists/%s' % playlist_id, ret='playlist')

    def get_playlist_tracks(self, playlist_id):
        return self._map_request('playlists/%s/tracks' % playlist_id, ret='tracks')

    def get_playlist_videos(self, playlist_id):
        return self._map_request('playlists/%s/items' % playlist_id, ret='video')

    def get_playlist_items(self, playlist_id):
        return self._get_items('playlists/%s/items' % playlist_id, ret='items')

    def get_album(self, album_id):
        return self._map_request('albums/%s' % album_id, ret='album')

    def get_album_tracks(self, album_id):
        return self._map_request('albums/%s/tracks' % album_id, ret='tracks')

    def get_album_videos(self, album_id):
        items = self._get_items('albums/%s/items' % album_id, ret='videos')
        return [item for item in items if isinstance(item, Video)]

    def get_album_items(self, album_id):
        return self._get_items('albums/%s/items' % album_id, ret='items')

    def get_artist(self, artist_id):
        return self._map_request('artists/%s' % artist_id, ret='artist')

    def get_artist_albums(self, artist_id):
        return self._map_request('artists/%s/albums' % artist_id, ret='albums')

    def get_artist_albums_ep_singles(self, artist_id):
        params = {'filter': 'EPSANDSINGLES'}
        return self._map_request('artists/%s/albums' % artist_id, params, ret='albums')

    def get_artist_albums_other(self, artist_id):
        params = {'filter': 'COMPILATIONS'}
        return self._map_request('artists/%s/albums' % artist_id, params, ret='albums')

    def get_artist_top_tracks(self, artist_id):
        return self._map_request('artists/%s/toptracks' % artist_id, ret='tracks')

    def get_artist_videos(self, artist_id):
        return self._map_request('artists/%s/videos' % artist_id, ret='videos')

    def get_artist_bio(self, artist_id):
        return self.request('GET', 'artists/%s/bio' % artist_id)['text']

    def get_artist_similar(self, artist_id):
        return self._map_request('artists/%s/similar' % artist_id, ret='artists')

    def get_artist_radio(self, artist_id):
        return self._map_request('artists/%s/radio' % artist_id, params={'limit': 100}, ret='tracks')

    def get_featured(self):
        items = self.request('GET', 'promotions')['items']
        return [_parse_featured_playlist(item) for item in items if item['type'] == 'PLAYLIST']

    def get_featured_items(self, content_type, group):
        return self._map_request('/'.join(['featured', group, content_type]), ret=content_type)

    def get_moods(self):
        return map(_parse_moods, self.request('GET', 'moods'))

    def get_mood_playlists(self, mood_id):
        return self._map_request('/'.join(['moods', mood_id, 'playlists']), ret='playlists')

    def get_genres(self):
        return map(_parse_genres, self.request('GET', 'genres'))

    def get_genre_items(self, genre_id, content_type):
        return self._map_request('/'.join(['genres', genre_id, content_type]), ret=content_type)

    def get_track_radio(self, track_id):
        return self._map_request('tracks/%s/radio' % track_id, params={'limit': 100}, ret='tracks')

    def get_track(self, track_id):
        return self._map_request('tracks/%s' % track_id, ret='track')

    def get_video(self, video_id):
        return self._map_request('videos/%s' % video_id, ret='video')

    def _map_request(self, url, params=None, ret=None):
        json_obj = self.request('GET', url, params)
        if not json_obj:
            return [] if ret.endswith('s') else None
        parse = None
        if ret.startswith('artist'):
            parse = _parse_artist
        elif ret.startswith('album'):
            parse = _parse_album
        elif ret.startswith('track'):
            parse = _parse_media
        elif ret.startswith('user'):
            raise NotImplementedError()
        elif ret.startswith('video'):
            parse = _parse_media
        elif ret.startswith('item'):
            parse = _parse_media
        elif ret.startswith('playlist'):
            parse = _parse_playlist

        items = json_obj.get('items')
        if items is None:
            return parse(json_obj)
        if len(items) > 0 and 'item' in items[0]:
            return list(map(parse, [item['item'] for item in items]))
        return list(map(parse, items))

    def _get_items(self, url, ret=None, offset=0):
        params = {
            'offset': offset,
            'limit': 100
        }
        remaining = 100
        while remaining == 100:
            items = self._map_request(url, params=params, ret=ret)
            remaining = len(items)
        return items

    def get_media_url(self, track_id):
        params = {'soundQuality': self._config.quality}
        r = self.request('GET', 'tracks/%s/streamUrl' % track_id, params)
        return r['url']

    def get_track_url(self, track_id):
        return self.get_media_url(track_id)

    def get_video_url(self, video_id):
        params = {
            'urlusagemode': 'STREAM',
            'videoquality': self._config.video_quality,
            'assetpresentation': 'FULL'
        }
        request = self.request('GET', 'videos/%s/urlpostpaywall' % video_id, params)
        return request['urls'][0]

    def search(self, field, value, limit=50):
        params = {
            'query': value,
            'limit': limit,
        }
        if field not in ['artist', 'album', 'playlist', 'track']:
            raise ValueError('Unknown field \'%s\'' % field)

        ret_type = field + 's'
        url = 'search/' + field + 's'
        result = self._map_request(url, params, ret=ret_type)
        return SearchResult(**{ret_type: result})


def _parse_artist(json_obj):
    roles = []
    for role in json_obj.get('artistTypes', [json_obj.get('type')]):
        roles.append(Role(role))

    return Artist(
        id=json_obj['id'],
        name=json_obj['name'],
        img_uuid=json_obj.get('picture'),
        roles=roles,
        role=roles[0]
    )


def _parse_artists(json_obj):
    return list(map(_parse_artist, json_obj))


def _parse_album(json_obj, artist=None, artists=None):
    if artist is None:
        artist = _parse_artist(json_obj.get('artist'))
    if artists is None:
        artists = _parse_artists(json_obj.get('artists'))
    kwargs = {
        'id': json_obj['id'],
        'name': json_obj['title'],
        'img_uuid': json_obj.get('cover'),
        'num_tracks': json_obj.get('numberOfTracks'),
        'num_discs': json_obj.get('numberOfVolumes'),
        'duration': json_obj.get('duration'),
        'artist': artist,
        'artists': artists,
    }
    if 'releaseDate' in json_obj and json_obj['releaseDate'] is not None:
        try:
            kwargs['release_date'] = datetime.datetime(*map(int, json_obj['releaseDate'].split('-')))
        except ValueError:
            pass
    return Album(**kwargs)


def _parse_featured_playlist(json_obj):
    kwargs = {
        'id': json_obj['artifactId'],
        'name': json_obj['header'],
        'description': json_obj['text'],
    }
    return Playlist(**kwargs)


def _parse_playlist(json_obj):
    kwargs = {
        'id': json_obj['uuid'],
        'name': json_obj['title'],
        'img_uuid': json_obj.get('squareImage'),
        'description': json_obj['description'],
        'num_tracks': int(json_obj['numberOfTracks']),
        'duration': int(json_obj['duration']),
        'is_public': json_obj['publicPlaylist'],
        # TODO 'creator': _parse_user(json_obj['creator']),
    }
    return Playlist(**kwargs)


def _parse_media(json_obj):
    artists = _parse_artists(json_obj.get('artists', []))
    artist = json_obj.get('artist')
    if artist:
        artist = _parse_artist(artist)
    else:
        artist = next((i for i in artists if i.role.main), None)
    album = json_obj.get('album')
    if album:
        album = _parse_album(album, artist, artists)

    kwargs = {
        'id': json_obj['id'],
        'name': json_obj['title'],
        'duration': json_obj['duration'],
        'track_num': json_obj['trackNumber'],
        'disc_num': json_obj['volumeNumber'],
        'version': json_obj.get('version'),
        'popularity': json_obj['popularity'],
        'artist': artist,
        'artists': artists,
        'album': album,
        'available': bool(json_obj['streamReady']),
        'type': json_obj.get('type'),
        'quality': json_obj.get('audioQuality'),
        'replay_gain': json_obj.get('replayGain', 0),
        'peak': json_obj.get('peak', 1),
        'explicit': json_obj.get('explicit', False),
        'release_date': json_obj.get('album', {}).get('releaseDate', ''),
    }

    if kwargs['type'] == 'Music Video':
        return Video(**kwargs)
    return Track(**kwargs)


def _parse_genres(json_obj):
    image = json_obj.get('image')
    image = IMG_URL.format(uuid=image.replace('-', '/'), width=480, height=480) if image else None
    return Category(id=json_obj['path'], name=json_obj['name'], image=image)


def _parse_moods(json_obj):
    image = json_obj.get('image')
    image = IMG_URL.format(uuid=image.replace('-', '/'), width=480, height=480) if image else None
    return Category(id=json_obj['path'], name=json_obj['name'], image=image)


class Favorites(object):

    def __init__(self, session, user_id):
        self._session = session
        self._base_url = 'users/%s/favorites' % user_id

    def add_artist(self, artist_id):
        return self._session.request('POST', self._base_url + '/artists', data={'artistId': artist_id}).ok

    def add_album(self, album_id):
        return self._session.request('POST', self._base_url + '/albums', data={'albumId': album_id}).ok

    def add_track(self, track_id):
        return self._session.request('POST', self._base_url + '/tracks', data={'trackId': track_id}).ok

    def remove_artist(self, artist_id):
        return self._session.request('DELETE', self._base_url + '/artists/%s' % artist_id).ok

    def remove_album(self, album_id):
        return self._session.request('DELETE', self._base_url + '/albums/%s' % album_id).ok

    def remove_track(self, track_id):
        return self._session.request('DELETE', self._base_url + '/tracks/%s' % track_id).ok

    def artists(self):
        return self._session._map_request(self._base_url + '/artists', ret='artists')

    def albums(self):
        return self._session._map_request(self._base_url + '/albums', ret='albums')

    def playlists(self):
        return self._session._map_request(self._base_url + '/playlists', ret='playlists')

    def tracks(self):
        request = self._session.request('GET', self._base_url + '/tracks')
        return [_parse_media(item['item']) for item in request['items']]


class User(object):
    favorites = None

    def __init__(self, session, id):
        """
        :type session: :class:`Session`
        :param id: The user ID
        """
        self._session = session
        self.id = id
        self.favorites = Favorites(session, self.id)

    def playlists(self):
        return self._session.get_user_playlists(self.id)

    def add_playlist(self, title, description):
        path = 'users/{uid}/playlists'.format(uid=self.id)
        return self._session.request('POST', path, data={'title': title, 'description': description})

    def add_tracks_to_playlist(self, playlist_id, track_id_list, to_index=0):
        path = 'playlists/{plid}'.format(plid=playlist_id)
        etag = self._session._request('GET', path).headers['ETag']
        path = 'playlists/{plid}/tracks'.format(plid=playlist_id)
        headers = {'if-none-match': etag}
        data = {'trackIds': ",".join(track_id_list), 'toIndex': to_index}
        return self._session._request('POST', path, data=data, headers=headers)

    def delete_playlist_item(self, item_index, playlist_id):
        path = 'playlists/{plid}/tracks'.format(plid=playlist_id)
        etag = self._session._request('GET', path).headers['ETag']
        headers = {'if-none-match': etag}
        path = 'playlists/{plid}/items/{index}'.format(plid=playlist_id, index=item_index)
        params = {'order': 'INDEX', 'orderDirection': 'ASC'}
        return self._session.request('DELETE', path, headers=headers, params=params)

    def delete_playlist(self, playlist_id):
        path = 'playlists/{plid}'.format(plid=playlist_id)
        etag = self._session._request('GET', path).headers['ETag']
        headers = {'if-none-match': etag}
        return self._session._request('DELETE', path, headers=headers)

