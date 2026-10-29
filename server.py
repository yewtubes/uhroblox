"""Offline replay gateway plus independent, explicitly implemented API handlers.

The serving process performs NO outbound HTTP requests. Missing documents are
JSON errors, never replacement HTML. Originals remain content-addressed on disk.
"""
import argparse
import hashlib
import gzip
import hmac
import html
import json
import os
import re
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from storage import Store
from capture_store import read_object
from auth_documents import AUTH_PATHS, auth_route, bind_document, bind_user_metadata
from client_contracts import ClientContracts
from local_api import dispatch as dispatch_local_api

ROOT = Path(__file__).resolve().parent
PREFIX = '/__upstream/'
HOST_URL = re.compile(r'(?<![A-Za-z0-9:])(?:https?:)?//((?:[A-Za-z0-9-]+\.)*(?:roblox\.com|rbxcdn\.com))(?=[:/\s\"\'<>]|$)(?::\d+)?')


class Application:
    def __init__(self, root=ROOT, database=None):
        self.root = Path(root)
        p = self.root / 'capture' / 'manifest.json'
        self.manifest = json.loads(p.read_text())
        self.manifest_mtime = p.stat().st_mtime_ns
        self.contracts = ClientContracts(self.root,self.manifest)
        self.auth_path = self.root/'capture'/'authenticated'/'manifest.json'
        self.auth_manifest = json.loads(self.auth_path.read_text()) if self.auth_path.exists() else {'documents':{}}
        self.auth_mtime = self.auth_path.stat().st_mtime_ns if self.auth_path.exists() else None
        self.store = Store(database or self.root / 'data' / 'platform.sqlite3')
        self.failed = set()
        self.attempts = defaultdict(deque)
        self.lock = threading.Lock()

    def limited(self, ip):
        with self.lock:
            q = self.attempts[ip]
            now = time.monotonic()
            while q and q[0] < now - 60:
                q.popleft()
            q.append(now)
            return len(q) > 10

    def missing(self, method, host, path):
        # Never log request bodies, passwords, cookies, tokens, or query values.
        key = (method, host, path)
        with self.lock:
            if key not in self.failed:
                self.failed.add(key)
                p = self.root / 'data' / 'unimplemented.jsonl'
                p.parent.mkdir(exist_ok=True)
                with p.open('a') as f:
                    f.write(json.dumps({'method': method, 'host': host, 'path': path}) + '\n')


def rewrite(text, origin, source_host, content_type):
    # Keep service URLs in JS valid for the client's original URL validators.
    # The transport adapter rebases requests only at the browser network layer.
    if 'javascript' in content_type:
        return text.replace('concat(window.location.protocol,"//").concat(window.location.hostname)',
                            'concat(window.location.protocol,"//").concat(window.location.host)')
    escaped = '\\/' in text
    if escaped:
        # Preserve escaping inside JSON/JS; process only URL prefixes.
        text = re.sub(r'https?:\\/\\/([A-Za-z0-9.-]+(?:roblox\.com|rbxcdn\.com))',
                      lambda m: (origin + ('' if m[1] in ('www.roblox.com', 'roblox.com') else PREFIX + m[1])).replace('/', '\\/'), text)
    text = HOST_URL.sub(lambda m: origin + ('' if m[1] in ('www.roblox.com', 'roblox.com') else PREFIX + m[1]), text)
    # The original URL helper drops local preview ports by using hostname.
    # Change only its URL construction, not auth checks or UI code.
    text = text.replace('concat(window.location.protocol,"//").concat(window.location.hostname)',
                        'concat(window.location.protocol,"//").concat(window.location.host)')
    if 'css' in content_type and source_host not in ('www.roblox.com', 'roblox.com'):
        text = re.sub(r'(url\(\s*[\"\']?)/(?!/)', lambda m: m[1] + PREFIX + source_host + '/', text)
    if 'html' in content_type:
        # Integrity values describe upstream bytes, which change when rebased.
        text = re.sub(r'\s+integrity=[\"\'][^\"\']*[\"\']', '', text)
        text = re.sub(r'<meta[^>]+http-equiv=[\"\']Content-Security-Policy[\"\'][^>]*>', '', text, flags=re.I)
        text = re.sub(r'(<head[^>]*>)', r'\1<script src="/__local/adapter.js"></script>', text, count=1, flags=re.I)
    return text


def user_bootstrap(text, user):
    """Feed the ORIGINAL user-data parser. This never builds navigation/UI."""
    if not user:
        return text
    return bind_user_metadata(text,user)


def independent_bootstrap(text):
    """Remove production DATA; retain exact captured SDUI layout/templates.

    The local games/recommendation service is not implemented yet. Original
    components receive no production recommendations or hydrated game records.
    """
    def replace(match):
        data = json.loads(match[2])
        data['hydrationData'] = {key: {} for key in data.get('hydrationData', {})}

        def clear_records(value):
            if isinstance(value, dict):
                return {key: [] if key in ('universeItems', 'gameItems', 'gameItemsCompact')
                        else clear_records(item) for key, item in value.items()}
            if isinstance(value, list):
                return [clear_records(x) for x in value]
            return value

        data['pageEntries'] = clear_records(data.get('pageEntries', []))
        return match[1] + json.dumps(data, separators=(',', ':'), ensure_ascii=False).replace('</', '<\\/') + match[3]

    return re.sub(r'(<script\b[^>]*\bid="landing-page-api-response"[^>]*>)(.*?)(</script>)',
                  replace, text, flags=re.S | re.I)


class Handler(BaseHTTPRequestHandler):
    server_version = 'PreservedClient/0.1'

    @property
    def app(self):
        return self.server.application

    def log_message(self, fmt, *args):
        # BaseHTTPRequestHandler's normal log includes full query strings.
        pass

    def origin(self):
        configured = os.environ.get('PUBLIC_ORIGIN')
        if configured:
            return configured.rstrip('/')
        host = self.headers.get('Host', '127.0.0.1:3000')
        if not re.fullmatch(r'[A-Za-z0-9.\-\[\]:]+', host):
            raise ValueError('Invalid Host')
        scheme = 'https' if self.headers.get('X-Forwarded-Proto') == 'https' else 'http'
        return scheme + '://' + host

    def send(self, status, body=b'', mime='application/json; charset=utf-8', headers=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; frame-src 'self'; media-src 'self' blob:; worker-src 'self' blob:; form-action 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'self'")
        for k, v in (headers or {}).items():
            self.send_header(k, str(v))
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def error(self, status, message, code=0):
        self.send(status, {'errors': [{'code': code, 'message': message}]})

    def token(self):
        c = SimpleCookie()
        try:
            c.load(self.headers.get('Cookie', ''))
            return c['local_session'].value if 'local_session' in c else ''
        except Exception:
            return ''

    def json_body(self, allow_list=False):
        n = int(self.headers.get('Content-Length', '0'))
        if n < 0 or n > 64 * 1024:
            raise ValueError('Request body too large')
        data = json.loads(self.rfile.read(n) or b'{}')
        if not isinstance(data, dict) and not (allow_list and isinstance(data, list)):
            raise ValueError('Expected JSON object')
        return data

    def do_HEAD(self):
        self.handle_request()

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

    def do_PATCH(self):
        self.handle_request()

    def do_OPTIONS(self):
        self.send(204)

    def handle_request(self):
        try:
            self.dispatch()
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            self.error(400, 'Invalid request')
        except (BrokenPipeError, ConnectionResetError):
            pass

    def dispatch(self):
        mp = self.app.root/'capture'/'manifest.json'
        if mp.stat().st_mtime_ns != self.app.manifest_mtime:
            with self.app.lock:
                self.app.manifest = json.loads(mp.read_text())
                self.app.manifest_mtime = mp.stat().st_mtime_ns
        if self.app.auth_path.exists() and self.app.auth_path.stat().st_mtime_ns != self.app.auth_mtime:
            with self.app.lock:
                self.app.auth_manifest=json.loads(self.app.auth_path.read_text())
                self.app.auth_mtime=self.app.auth_path.stat().st_mtime_ns
        split = urlsplit(self.path)
        host, path = 'www.roblox.com', split.path
        if path.startswith(PREFIX):
            host, sep, tail = path[len(PREFIX):].partition('/')
            if not sep or not re.fullmatch(r'(?:[A-Za-z0-9-]+\.)*(?:roblox\.com|rbxcdn\.com|robloxlabs\.com)', host):
                return self.error(400, 'Invalid local service route')
            path = '/' + tail
            # The original video SDK selects sitetest3 on non-Roblox hosts.
            # Alias that transport locally; do not alter its rendering code.
            if host == 'assetdelivery.sitetest3.robloxlabs.com':
                host = 'assetdelivery.roblox.com'
        session = self.app.store.session(self.token())
        user = self.app.store.user(session['user_id']) if session else None
        if self.command not in ('GET', 'HEAD', 'OPTIONS'):
            origin = self.headers.get('Origin')
            if origin and origin != self.origin():
                return self.error(403, 'Cross-origin request rejected')
        if path == '/__local/adapter.js' and self.command in ('GET', 'HEAD'):
            return self.send(200, (self.app.root/'adapter.js').read_bytes(), 'text/javascript; charset=utf-8')
        if path == '/__local/status' and self.command in ('GET', 'HEAD'):
            return self.send(200, {'mode': 'offline', 'customPages': 0, 'outboundProxy': False,
                                   'resources': len(self.app.manifest['resources']),
                                   'documents': self.app.manifest['documents'],
                                   'authenticatedDocuments':list(self.app.auth_manifest['documents']),
                                   'unimplementedEndpointsObserved': len(self.app.failed)})
        # These are guest documents, not interchangeable authenticated pages.
        if host in ('www.roblox.com', 'roblox.com') and self.command in ('GET', 'HEAD'):
            if user and path.lower() in ('/', '/login', '/createaccount', '/login/forgot-password-or-username', '/account/signupredir'):
                return self.send(302, headers={'Location': '/home'})
            key,target_id=auth_route(path)
            captured=self.app.auth_manifest['documents'].get(key)
            if path in AUTH_PATHS and path != '/home' and not user and captured:
                from urllib.parse import urlencode
                return self.send(302,headers={'Location':'/login?'+urlencode({'returnUrl':self.path})})
            if captured and user:
                target=self.app.store.user(target_id) if target_id else user
                if not target:
                    return self.error(404,'Independent user not found')
                body=read_object(self.app.root,captured['sha256'])
                if hashlib.sha256(body).hexdigest()!=captured['sha256']:
                    return self.error(500,'Authenticated template integrity check failed')
                text=bind_document(body.decode(),user,target,session['csrf'])
                if key.endswith('/inventory'):
                    visible=self.app.store.can_view_inventory(target['id'],user['id'])
                    text=re.sub(r'(\bcan-view-inventory=)["\'][^"\']*["\']',
                                lambda m:m[1]+'"'+str(visible)+'"',text)
                text=independent_bootstrap(text)
                text=rewrite(text,self.origin(),host,'text/html')
                return self.send(200,text,'text/html; charset=utf-8',{
                    'X-Preservation-Source-SHA256':captured['source_response_sha256_reported'],
                    'X-Preservation-Template-SHA256':captured['sha256'],
                    'X-Preservation-Identity':'independent-local-session'})
            if user and path.lower() == '/home':
                return self.error(503, 'Original authenticated Home document has not been captured')
            if not user and key and key.endswith('/inventory') and captured:
                from urllib.parse import urlencode
                return self.send(302,headers={'Location':'/login?'+urlencode({'returnUrl':self.path})})
            if path == '/account/signupredir':
                return self.send(302, headers={'Location': '/CreateAccount'})
        if dispatch_local_api(self,host,path,split.query,user,session):
            return
        if host in ('www.roblox.com','roblox.com') and path=='/my/settings/json' and self.command=='GET':
            if not user:
                return self.error(401,'Authentication required')
            return self.send(200,{'UserId':user['id'],'Name':user['name'],'DisplayName':user['display_name'],
                                  'IsEmailOnFile':False,'IsEmailVerified':False,'HasPasswordSet':True,
                                  'UserAbove13':True,'IsPremium':False})
        currency=re.fullmatch(r'/v1/users/(\d+)/currency',path)
        if host=='economy.roblox.com' and currency and self.command=='GET':
            if not user:
                return self.error(401,'Authentication required')
            if int(currency[1])!=user['id']:
                return self.error(403,'Only your independent balance is accessible')
            return self.send(200,{'robux':self.app.store.balance(user['id'])})
        friends=re.fullmatch(r'/v1/users/(\d+)/friends/(count|find|online)',path)
        if host=='friends.roblox.com' and friends and self.command=='GET':
            owner=self.app.store.user(int(friends[1]))
            if not owner:
                return self.error(404,'User not found')
            if friends[2]=='count':
                return self.send(200,{'count':self.app.store.friend_count(owner['id'])})
            if not user:
                return self.error(401,'Authentication required')
            if owner['id']!=user['id']:
                return self.error(403,'Only your independent connections are accessible')
            if friends[2]=='online':
                # Presence infrastructure is not implemented; never invent it.
                return self.error(501,'Independent friend presence is not implemented')
            rows=self.app.store.friends(owner['id'])
            return self.send(200,{'PageItems':[{'id':row['id'],'name':row['name'],'displayName':row['display_name']} for row in rows],
                                  'NextCursor':None,'PreviousCursor':None})
        if host == 'auth.roblox.com' and path == '/v2/login' and self.command == 'POST':
            if self.app.limited(self.client_address[0]):
                return self.error(429, 'Too many attempts', 6)
            # Login itself also uses a local double-submit CSRF challenge.
            challenge = hashlib.sha256((self.server.csrf_secret + self.client_address[0]).encode()).hexdigest()
            if not hmac.compare_digest(self.headers.get('X-CSRF-TOKEN', ''), challenge):
                return self.send(403, {'errors': [{'code': 0, 'message': 'Token Validation Failed'}]}, headers={'x-csrf-token': challenge})
            b = self.json_body()
            if b.get('ctype', b.get('credentialType')) not in ('Username', 0):
                return self.error(400, 'Only independent local usernames are supported', 1)
            name, password = b.get('cvalue', ''), b.get('password', '')
            if not isinstance(name, str) or not isinstance(password, str) or len(password) > 200:
                return self.error(400, 'Invalid local credentials', 1)
            result = self.app.store.login(name, password)
            if not result:
                return self.error(400, 'Incorrect username or password.', 1)
            token, csrf, u = result
            secure = '; Secure' if self.origin().startswith('https:') else ''
            return self.send(200, {'user': {'id': u['id'], 'name': u['name'], 'displayName': u['display_name']},
                                   'isBanned': False, 'twoStepVerificationData': None},
                             headers={'Set-Cookie': f'local_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400{secure}', 'x-csrf-token': csrf})
        if host == 'auth.roblox.com' and path == '/v2/logout' and self.command == 'POST':
            if not session:
                return self.error(401, 'Authentication required')
            if not hmac.compare_digest(self.headers.get('X-CSRF-TOKEN', ''), session['csrf']):
                return self.send(403, {'errors': [{'code': 0, 'message': 'Token Validation Failed'}]}, headers={'x-csrf-token': session['csrf']})
            self.app.store.logout(self.token())
            return self.send(200, {}, headers={'Set-Cookie': 'local_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0'})
        if host == 'users.roblox.com' and path == '/v1/users/authenticated' and self.command == 'GET':
            if not user:
                return self.error(401, 'Authentication required')
            return self.send(200, {'id': user['id'], 'name': user['name'], 'displayName': user['display_name']})
        if host == 'users.roblox.com' and path == '/v1/description' and self.command == 'POST':
            if not user:
                return self.error(401, 'Authentication required')
            if not hmac.compare_digest(self.headers.get('X-CSRF-TOKEN', ''), session['csrf']):
                return self.send(403, {'errors': [{'code': 0, 'message': 'Token Validation Failed'}]}, headers={'x-csrf-token': session['csrf']})
            value = self.json_body().get('description')
            if not isinstance(value, str) or len(value) > 1000:
                return self.error(400, 'Description must be at most 1000 characters')
            self.app.store.update(user['id'], 'description', value)
            return self.send(200, {'description': value})
        if host == 'catalog.roblox.com' and path == '/v2/search/items/details' and self.command == 'GET':
            query = parse_qs(split.query)
            limit = max(1, min(120, int(query.get('limit', ['30'])[0])))
            offset = max(0, int(query.get('cursor', ['0'])[0] or '0'))
            rows = self.app.store.catalog_search(query.get('Keyword', query.get('keyword', ['']))[0], limit + 1, offset)
            items = [{'id': c['id'], 'itemType': 'Asset', 'assetType': c['asset_type'], 'name': c['name'],
                      'price': c['price'], 'creatorType': 'User', 'creatorTargetId': c['creator_id'],
                      'creatorName': c['creator_name'], 'favoriteCount': 0} for c in rows[:limit]]
            return self.send(200, {'data': items, 'keyword': query.get('Keyword', query.get('keyword', ['']))[0],
                                   'previousPageCursor': str(max(0, offset-limit)) if offset else None,
                                   'nextPageCursor': str(offset+limit) if len(rows)>limit else None})
        if host == 'apis.roblox.com' and path == '/profile-platform-api/v1/profiles/get' and self.command == 'POST':
            b = self.json_body()
            if b.get('profileType') != 'User':
                return self.error(501, 'This independent profile type is not implemented')
            u = self.app.store.user(int(b.get('profileId', 0)))
            if not u:
                return self.error(404, 'User not found')
            count = self.app.store.friend_count(u['id'])
            # Shape and component keys verified against the captured bundle and
            # a public read-only response, not a recreated page layout.
            components = {
                'UserProfileHeader': {'userId': u['id'], 'isPremium': False, 'isVerified': False, 'isRobloxAdmin': False,
                    'counts': {'friendsCount': count, 'followersCount': 0, 'followingsCount': 0, 'mutualFriendsCount': 0,
                               'isFriendsCountEnabled': False, 'isFollowersCountEnabled': False, 'isFollowingsCountEnabled': False, 'isMutualFriendsCountEnabled': False},
                    'names': {'primaryName': u['display_name'], 'username': u['name'], 'displayName': u['display_name']},
                    'school': None, 'contextualInformation': {'context': 'None'}, 'editName': None,
                    'viewerRelationship': {'friendshipStatus': 'None', 'trustedFriendStatus': 'NotEligible'}},
                'ProfileBackground': {'assetId': None},
            }
            return self.send(200, {'profileType': 'User', 'profileId': str(u['id']),
                                   'componentOrdering': ['ProfileBackground', 'UserProfileHeader'], 'components': components,
                                   'onlyEssentialComponents': None, 'gracefulDegradationEnabled': False})
        if host == 'thumbnails.roblox.com' and path == '/v1/batch' and self.command == 'POST':
            payload = self.json_body(allow_list=True)
            if isinstance(payload, list):
                # Public content identifiers only; never credentials or bodies
                # from any other endpoint. Used by the offline capture tooling.
                records = [{k: x[k] for k in ('type','targetId','size','format','version','isCircular') if k in x}
                           for x in payload if isinstance(x, dict)]
                with self.app.lock:
                    with (self.app.root/'data'/'thumbnail-requests.jsonl').open('a') as f:
                        f.write(json.dumps(records)+'\n')
            self.app.missing(self.command, host, path)
            return self.error(501, 'Original thumbnail response not captured')
        match = re.fullmatch(r'/v1/users/(\d+)', path)
        if host == 'users.roblox.com' and match and self.command == 'GET':
            u = self.app.store.user(int(match[1]))
            if not u:
                return self.error(404, 'User not found')
            return self.send(200, {'id': u['id'], 'name': u['name'], 'displayName': u['display_name'],
                                   'description': u['description'], 'created': datetime.fromtimestamp(u['created'], timezone.utc).isoformat(),
                                   'isBanned': False, 'hasVerifiedBadge': False, 'externalAppDisplayName': None})
        if self.command in ('GET', 'HEAD'):
            url = 'https://' + host + path + (('?' + split.query) if split.query else '')
            e = self.app.manifest['resources'].get(url)
            if not e and host.endswith('.rbxcdn.com'):
                # CDN signatures/CMCD parameters are transport metadata. Only
                # an already-captured immutable path can match this lookup.
                e = next((saved for saved_url, saved in self.app.manifest['resources'].items()
                          if urlsplit(saved_url).hostname == host and urlsplit(saved_url).path == path), None)
            if not e and host == 'assetdelivery.roblox.com':
                q = parse_qs(split.query)
                asset_id = q.get('id', q.get('Id', [None]))[0]
                for saved_url, saved in self.app.manifest['resources'].items():
                    p = urlsplit(saved_url)
                    sq = parse_qs(p.query)
                    if p.hostname == host and p.path == path and asset_id and sq.get('id', sq.get('Id', [None]))[0] == asset_id:
                        e = saved
                        break
            if not e and host == 'www.roblox.com':
                e = self.app.manifest['resources'].get('https://roblox.com' + path + (('?' + split.query) if split.query else ''))
            # Captured public configuration defaults (not user data) may be
            # requested with locale/cache query parameters by the original code.
            if not e and (host, path) in {
                ('catalog.roblox.com', '/v1/catalog/metadata'),
                ('catalog.roblox.com', '/v1/asset-to-category'),
                ('catalog.roblox.com', '/v1/asset-to-subcategory'),
                ('catalog.roblox.com', '/v1/search/navigation-menu-items'),
                ('locale.roblox.com', '/v1/locales'),
                ('locale.roblox.com', '/v1/locales/user-localization-locus-supported-locales'),
                ('apis.roblox.com', '/otp-service/v1/metadata'),
                ('apis.roblox.com', '/auth-token-service/v1/login/metadata'),
                ('apis.rbxcdn.com', '/captcha/v1/metadata'),
            }:
                e = self.app.manifest['resources'].get('https://' + host + path)
            # Page query parameters belong to the local request, not capture identity.
            if not e and host in ('www.roblox.com', 'roblox.com'):
                doc = self.app.manifest['documents'].get(path)
                if doc:
                    e = self.app.manifest['resources'][doc]
                profile = re.fullmatch(r'/users/(\d+)/profile', path)
                if profile:
                    if not self.app.store.user(int(profile[1])):
                        return self.error(404, 'Independent user not found')
                    doc = self.app.manifest['documents'].get('/users/1/profile')
                    e = self.app.manifest['resources'][doc] if doc else None
            if e:
                final = urlsplit(e['final_url'])
                # A login redirect is a redirect, NOT a recovered authenticated page.
                if 'html' in e['content_type'] and final.path.lower() != path.lower() and not re.fullmatch(r'/users/\d+/profile', path):
                    location = self.origin() + ('' if final.hostname in ('www.roblox.com', 'roblox.com') else PREFIX + final.hostname) + final.path
                    if final.query:
                        location += '?' + final.query
                    return self.send(302, headers={'Location': location})
                body = read_object(self.app.root,e['sha256'])
                if hashlib.sha256(body).hexdigest() != e['sha256']:
                    return self.error(500, 'Captured resource integrity check failed')
                # CDN asset delivery may return transport-compressed files with
                # an octet-stream type. Preserve the raw capture, decode only
                # the HTTP representation served to the local browser.
                if body.startswith(b'\x1f\x8b'):
                    body = gzip.decompress(body)
                mime = e['content_type']
                if 'octet-stream' in mime:
                    if body.startswith(b'\x89PNG\r\n\x1a\n'):
                        mime = 'image/png'
                    elif body.startswith(b'\xff\xd8\xff'):
                        mime = 'image/jpeg'
                    elif body.startswith(b'RIFF') and body[8:12] == b'WEBP':
                        mime = 'image/webp'
                    elif body.startswith(b'\x1aE\xdf\xa3'):
                        mime = 'video/webm'
                    elif body[4:8] == b'ftyp':
                        mime = 'video/mp4'
                if any(x in e['content_type'] for x in ('text/', 'javascript', 'json', 'svg')):
                    text = rewrite(body.decode('utf-8'), self.origin(), host, e['content_type'])
                    if 'html' in e['content_type']:
                        text = independent_bootstrap(text)
                        text = user_bootstrap(text, user)
                        profile = re.fullmatch(r'/users/(\d+)/profile', path)
                        if profile:
                            u = self.app.store.user(int(profile[1]))
                            text = text.replace('data-profile-id="1"', 'data-profile-id="'+profile[1]+'"')
                            text = text.replace('<title>Roblox - Roblox</title>', '<title>'+html.escape(u['display_name'])+' - Roblox</title>')
                            text = text.replace('Roblox&#x27;s Profile', html.escape(u['display_name'], quote=True)+'&#x27;s Profile')
                    body = text.encode()
                # Video players request byte ranges while seeking/buffering.
                headers = {'X-Preservation-Source-SHA256': e.get('original_sha256',e['sha256'])}
                if e.get('publication_transform'):
                    headers['X-Preservation-Template-SHA256']=e['sha256']
                if mime.startswith(('image/', 'video/', 'font/')):
                    headers['Accept-Ranges'] = 'bytes'
                    range_header = self.headers.get('Range')
                    if range_header:
                        match = re.fullmatch(r'bytes=(\d*)-(\d*)', range_header)
                        if not match or not (match[1] or match[2]):
                            return self.send(416, headers={'Content-Range':f'bytes */{len(body)}'})
                        total = len(body)
                        start = int(match[1]) if match[1] else max(0,total-int(match[2]))
                        end = min(total-1,int(match[2])) if match[1] and match[2] else total-1
                        if start >= total or start > end:
                            return self.send(416, headers={'Content-Range':f'bytes */{total}'})
                        headers['Content-Range'] = f'bytes {start}-{end}/{total}'
                        return self.send(206, body[start:end+1], mime, headers)
                return self.send(200, body, mime, headers)
        self.app.missing(self.command, host, path)
        self.error(501 if host not in ('www.roblox.com', 'roblox.com', 'js.rbxcdn.com', 'css.rbxcdn.com', 'static.rbxcdn.com') else 404,
                   'Independent endpoint not implemented' if host.endswith('roblox.com') and host != 'www.roblox.com' else 'Original resource not captured')


def make_server(port=3000, host='127.0.0.1', root=ROOT, database=None):
    server = ThreadingHTTPServer((host, port), Handler)
    server.application = Application(root, database)
    server.csrf_secret = os.urandom(32).hex()
    return server


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=int(os.environ.get('PORT', '3000')))
    ap.add_argument('--strictPort', action='store_true', help=argparse.SUPPRESS)
    args = ap.parse_args()
    server = make_server(args.port, args.host)
    print(f'Preserved client serving locally on port {server.server_port}; no outbound proxy', flush=True)
    server.serve_forever()
