import http.client
import json
import re
import subprocess
import tempfile
import threading
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import patch

from server import ROOT, make_server, rewrite
from storage import Store


class MetaParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.dataset = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'meta' and a.get('name') == 'user-data':
            self.dataset = {k[5:]:v for k,v in a.items() if k.startswith('data-')}


class GatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Path(cls.tmp.name)/'db.sqlite3'
        cls.server = make_server(0, database=cls.db)
        cls.store = cls.server.application.store
        cls.user_id = cls.store.create('IndependentUser', 'Independent-test-password-2026')
        cls.other_id = cls.store.create('AnotherLocalUser', 'Another-test-password-2026')
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.tmp.cleanup()

    def request(self, path, method='GET', body=None, headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port)
        h = dict(headers or {})
        if body is not None:
            body = json.dumps(body)
            h['Content-Type'] = 'application/json'
        conn.request(method, path, body, h)
        r = conn.getresponse()
        status, headers, body = r.status, dict(r.getheaders()), r.read()
        conn.close()
        return status, headers, body

    def session_headers(self):
        token, csrf, _ = self.store.login('IndependentUser', 'Independent-test-password-2026')
        return {'Cookie': 'local_session='+token, 'X-CSRF-TOKEN': csrf}

    def test_original_login_and_provenance(self):
        status, headers, body = self.request('/login')
        self.assertEqual(status, 200)
        self.assertIn(b'react-login-web-app', body)
        self.assertIn('X-Preservation-Source-SHA256', headers)
        self.assertIn("connect-src 'self'", headers['Content-Security-Policy'])

    def test_guest_has_no_auth_metadata(self):
        _, _, b = self.request('/catalog')
        parser = MetaParser(); parser.feed(b.decode())
        self.assertIsNone(parser.dataset)

    def test_landing_uses_original_templates_without_production_game_data(self):
        import re
        status, _, body = self.request('/')
        self.assertEqual(status, 200)
        match = re.search(rb'<script id="landing-page-api-response"[^>]*>(.*?)</script>', body, re.S)
        data = json.loads(match[1])
        self.assertIn('templates', data)
        self.assertTrue(data['templates'])
        self.assertEqual(data['hydrationData']['universe'], {})
        self.assertNotIn(b'Dress To Impress', body)
        self.assertNotIn(b'15101393044', body)
        self.assertIn(b'125124081670923', body)  # Original static hero video.
        self.assertIn(b'105014709880567', body)  # Original static hero image.

    def test_public_configuration_survives_original_locale_query(self):
        status, _, body = self.request('/__upstream/catalog.roblox.com/v1/catalog/metadata?languageCode=en_us')
        self.assertEqual(status, 200)
        self.assertIn('isAutocompleteEnabled', json.loads(body))

    def test_static_hero_image_decodes_original_gzip_transport(self):
        status, headers, body = self.request('/__upstream/assetdelivery.roblox.com/v1/asset?id=105014709880567')
        self.assertEqual(status, 200)
        self.assertEqual(headers['Content-Type'], 'image/png')
        self.assertTrue(body.startswith(b'\x89PNG\r\n\x1a\n'))

    def test_original_video_byte_ranges(self):
        status, headers, body = self.request('/__upstream/assetdelivery.roblox.com/v1/asset?id=125124081670923', headers={'Range':'bytes=0-15'})
        self.assertEqual(status, 206)
        self.assertEqual(len(body), 16)
        self.assertTrue(body.startswith(b'\x1aE\xdf\xa3'))
        self.assertEqual(headers['Content-Type'], 'video/webm')
        self.assertTrue(headers['Content-Range'].startswith('bytes 0-15/'))

    def test_original_sdk_environment_uses_only_local_captured_media(self):
        status, _, body = self.request('/__upstream/assetdelivery.sitetest3.robloxlabs.com/v2/asset?Id=125124081670923')
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn('/__upstream/sc5.rbxcdn.com/',data['locations'][0]['location'])
        self.assertNotIn('https://sc5.rbxcdn.com/',data['locations'][0]['location'])

    def test_actual_original_auth_parser_sees_only_valid_local_session(self):
        for headers, expected in [({}, False), ({'Cookie':'local_session=invalid'}, False), (self.session_headers(), True)]:
            status, _, b = self.request('/catalog', headers=headers)
            self.assertEqual(status, 200)
            parser = MetaParser(); parser.feed(b.decode())
            original = (ROOT/'evidence'/'original-auth-check.js').read_text()
            script = 'const dataset='+json.dumps(parser.dataset)+'; const document={querySelector:()=>dataset===null?null:{dataset}};\n'+original+'\nconsole.log(JSON.stringify({isAuthenticated:nd(),user:np()}));'
            result = json.loads(subprocess.check_output(['node','-e',script]))
            self.assertEqual(result['isAuthenticated'], expected)
            if expected:
                self.assertEqual(result['user']['id'], self.user_id)
                self.assertEqual(result['user']['name'], 'IndependentUser')

    def test_authenticated_user_does_not_receive_guest_documents(self):
        h = self.session_headers()
        for route in ['/', '/login', '/CreateAccount', '/login/forgot-password-or-username']:
            status, headers, b = self.request(route, headers=h)
            self.assertEqual(status, 302)
            self.assertEqual(headers['Location'], '/home')
            self.assertEqual(b, b'')

    def test_missing_authenticated_home_is_not_guest_login(self):
        with patch.dict(self.server.application.auth_manifest, {'documents':{}}):
            status, headers, b = self.request('/home', headers=self.session_headers())
        self.assertEqual(status, 503)
        self.assertNotIn(b'react-login', b)
        self.assertIn('application/json', headers['Content-Type'])

    def test_original_authenticated_documents_bind_local_identity(self):
        h=self.session_headers()
        routes={'/home':b'places-list-web-app','/my/account':b'react-user-account-base',
                '/my/avatar':b'avatar-web-app','/users/friends':b'friends-web-app',
                f'/users/{self.user_id}/profile':b'profile-platform-container',
                f'/users/{self.user_id}/inventory':b'inventory-container'}
        for route,mount in routes.items():
            with self.subTest(route=route):
                status,headers,body=self.request(route,headers=h)
                self.assertEqual(status,200)
                self.assertIn(mount,body)
                self.assertEqual(headers['X-Preservation-Identity'],'independent-local-session')
                self.assertIn('X-Preservation-Template-SHA256',headers)
                parser=MetaParser();parser.feed(body.decode())
                self.assertEqual(parser.dataset['userid'],str(self.user_id))
                self.assertEqual(parser.dataset['name'],'IndependentUser')
                self.assertEqual(len(re.findall(rb'<meta\b[^>]*name="user-data"',body)),1)
                self.assertNotRegex(body,rb'__LOCAL_[A-Z_]+__')
                self.assertIn(('data-token="'+h['X-CSRF-TOKEN']+'"').encode(),body)

    def test_authenticated_documents_are_unavailable_without_valid_session(self):
        for route in ['/my/account','/my/avatar','/users/friends',f'/users/{self.user_id}/inventory']:
            for h in [{},{'Cookie':'local_session=invalid'}]:
                status,headers,body=self.request(route,headers=h)
                self.assertEqual(status,302)
                self.assertTrue(headers['Location'].startswith('/login?returnUrl='))
                self.assertEqual(body,b'')

    def test_authenticated_profile_separates_viewer_and_target(self):
        status,_,body=self.request(f'/users/{self.other_id}/profile',headers=self.session_headers())
        self.assertEqual(status,200)
        self.assertIn(f'data-profile-id="{self.other_id}"'.encode(),body)
        self.assertIn(b'AnotherLocalUser - Roblox',body)
        parser=MetaParser();parser.feed(body.decode())
        self.assertEqual(parser.dataset['userid'],str(self.user_id))
        self.assertEqual(self.request('/users/999999999/profile',headers=self.session_headers())[0],404)

    def test_authenticated_document_access_is_revoked_on_logout(self):
        h=self.session_headers()
        self.assertEqual(self.request('/home',headers=h)[0],200)
        self.assertEqual(self.request('/__upstream/auth.roblox.com/v2/logout','POST',{},h)[0],200)
        self.assertEqual(self.request('/home',headers=h)[0],302)

    def test_authenticated_reads_project_only_independent_records(self):
        h=self.session_headers()
        with self.store.connect() as db:
            db.execute('INSERT OR REPLACE INTO wallet(user_id,balance) VALUES (?,?)',(self.user_id,57))
            db.execute("INSERT OR REPLACE INTO friendships VALUES (?,?,'accepted')",(self.user_id,self.other_id))
        status,_,body=self.request('/my/settings/json',headers=h)
        self.assertEqual(status,200)
        self.assertEqual(json.loads(body)['Name'],'IndependentUser')
        base='/__upstream/economy.roblox.com/v1/users/'
        self.assertEqual(json.loads(self.request(base+str(self.user_id)+'/currency',headers=h)[2]),{'robux':57})
        self.assertEqual(self.request(base+str(self.other_id)+'/currency',headers=h)[0],403)
        self.assertEqual(self.request(base+str(self.user_id)+'/currency')[0],401)
        base='/__upstream/friends.roblox.com/v1/users/'
        self.assertEqual(json.loads(self.request(base+str(self.user_id)+'/friends/count')[2]),{'count':1})
        status,_,body=self.request(base+str(self.user_id)+'/friends/find?limit=18',headers=h)
        self.assertEqual(status,200)
        self.assertEqual(json.loads(body)['PageItems'],[{'id':self.other_id,'name':'AnotherLocalUser','displayName':'AnotherLocalUser'}])
        self.assertEqual(self.request(base+str(self.other_id)+'/friends/find',headers=h)[0],403)
        self.assertEqual(self.request(base+str(self.user_id)+'/friends/online',headers=h)[0],501)

    def test_anonymous_home_preserves_captured_redirect(self):
        status, headers, _ = self.request('/home')
        self.assertEqual(status, 302)
        self.assertTrue(headers['Location'].endswith('/Login'))

    def test_unknown_document_returns_json_not_custom_page(self):
        status, headers, b = self.request('/not-a-captured-page')
        self.assertEqual(status, 404)
        self.assertIn('application/json', headers['Content-Type'])
        self.assertNotIn(b'<html', b)

    def test_local_credentials_auth_csrf_and_revocation(self):
        data = {'ctype':'Username','cvalue':'IndependentUser','password':'Independent-test-password-2026'}
        route = '/__upstream/auth.roblox.com/v2/login'
        status, headers, _ = self.request(route, 'POST', data)
        self.assertEqual(status, 403)
        status, headers, body = self.request(route, 'POST', data, {'X-CSRF-TOKEN':headers['x-csrf-token']})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['user']['name'], 'IndependentUser')
        self.assertIn('HttpOnly', headers['Set-Cookie'])
        cookie = headers['Set-Cookie'].split(';')[0]
        h = {'Cookie':cookie}
        self.assertEqual(self.request('/__upstream/users.roblox.com/v1/users/authenticated', headers=h)[0], 200)
        status, challenge, _ = self.request('/__upstream/auth.roblox.com/v2/logout', 'POST', {}, h)
        self.assertEqual(status, 403)
        h['X-CSRF-TOKEN'] = challenge['x-csrf-token']
        self.assertEqual(self.request('/__upstream/auth.roblox.com/v2/logout', 'POST', {}, h)[0], 200)
        self.assertEqual(self.request('/__upstream/users.roblox.com/v1/users/authenticated', headers=h)[0], 401)

    def test_cross_origin_login_rejected(self):
        self.assertEqual(self.request('/__upstream/auth.roblox.com/v2/login', 'POST', {}, {'Origin':'https://unrelated.example'})[0],403)

    def test_profile_is_local_data_not_captured_real_user(self):
        body = {'profileType':'User','profileId':self.user_id,'components':[]}
        status, _, b = self.request('/__upstream/apis.roblox.com/profile-platform-api/v1/profiles/get', 'POST', body)
        self.assertEqual(status,200)
        data=json.loads(b)
        self.assertEqual(data['components']['UserProfileHeader']['names']['primaryName'],'IndependentUser')
        self.assertNotIn('CurrentlyWearing',data['components'])

    def test_profile_document_uses_original_mount_for_requested_local_user(self):
        status, headers, b = self.request(f'/users/{self.other_id}/profile')
        self.assertEqual(status,200)
        self.assertIn(f'data-profile-id="{self.other_id}"'.encode(),b)
        self.assertIn(b'AnotherLocalUser - Roblox',b)
        self.assertIn('X-Preservation-Source-SHA256',headers)

    def test_missing_thumbnail_stays_unimplemented(self):
        status, headers, b = self.request('/__upstream/thumbnails.roblox.com/v1/batch','POST',{})
        self.assertEqual(status,501)
        self.assertIn('application/json',headers['Content-Type'])
        self.assertNotIn(b'imageUrl',b)

    def test_catalog_empty_database_is_real_empty_result(self):
        status, _, b=self.request('/__upstream/catalog.roblox.com/v2/search/items/details?limit=30&keyword=hat')
        self.assertEqual(status,200)
        self.assertEqual(json.loads(b)['data'],[])

    def test_passwords_not_plaintext_and_persistence(self):
        store=Store(self.db)
        user=store.user(self.user_id)
        self.assertNotEqual(user['password_hash'],'Independent-test-password-2026')
        self.assertEqual(user['name'],'IndependentUser')
        self.assertIsNone(store.login('IndependentUser','wrong-password'))
        store.update(self.user_id,'description','Saved independent bio')
        self.assertEqual(Store(self.db).user(self.user_id)['description'],'Saved independent bio')

    def test_transport_rebase_keeps_auth_function_exact(self):
        original=(ROOT/'evidence'/'original-auth-check.js').read_text()
        self.assertEqual(rewrite(original,'http://localhost:3000','js.rbxcdn.com','text/javascript'),original)

    def test_runtime_serves_original_guest_play_code(self):
        from urllib.parse import urlsplit
        meta=json.loads((ROOT/'evidence/original-play-branches.json').read_text())
        source=urlsplit(meta['source_url'])
        status, headers, body=self.request('/__upstream/'+source.hostname+source.path)
        self.assertEqual(status,200)
        self.assertEqual(headers['X-Preservation-Source-SHA256'],meta['source_sha256'])
        raw=(ROOT/'capture/objects'/meta['source_sha256']).read_text()
        for part in meta['parts'].values():
            self.assertIn(raw[part['start_offset']:part['end_offset']].encode(),body)

    def test_runtime_has_no_production_http_proxy(self):
        with patch('urllib.request.urlopen',side_effect=AssertionError('Unexpected outbound request')):
            status, _, _=self.request('/__upstream/gamejoin.roblox.com/v1/join-game','POST',{})
            self.assertEqual(status,501)


if __name__ == '__main__':
    unittest.main()
