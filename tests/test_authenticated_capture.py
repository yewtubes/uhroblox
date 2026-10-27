import base64
import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
TOOLS=ROOT/'tools'/'auth_capture'
spec=importlib.util.spec_from_file_location('auth_capture_importer',TOOLS/'import-authenticated.py')
importer=importlib.util.module_from_spec(spec)
spec.loader.exec_module(importer)


def js(expression):
    code='const api=require('+json.dumps(str(TOOLS/'capture-authenticated.js'))+'); console.log(JSON.stringify('+expression+'));'
    return json.loads(subprocess.check_output(['node','-e',code],text=True))


class CaptureScriptTests(unittest.TestCase):
    def test_read_only_pages_exclude_transactions_messages_and_auth_actions(self):
        self.assertTrue(js('api.allowedPage("/home")'))
        self.assertTrue(js('api.allowedPage("/my/account")'))
        for route in ['/my/messages','/transactions','/v2/logout','https://elsewhere.example/home']:
            self.assertFalse(js('api.allowedPage('+json.dumps(route)+')'))

    def test_export_routes_remove_query_and_bind_user_id_placeholder(self):
        self.assertEqual(js('api.normalizeRoute("/users/4321/profile?token=private#details","4321")'),'/users/__LOCAL_USER_ID__/profile')

    def test_static_resource_scope_excludes_secrets_and_dynamic_thumbnails(self):
        self.assertEqual(js('api.staticURL("https://js.rbxcdn.com/abc-Home.js")'),'https://js.rbxcdn.com/abc-Home.js')
        self.assertEqual(js('api.staticURL("https://static.rbxcdn.com/css/site.css/fetch")'),'https://static.rbxcdn.com/css/site.css/fetch')
        for url in ['https://js.rbxcdn.com/a.js?token=secret','https://tr.rbxcdn.com/a.webp','https://auth.roblox.com/a.js','https://unrelated.example/a.js','http://js.rbxcdn.com/a.js']:
            self.assertIsNone(js('api.staticURL('+json.dumps(url)+')'))

    def test_html_redaction_retains_original_navigation_and_auth_code(self):
        html='''<!DOCTYPE html><html><head><meta name="user-data" data-userid="4321" data-name="PrivateUsername" data-displayname="PrivateDisplay"><meta name="csrf-token" data-token="fake-secret-token"><script src="https://js.rbxcdn.com/original.js"></script></head><body><nav class="original-navigation"></nav><input type="password" value="fake-password"><script>function originalAuth(){return !!document.querySelector('meta[name="user-data"]')}</script><textarea>private bio</textarea></body></html>'''
        result=js('api.scrubHTML('+json.dumps(html)+')')['html']
        for value in ['4321','PrivateUsername','PrivateDisplay','fake-secret-token','fake-password','private bio']:
            self.assertNotIn(value,result)
        self.assertIn('data-userid="__LOCAL_USER_ID__"',result)
        self.assertIn('src="https://js.rbxcdn.com/original.js"',result)
        self.assertIn('<nav class="original-navigation"></nav>',result)
        self.assertIn("function originalAuth(){return !!document.querySelector('meta[name=\"user-data\"]')}",result)

    def test_production_hydration_and_credentials_not_exported_as_local_data(self):
        data={'templates':{'original':{'type':'unchanged-component'}},'hydrationData':{'universe':{'42':{'name':'Production game'}}},'pageEntries':[{'universeItems':[{'universeId':42}]}], 'user':{'id':4321,'name':'PrivateName','email':'private@example.test'},'accessToken':'fake-token'}
        result=js('api.scrubJSON('+json.dumps(data)+')')
        self.assertEqual(result['templates'],data['templates'])
        self.assertEqual(result['hydrationData']['universe'],{})
        self.assertEqual(result['pageEntries'][0]['universeItems'],[])
        self.assertEqual(result['user']['id'],'__LOCAL_USER_ID__')
        self.assertNotIn('fake-token',json.dumps(result))


class CaptureImporterTests(unittest.TestCase):
    def fixture(self):
        html='<!DOCTYPE html><html><head><meta name="user-data" data-userid="__LOCAL_USER_ID__" data-name="__LOCAL_USERNAME__"></head><body></body></html>'
        public=b'/* original captured public bundle bytes */'
        digest=lambda b:hashlib.sha256(b).hexdigest()
        return {'format':importer.FORMAT,'version':1,'createdAt':'2026-10-26T00:00:00Z',
                'privacy':{'manualReviewRequired':True,'rawAccountAPIBodiesCaptured':False,'requestHeadersCaptured':False,'cookiesRead':False,'storageRead':False,'uploadsPerformed':False},
                'pages':[{'route':'/home','finalRoute':'/home','authenticated':True,'sourceSha256':digest(b'original response before data scrubbing'), 'storedSha256':digest(html.encode()),'html':html}],
                'resources':[{'url':'https://js.rbxcdn.com/abc-Home.js','contentType':'application/javascript','encoding':'base64','body':base64.b64encode(public).decode(),'bytes':len(public),'sha256':digest(public)}],
                'issues':[],'assetUrls':['https://js.rbxcdn.com/abc-Home.js','https://css.rbxcdn.com/abc.css']}

    def test_valid_capture_is_quarantined_without_changing_active_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'capture').mkdir()
            active=root/'capture'/'manifest.json';active.write_text('{"original_guest_capture":true}')
            source=root/'capture-input.json';source.write_text(json.dumps(self.fixture()))
            report=importer.import_capture(source,root)
            self.assertFalse(report['activated'])
            self.assertEqual(active.read_text(),'{"original_guest_capture":true}')
            staged=json.loads((Path(report['staging_directory'])/'manifest.json').read_text())
            self.assertFalse(staged['activation_allowed'])
            self.assertEqual(staged['documents']['/home']['requires_local_bootstrap_binding'],True)
            self.assertEqual(staged['unfetched_public_asset_urls'],['https://css.rbxcdn.com/abc.css'])

    def test_tampered_response_hash_is_rejected(self):
        fixture=self.fixture();fixture['pages'][0]['html']+='changed'
        with self.assertRaisesRegex(ValueError,'hash'):
            importer.validate_capture(fixture)

    def test_real_user_metadata_cannot_activate_through_import(self):
        fixture=self.fixture();page=fixture['pages'][0]
        page['html']=page['html'].replace('__LOCAL_USER_ID__','4321')
        page['storedSha256']=hashlib.sha256(page['html'].encode()).hexdigest()
        with self.assertRaisesRegex(ValueError,'redacted'):
            importer.validate_capture(fixture)

    def test_nonstatic_or_credential_url_is_rejected(self):
        for url in ['https://auth.roblox.com/v1/account','https://js.rbxcdn.com/a.js?token=private']:
            fixture=self.fixture();fixture['resources'][0]['url']=url
            with self.assertRaisesRegex(ValueError,'static'):
                importer.validate_capture(fixture)

    def test_request_header_capture_is_rejected(self):
        fixture=self.fixture();fixture['privacy']['requestHeadersCaptured']=True
        with self.assertRaisesRegex(ValueError,'privacy'):
            importer.validate_capture(fixture)

    def test_path_traversal_is_rejected(self):
        fixture=self.fixture();fixture['pages'][0]['route']='/../../server.py'
        with self.assertRaisesRegex(ValueError,'route'):
            importer.validate_capture(fixture)


if __name__=='__main__':
    unittest.main()
