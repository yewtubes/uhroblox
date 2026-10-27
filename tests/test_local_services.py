import http.client
import json
import re
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.parse import urlencode

from client_contracts import bundle
from server import ROOT,make_server
from storage import Store

SETTINGS='/__upstream/apis.roblox.com/user-settings-api/v1/user-settings'


class LocalServicesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        cls.database=Path(cls.tmp.name)/'platform.sqlite3'
        cls.server=make_server(0,database=cls.database)
        cls.store=cls.server.application.store
        cls.owner=cls.store.create('LocalOwner','separate-local-test-password')
        cls.friend=cls.store.create('LocalFriend','separate-local-test-password')
        cls.stranger=cls.store.create('LocalStranger','separate-local-test-password')
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
        token,csrf,_=cls.store.login('LocalOwner','separate-local-test-password')
        cls.owner_headers={'Cookie':'local_session='+token,'X-CSRF-TOKEN':csrf}
        token,csrf,_=cls.store.login('LocalFriend','separate-local-test-password')
        cls.friend_headers={'Cookie':'local_session='+token,'X-CSRF-TOKEN':csrf}
        with cls.store.connect() as db:
            db.execute("INSERT INTO friendships VALUES (?,?,'accepted')",(cls.owner,cls.friend))
            for name,kind,acquired in [('First local face',18,1),('Second local face',18,2),('Third local face',18,2),('Local hat',8,3)]:
                asset=db.execute('INSERT INTO catalog(name,asset_type,price,creator_id) VALUES (?,?,0,?)',(name,kind,cls.owner)).lastrowid
                db.execute('INSERT INTO inventory VALUES (?,?,?)',(cls.owner,asset,acquired))

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join();cls.tmp.cleanup()

    def tearDown(self):
        self.store.update_settings(self.owner,{'accountTheme':'Default','whoCanSeeMyInventory':'AllUsers'})
        self.store.update(self.owner,'display_name','LocalOwner')

    def request(self,path,method='GET',body=None,headers=None):
        connection=http.client.HTTPConnection('127.0.0.1',self.server.server_port)
        headers=dict(headers or {})
        if body is not None:
            body=json.dumps(body);headers['Content-Type']='application/json'
        connection.request(method,path,body,headers)
        response=connection.getresponse();raw=response.read()
        result=response.status,dict(response.getheaders()),raw
        connection.close();return result

    def json(self,path,method='GET',body=None,headers=None):
        status,h,raw=self.request(path,method,body,headers)
        return status,h,json.loads(raw)

    def test_display_name_validation_persistence_and_original_metadata(self):
        route=f'/__upstream/users.roblox.com/v1/users/{self.owner}/display-names'
        for value,code in [('ab',1),('A'*21,2),('<script>',3)]:
            status,_,body=self.json(route+'/validate?'+urlencode({'displayName':value}),headers=self.owner_headers)
            self.assertEqual(status,400);self.assertEqual(body['errors'][0]['code'],code)
        name='Local Player'
        self.assertEqual(self.json(route+'/validate?'+urlencode({'displayName':name}),headers=self.owner_headers)[0],200)
        self.assertEqual(self.json(route,'PATCH',{'newDisplayName':name},self.owner_headers)[0],200)
        self.assertEqual(Store(self.database).user(self.owner)['display_name'],name)
        self.assertEqual(self.json('/my/settings/json',headers=self.owner_headers)[2]['DisplayName'],name)
        status,_,body=self.request('/home',headers=self.owner_headers)
        self.assertEqual(status,200);self.assertIn(b'data-displayname="Local Player"',body)

    def test_display_name_requires_owner_and_csrf(self):
        route=f'/__upstream/users.roblox.com/v1/users/{self.owner}/display-names'
        self.assertEqual(self.json(route,'PATCH',{'newDisplayName':'Changed Name'})[0],401)
        no_csrf={'Cookie':self.owner_headers['Cookie']}
        status,headers,_=self.json(route,'PATCH',{'newDisplayName':'Changed Name'},no_csrf)
        self.assertEqual(status,403);self.assertEqual(headers['x-csrf-token'],self.owner_headers['X-CSRF-TOKEN'])
        self.assertEqual(self.json(route,'PATCH',{'newDisplayName':'Changed Name'},self.friend_headers)[0],403)
        self.assertEqual(self.store.user(self.owner)['display_name'],'LocalOwner')

    def test_settings_are_persistent_isolated_and_atomic(self):
        self.assertEqual(self.json(SETTINGS,'POST',{'accountTheme':'Classic'},self.owner_headers)[0],200)
        self.assertEqual(Store(self.database).settings(self.owner)['accountTheme'],'Classic')
        self.assertEqual(self.json(SETTINGS+'?requestedUserSettings=accountTheme',headers=self.owner_headers)[2],{'accountTheme':'Classic'})
        self.assertEqual(self.json(SETTINGS+'?requestedUserSettings=accountTheme',headers=self.friend_headers)[2],{'accountTheme':'Default'})
        for changes,status in [({'accountTheme':'InventedTheme'},400),({'accountTheme':'Default','enablePurchases':True},501)]:
            self.assertEqual(self.json(SETTINGS,'POST',changes,self.owner_headers)[0],status)
            self.assertEqual(self.store.settings(self.owner)['accountTheme'],'Classic')
        self.assertEqual(self.json(SETTINGS+'?requestedUserSettings=enablePurchases',headers=self.owner_headers)[0],501)

    def test_settings_require_local_session_and_csrf(self):
        self.assertEqual(self.json(SETTINGS)[0],401)
        self.assertEqual(self.json(SETTINGS,'POST',{'accountTheme':'Classic'})[0],401)
        self.assertEqual(self.json(SETTINGS,'POST',{'accountTheme':'Classic'},{'Cookie':self.owner_headers['Cookie']})[0],403)
        self.assertEqual(self.store.settings(self.owner)['accountTheme'],'Default')

    def test_original_option_filter_accepts_local_settings_response(self):
        source,_=bundle(ROOT,self.server.application.manifest,'UserSettings')
        start=source.index('h5=function(');end=source.index(',h8=',start)
        original='var '+source[start:end]+';'
        for route in [SETTINGS+'/settings-and-options','/__upstream/apis.roblox.com/user-settings-api/v2/user-settings/settings-and-options-subset']:
            status,_,data=self.json(route,headers=self.owner_headers);self.assertEqual(status,200)
            options=data['whoCanSeeMyInventory']['options']
            code=original+'console.log(JSON.stringify(h5([{value:"AllUsers"},{value:"Friends"},{value:"NoOne"},{value:"Invented"}],'+json.dumps(options)+')));'
            filtered=json.loads(subprocess.check_output(['node','-e',code],text=True))
            self.assertEqual(filtered,[{'value':'AllUsers'},{'value':'Friends'},{'value':'NoOne'}])
            self.assertIn('currentValue',data['accountTheme'])

    def test_inventory_categories_are_original_bundle_constants(self):
        route=f'/__upstream/inventory.roblox.com/v1/users/{self.owner}/categories'
        status,_,body=self.json(route)
        self.assertEqual(status,200)
        self.assertEqual(body['categories'],self.server.application.contracts.inventory_categories)
        self.assertEqual(len(body['categories']),22)
        # Public mapping configuration needed by the unchanged original client.
        for name in ['asset-to-category','asset-to-subcategory']:
            self.assertEqual(self.json('/__upstream/catalog.roblox.com/v1/'+name+'?languageCode=en_us')[0],200)

    def test_inventory_pagination_filtering_and_cursor_scope(self):
        base=f'/__upstream/inventory.roblox.com/v2/users/{self.owner}/inventory/'
        status,_,first=self.json(base+'18?limit=2&sortOrder=Desc')
        self.assertEqual(status,200)
        self.assertEqual([r['name'] for r in first['data']],['Third local face','Second local face'])
        status,_,second=self.json(base+'18?'+urlencode({'limit':2,'sortOrder':'Desc','cursor':first['nextPageCursor']}))
        self.assertEqual(status,200);self.assertEqual([r['name'] for r in second['data']],['First local face'])
        self.assertIsNone(second['nextPageCursor'])
        status,_,back=self.json(base+'18?'+urlencode({'limit':2,'cursor':second['previousPageCursor']}))
        self.assertEqual([r['assetId'] for r in back['data']],[r['assetId'] for r in first['data']])
        self.assertEqual(self.json(base+'8?'+urlencode({'cursor':first['nextPageCursor']}))[0],400)
        for query in ['limit=0','limit=101','cursor=bad!','sortOrder=Invalid']:
            self.assertEqual(self.json(base+'18?'+query)[0],400)
        self.assertEqual([r['name'] for r in self.json(base+'18?sortOrder=Asc')[2]['data']],['First local face','Second local face','Third local face'])
        self.assertEqual(self.json(base+'17')[2]['data'],[])

    def test_inventory_privacy_enforced_in_api_and_original_document(self):
        route=f'/__upstream/inventory.roblox.com/v2/users/{self.owner}/inventory/18'
        self.assertEqual(self.json(SETTINGS,'POST',{'whoCanSeeMyInventory':'NoOne'},self.owner_headers)[0],200)
        self.assertEqual(self.json(route)[0],403)
        self.assertEqual(self.json(route,headers=self.friend_headers)[0],403)
        self.assertEqual(self.json(route,headers=self.owner_headers)[0],200)
        status,_,doc=self.request(f'/users/{self.owner}/inventory',headers=self.friend_headers)
        self.assertEqual(status,200);self.assertIn(b'can-view-inventory="False"',doc)
        self.assertEqual(self.json(SETTINGS,'POST',{'whoCanSeeMyInventory':'Friends'},self.owner_headers)[0],200)
        self.assertEqual(self.json(route,headers=self.friend_headers)[0],200)
        self.assertEqual(self.json(route)[0],403)
        status,_,doc=self.request(f'/users/{self.owner}/inventory',headers=self.friend_headers)
        self.assertEqual(status,200);self.assertIn(b'can-view-inventory="True"',doc)
        with self.store.connect() as db:db.execute("UPDATE friendships SET state='pending' WHERE requester=? AND recipient=?",(self.owner,self.friend))
        try:self.assertEqual(self.json(route,headers=self.friend_headers)[0],403)
        finally:
            with self.store.connect() as db:db.execute("UPDATE friendships SET state='accepted' WHERE requester=? AND recipient=?",(self.owner,self.friend))

    def test_catalog_hydrates_only_existing_local_inventory_records(self):
        listing=self.json(f'/__upstream/inventory.roblox.com/v2/users/{self.owner}/inventory/18')[2]['data']
        items=[{'id':row['assetId'],'itemType':'Asset'} for row in listing]+[{'id':99999999,'itemType':'Asset'}]
        status,_,body=self.json('/__upstream/catalog.roblox.com/v1/catalog/items/details','POST',{'items':items})
        self.assertEqual(status,200);self.assertEqual(len(body['data']),3)
        self.assertTrue(all(r['creatorName']=='LocalOwner' for r in body['data']))
        self.assertEqual({r['id'] for r in body['data']},{r['assetId'] for r in listing})
        self.assertNotIn('imageUrl',json.dumps(body))
        self.assertEqual(self.json('/__upstream/catalog.roblox.com/v1/catalog/items/details','POST',{'items':[{'id':1,'itemType':'Bundle'}]})[0],400)

    def test_operator_can_populate_independent_catalog_and_inventory(self):
        # A separate database prevents test fixtures entering the real platform.
        with tempfile.TemporaryDirectory() as tmp:
            database=Path(tmp)/'operator.sqlite3';store=Store(database)
            user=store.create('LocalCreator','independent-test-only-password')
            command=['python',str(ROOT/'manage.py'),'--database',str(database)]
            output=subprocess.check_output(command+['create-asset','--owner',str(user),'--type','18','--name','Independent Face'],text=True)
            self.assertIn('Asset bytes and thumbnails are not configured',output)
            asset=store.catalog_search()[0]['id']
            first=subprocess.check_output(command+['grant-asset','--user',str(user),'--asset',str(asset)],text=True)
            second=subprocess.check_output(command+['grant-asset','--user',str(user),'--asset',str(asset)],text=True)
            self.assertIn('Granted local asset',first);self.assertIn('already owned',second)
            self.assertEqual(len(Store(database).inventory(user,18,30,0)),1)
            with self.assertRaises(ValueError):store.grant_asset(user,999999)


if __name__=='__main__':unittest.main()
