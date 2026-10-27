"""Independent service implementations for contracts read from original bundles.

No HTML, visual assets, production records, outbound requests or UI components.
"""
import base64
import binascii
import hmac
import json
import re
import unicodedata
from datetime import datetime,timezone
from urllib.parse import parse_qs


def iso(timestamp):
    return datetime.fromtimestamp(timestamp,timezone.utc).isoformat()


def display_name_error(value):
    if not isinstance(value,str):return 3,'Display name must be text'
    if len(value)<3:return 1,'Display name is too short'
    if len(value)>20:return 2,'Display name is too long'
    if value!=value.strip() or not all(c in ' _' or unicodedata.category(c)[0] in 'LN' for c in value):
        return 3,'Display name contains unsupported characters'
    return None


def require_session(handler,user,session,mutation=False):
    if not user:
        handler.error(401,'Authentication required');return False
    if mutation and not hmac.compare_digest(handler.headers.get('X-CSRF-TOKEN',''),session['csrf']):
        handler.send(403,{'errors':[{'code':0,'message':'Token Validation Failed'}]},headers={'x-csrf-token':session['csrf']})
        return False
    return True


def page(query,scope):
    limit=int(query.get('limit',['30'])[0])
    if not 1<=limit<=100:raise ValueError('Invalid page size')
    cursor=query.get('cursor',[''])[0]
    offset=0
    if cursor:
        try:
            raw=base64.b64decode(cursor+'='*(-len(cursor)%4),altchars=b'-_',validate=True)
            data=json.loads(raw)
            if data['scope']!=scope or type(data['offset']) is not int or not 0<=data['offset']<=10000000:
                raise ValueError('Invalid cursor scope')
            offset=data['offset']
        except (binascii.Error,ValueError,KeyError,TypeError,UnicodeDecodeError) as e:
            raise ValueError('Invalid cursor') from e
    return limit,offset


def cursor(scope,offset):
    return base64.urlsafe_b64encode(json.dumps({'scope':scope,'offset':offset},separators=(',',':')).encode()).decode().rstrip('=')


def catalog_item(row):
    return {'id':row['id'],'itemType':'Asset','assetType':row['asset_type'],'name':row['name'],
            'price':row['price'],'creatorType':'User','creatorTargetId':row['creator_id'],
            'creatorName':row['creator_name']}


def dispatch(handler,host,path,query_string,user,session):
    """True means handled, including a rejected/invalid implemented request."""
    store=handler.app.store
    method=handler.command
    query=parse_qs(query_string,keep_blank_values=True)
    name_match=re.fullmatch(r'/v1/users/(\d+)/display-names(/validate)?',path)
    if host=='users.roblox.com' and name_match and method in ('GET','PATCH'):
        if not require_session(handler,user,session,method=='PATCH'):return True
        if int(name_match[1])!=user['id']:
            handler.error(403,'Only your independent display name can be edited');return True
        if method=='GET' and name_match[2]:
            value=query.get('displayName',[''])[0]
        elif method=='PATCH' and not name_match[2]:
            value=handler.json_body().get('newDisplayName')
        else:
            handler.error(405,'Method not supported');return True
        error=display_name_error(value)
        if error:
            handler.error(400,error[1],error[0]);return True
        if method=='PATCH':store.update(user['id'],'display_name',value)
        handler.send(200,{});return True

    settings_paths={'/v1/user-settings','/v1/user-settings/settings-and-options','/v2/user-settings/settings-and-options-subset'}
    settings_path=path.removeprefix('/user-settings-api') if host=='apis.roblox.com' and path.startswith('/user-settings-api/') else None
    if settings_path in settings_paths and method in ('GET','POST'):
        if not require_session(handler,user,session,method=='POST'):return True
        options={'accountTheme':handler.app.contracts.account_themes,'whoCanSeeMyInventory':('AllUsers','Friends','NoOne')}
        if method=='POST':
            if settings_path!='/v1/user-settings':handler.error(405,'Method not supported');return True
            changes=handler.json_body()
            if not changes:handler.error(400,'No settings supplied');return True
            # Validate the entire mutation before touching persistent state.
            if set(changes)-set(options):
                handler.error(501,'This independent setting is not implemented');return True
            if any(not isinstance(v,str) or v not in options[k] for k,v in changes.items()):
                handler.error(400,'Invalid setting option');return True
            store.update_settings(user['id'],changes)
            handler.send(200,{});return True
        settings=store.settings(user['id'])
        requested=[x for value in query.get('requestedUserSettings',[]) for x in value.split(',') if x]
        keys=requested or list(options)
        if set(keys)-set(options):
            handler.error(501,'A requested independent setting is not implemented');return True
        if settings_path=='/v1/user-settings':
            handler.send(200,{k:settings[k] for k in keys});return True
        v2=settings_path.startswith('/v2/')
        handler.send(200,{key:{'currentValue':settings[key],'options':[
            {'option':{'optionValue':value},**({'requiredActions':[]} if v2 else {'requirement':None})}
            for value in options[key]]} for key in keys});return True

    inventory_match=re.fullmatch(r'/v(?:(1)/users/(\d+)/categories|(2)/users/(\d+)/inventory/(\d+))',path)
    if host=='inventory.roblox.com' and inventory_match and method=='GET':
        owner=int(inventory_match[2] or inventory_match[4])
        if not store.user(owner):handler.error(404,'Independent user not found');return True
        if not store.can_view_inventory(owner,user['id'] if user else None):
            handler.error(403,'Inventory is private');return True
        if inventory_match[1]:
            handler.send(200,{'categories':handler.app.contracts.inventory_categories});return True
        asset_type=int(inventory_match[5])
        order=query.get('sortOrder',['Desc'])[0]
        if order not in ('Asc','Desc'):raise ValueError('Invalid sort order')
        scope=f'inventory:{owner}:{asset_type}:{order}'
        limit,offset=page(query,scope)
        rows=store.inventory(owner,asset_type,limit+1,offset,order=='Desc')
        handler.send(200,{'data':[{'assetId':row['id'],'name':row['name'],'assetType':row['asset_type'],
                                  'created':iso(row['acquired']),'updated':iso(row['acquired'])} for row in rows[:limit]],
                          'nextPageCursor':cursor(scope,offset+limit) if len(rows)>limit else None,
                          'previousPageCursor':cursor(scope,max(0,offset-limit)) if offset else None});return True

    if host=='catalog.roblox.com' and path=='/v1/catalog/items/details' and method=='POST':
        body=handler.json_body()
        items=body.get('items')
        if not isinstance(items,list) or len(items)>100:raise ValueError('Invalid catalog lookup')
        if any(not isinstance(item,dict) or item.get('itemType')!='Asset' or type(item.get('id')) is not int or item['id']<=0 for item in items):
            raise ValueError('Only local asset identifiers are supported')
        rows={row['id']:row for row in store.catalog_items(list(dict.fromkeys(item['id'] for item in items)))}
        handler.send(200,{'data':[catalog_item(rows[item['id']]) for item in items if item['id'] in rows]});return True
    return False
