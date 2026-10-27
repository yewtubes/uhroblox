"""Validate browser captures and quarantine them; never activate account data.

No network operations, archive extraction, authentication replay, or execution
of captured JavaScript occurs here. Run against the local project checkout.
"""
import argparse
import base64
import hashlib
import json
import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

FORMAT = 'roblox-original-client-auth-capture'
MAX_CAPTURE_BYTES = 200 * 1024 * 1024
MAX_RESOURCE_BYTES = 12 * 1024 * 1024
SECRET_QUERY = re.compile(r'token|signature|policy|key-pair-id|auth|ticket|password|code|session|email|phone|access', re.I)
ROUTE = re.compile(r'^/(?:home/?|my/(?:account|avatar)/?|users/friends/?|users/__LOCAL_USER_ID__/(?:profile|inventory)/?)$')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def static_url(url):
    try:
        u = urlsplit(url)
        if u.scheme != 'https' or u.username or u.password or u.fragment or u.port not in (None, 443):
            return False
        for key, _ in parse_qsl(u.query):
            if SECRET_QUERY.search(key) or key.lower() not in ('v', 'version', 'locale', 'languagecode'):
                return False
        if u.hostname == 'www.roblox.com':
            return u.path.startswith('/js/') and u.path.lower().endswith('.js')
        if not (u.hostname or '').endswith('.rbxcdn.com') or u.hostname.split('.')[0] in ('tr','thumbnails','sourcemaps'):
            return False
        return bool(re.search(r'\.(?:js|css|woff2?|ttf|otf|png|jpe?g|webp|gif|svg|ico)(?:/fetch)?$',u.path,re.I))
    except (TypeError, ValueError):
        return False


class UserMetadata(HTMLParser):
    def __init__(self):
        super().__init__()
        self.user = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'meta' and a.get('name') == 'user-data':
            self.user = a


def validate_capture(data):
    if not isinstance(data, dict) or data.get('format') != FORMAT or data.get('version') != 1:
        raise ValueError('Unsupported capture format')
    privacy = data.get('privacy', {})
    for key in ('rawAccountAPIBodiesCaptured','requestHeadersCaptured','cookiesRead','storageRead','uploadsPerformed'):
        if privacy.get(key) is not False:
            raise ValueError('Capture privacy declaration is missing or unsafe: '+key)
    if privacy.get('manualReviewRequired') is not True:
        raise ValueError('Capture must be marked for manual review')
    pages, resources = data.get('pages', []), data.get('resources', [])
    if not isinstance(pages,list) or not isinstance(resources,list) or len(pages)>12 or len(resources)>650:
        raise ValueError('Capture exceeds item limits')
    objects, documents, assets = {}, {}, {}
    for page in pages:
        route = page.get('route', '')
        final_route = page.get('finalRoute', '')
        if not ROUTE.fullmatch(route) or not ROUTE.fullmatch(final_route):
            raise ValueError('Document route is outside capture scope')
        if page.get('authenticated') is not True:
            raise ValueError('Document is not marked as authenticated')
        body = page.get('html')
        if not isinstance(body, str):
            raise ValueError('Document HTML is missing')
        encoded = body.encode()
        if len(encoded)>MAX_RESOURCE_BYTES or sha(encoded)!=page.get('storedSha256'):
            raise ValueError('Document hash or size mismatch')
        if not re.fullmatch(r'[a-f0-9]{64}',page.get('sourceSha256','')):
            raise ValueError('Document source provenance is missing')
        parser = UserMetadata(); parser.feed(body)
        if not parser.user or parser.user.get('data-userid')!='__LOCAL_USER_ID__':
            raise ValueError('Document lacks redacted original user metadata')
        if re.search(r'\.ROBLOSECURITY\s*=\s*(?!__REDACTED__)[^\s;"\'<>]+',body,re.I):
            raise ValueError('Possible account credential in document; do not import')
        if re.search(r'Bearer\s+[A-Za-z0-9._~-]{20,}',body,re.I):
            raise ValueError('Possible bearer credential in document; do not import')
        if route in documents:
            raise ValueError('Duplicate document route')
        digest=sha(encoded);objects[digest]=encoded
        documents[route]={'final_route':final_route,'sha256':digest,'source_sha256':page['sourceSha256'],
                          'authenticated':True,'requires_local_bootstrap_binding':True,
                          'redactions':page.get('redactions',{})}
    for entry in resources:
        url=entry.get('url','')
        if not static_url(url) or entry.get('encoding')!='base64':
            raise ValueError('Non-public static resource or unsupported encoding')
        try:
            body=base64.b64decode(entry.get('body',''),validate=True)
        except (ValueError,TypeError) as e:
            raise ValueError('Invalid resource bytes') from e
        digest=sha(body)
        if len(body)>MAX_RESOURCE_BYTES or len(body)!=entry.get('bytes') or digest!=entry.get('sha256'):
            raise ValueError('Resource hash or size mismatch')
        if 'html' in entry.get('contentType','').lower() or 'json' in entry.get('contentType','').lower():
            raise ValueError('Account/API responses are not static client resources')
        if url in assets:
            raise ValueError('Duplicate static resource')
        objects[digest]=body
        assets[url]={'sha256':digest,'size':len(body),'content_type':entry.get('contentType','application/octet-stream')}
    issues=data.get('issues',[])
    if not isinstance(issues,list):
        raise ValueError('Invalid issues list')
    manifest={'format':FORMAT+'-staged','version':1,'activation_allowed':False,'manual_review_required':True,
              'captured_at':data.get('createdAt'),'documents':documents,'resources':assets,
              'unavailable_count':len(issues),'unfetched_public_asset_urls':[u for u in data.get('assetUrls',[]) if static_url(u) and u not in assets],
              'note':'Original response HTML was scrubbed before export. Bind independent user metadata and local API data before activation. Raw account API responses were not collected.'}
    return manifest, objects


def import_capture(input_path, project_root):
    input_path, project_root=Path(input_path), Path(project_root)
    if input_path.stat().st_size>MAX_CAPTURE_BYTES:
        raise ValueError('Capture exceeds file size limit')
    if not (project_root/'capture'/'manifest.json').is_file():
        raise ValueError('Choose the existing project root containing capture/manifest.json')
    raw=input_path.read_bytes()
    manifest,objects=validate_capture(json.loads(raw))
    destination=project_root/'capture'/'authenticated-staging'/sha(raw)[:16]
    (destination/'objects').mkdir(parents=True,exist_ok=True)
    for digest,body in objects.items():
        (destination/'objects'/digest).write_bytes(body)
    manifest['capture_sha256']=sha(raw)
    (destination/'manifest.json').write_text(json.dumps(manifest,indent=2))
    report={'staging_directory':str(destination.resolve()),'documents':len(manifest['documents']),
            'public_resources':len(manifest['resources']),'unavailable_count':manifest['unavailable_count'],
            'activated':False,'manual_review_required':True}
    return report


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('capture_json',type=Path)
    ap.add_argument('--project-root',type=Path,default=Path.cwd())
    args=ap.parse_args()
    try:
        print(json.dumps(import_capture(args.capture_json,args.project_root),indent=2))
    except (ValueError,OSError,TypeError,KeyError) as e:
        raise SystemExit('Capture not imported: '+str(e))
