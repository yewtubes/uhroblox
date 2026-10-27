"""Bind reviewed original authenticated documents to independent local data.

No layouts/components are constructed here. Only captured bootstrap fields,
page identity data and local security values are bound before serving HTML.
"""
import hashlib
import html
import json
import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

AUTH_PATHS = {'/home', '/my/account', '/my/avatar', '/users/friends'}
USER_META = re.compile(r'<meta\b(?=[^>]*\bname=["\']user-data["\'])[^>]*>', re.I)


class CaptureParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.profile_id = None
        self.resources = set()

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if a.get('data-profile-id', '').isdigit():
            self.profile_id = a['data-profile-id']
        if tag == 'div' and a.get('data-staticcomponentdata'):
            data = json.loads(a['data-staticcomponentdata'])
            for components in data.values():
                for component in components:
                    for key in ('jsBundleTags', 'cssBundleTags', 'localizationBundleTags'):
                        for markup in component.get(key, []):
                            for url in re.findall(r'(?:src|href)=["\']([^"\']+)', markup):
                                self.resources.add(url)


def prepare_templates(capture, project_root):
    """Review a validated export into data-free document templates.

    Keep the unactivated import in authenticated-staging. This creates separate
    derivatives after binding rules have been implemented and tested.
    """
    root = Path(project_root)
    parser = CaptureParser()
    for page in capture['pages']:
        if page['route'].endswith('/profile'):
            parser.feed(page['html'])
    old_id = parser.profile_id
    documents = {}
    embedded = set()
    for page in capture['pages']:
        text = page['html']
        p = CaptureParser(); p.feed(text); embedded.update(p.resources)
        # The original marker in the captured profile mount is a target ID,
        # separate from the viewing user's original user-data metadata.
        text = re.sub(r'(\bdata-profile-id=)["\'][^"\']*["\']',
                      r'\1"__LOCAL_TARGET_USER_ID__"', text)
        if old_id:
            marker = '__LOCAL_TARGET_USER_ID__' if page['route'].endswith(('/profile','/inventory')) else '__LOCAL_USER_ID__'
            text = re.sub(r'(?<!\d)' + re.escape(old_id) + r'(?!\d)', marker, text)
        if page['route'].endswith(('/profile', '/inventory')):
            text = re.sub(r'(<title[^>]*>).*?(</title>)',r'\1__LOCAL_DOCUMENT_TITLE__\2',text,flags=re.S|re.I)
            text = re.sub(r'(<meta\b[^>]*\b(?:property|name)=["\'](?:og:title|twitter:title)["\'][^>]*\bcontent=)["\'][^"\']*["\']',
                          r'\1"__LOCAL_DOCUMENT_TITLE__"', text, flags=re.I)
            # Do not publish a captured real user's social-preview avatar.
            text = re.sub(r'(<meta\b[^>]*\b(?:property|name)=["\'](?:og:image|twitter:image)["\'][^>]*\bcontent=)["\'][^"\']*["\']',
                          r'\1""', text, flags=re.I)
        if old_id and re.search(r'(?<!\d)' + re.escape(old_id) + r'(?!\d)',text):
            raise ValueError('Captured target identity remains in template')
        if not USER_META.search(text) or '__LOCAL_USER_ID__' not in text:
            raise ValueError('Original authenticated metadata contract missing')
        body = text.encode()
        digest = hashlib.sha256(body).hexdigest()
        (root/'capture'/'objects'/digest).write_bytes(body)
        documents[page['route']] = {
            'sha256':digest, 'source_response_sha256_reported':page['sourceSha256'],
            'scrubbed_capture_sha256':page['storedSha256'], 'captured_at':capture['createdAt'],
            'content_type':'text/html; charset=utf-8',
            'data_binding':'independent-local-session',
        }
    manifest = {'version':1,'documents':documents,'source':'reviewed original browser-response capture',
                'layouts_recreated':False,'captured_account_records_imported':False,
                'requires_valid_local_session':True}
    dest=root/'capture'/'authenticated'
    dest.mkdir(exist_ok=True)
    (dest/'manifest.json').write_text(json.dumps(manifest,indent=2))
    return manifest, sorted(embedded)


def auth_route(path):
    if path in AUTH_PATHS:
        return path, None
    match = re.fullmatch(r'/users/(\d+)/(profile|inventory)/?', path)
    if match:
        return '/users/__LOCAL_USER_ID__/'+match[2], int(match[1])
    return None, None


def bind_user_metadata(text, user):
    values={'userid':str(user['id']), 'name':user['name'], 'displayname':user['display_name'],
            'created':datetime.fromtimestamp(user['created'],timezone.utc).isoformat(),
            'isunder13':'false','ispremiumuser':'false','hasverifiedbadge':'false','membership':''}
    meta='<meta name="user-data" '+' '.join(f'data-{key}="{html.escape(value,quote=True)}"' for key,value in values.items())+' />'
    if USER_META.search(text):
        return USER_META.sub(lambda _:meta,text)
    return re.sub(r'(<head[^>]*>)',lambda m:m[1]+meta,text,count=1,flags=re.I)


def bind_document(text, user, target, csrf):
    text=bind_user_metadata(text,user)
    title=(target['display_name']+' - Roblox') if target else 'Roblox'
    replacements={'__LOCAL_TARGET_USER_ID__':str(target['id'] if target else user['id']),
                  '__LOCAL_USER_ID__':str(user['id']), '__LOCAL_USERNAME__':html.escape(user['name'],quote=True),
                  '__LOCAL_DISPLAY_NAME__':html.escape(user['display_name'],quote=True),
                  '__LOCAL_CREATED__':datetime.fromtimestamp(user['created'],timezone.utc).isoformat(),
                  '__LOCAL_DOCUMENT_TITLE__':html.escape(title,quote=True),
                  '__LOCAL_CSRF_TOKEN__':csrf}
    for marker,value in replacements.items():
        text=text.replace(marker,value)
    # Preserve the original CSRF reader; bind only its local per-session value.
    text=re.sub(r'(<meta\b(?=[^>]*\bname=["\']csrf-token["\'])[^>]*\bdata-token=)["\'][^"\']*["\']',
                lambda m:m[1]+'"'+html.escape(csrf,quote=True)+'"',text,flags=re.I)
    return text
