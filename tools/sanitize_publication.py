"""Create publishable data-only derivatives; never reconstruct client UI."""
import gzip
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit,urlunsplit,parse_qsl,urlencode

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
SECRET_QUERY=re.compile(r'token|signature|policy|hmac|key-pair|credential|ticket',re.I)

def clean_url(value):
    try:
        u=urlsplit(value)
        if u.scheme not in ('http','https'):return value
        return urlunsplit((u.scheme,u.netloc,u.path,urlencode([(k,v) for k,v in parse_qsl(u.query,keep_blank_values=True) if not SECRET_QUERY.search(k)]),u.fragment))
    except ValueError:return value

def clean_json(value):
    if isinstance(value,dict):
        return {k: ([] if k=='creatorFilters' else 0 if k.lower() in ('robloxuserid','userid') else '' if k.lower() in ('robloxusername','username') else clean_json(v)) for k,v in value.items()}
    if isinstance(value,list):return [clean_json(x) for x in value]
    if isinstance(value,str):return clean_url(value)
    return value

def clean_metadata(value):
    if isinstance(value,dict):
        return {clean_url(k):clean_metadata(v) for k,v in value.items() if k.lower() not in ('set-cookie','cookie','authorization','x-csrf-token')}
    if isinstance(value,list):return [clean_metadata(x) for x in value]
    if isinstance(value,str):return re.sub(r'https?://[^\s"<>]+',lambda m:clean_url(m[0]),value)
    return value

def clean_html(text):
    from server import independent_bootstrap
    text=independent_bootstrap(text)
    text=re.sub(r'(<meta\b(?=[^>]*\bname=["\']csrf-token["\'])[^>]*\bdata-token=)["\'][^"\']*["\']',lambda m:m[1]+'""',text,flags=re.I)
    text=re.sub(r'(\bnonce=)["\'][^"\']*["\']',lambda m:m[1]+'""',text,flags=re.I)
    text=re.sub(r'https?://[^\s"\'<>]*@[^\s"\'<>]*sentry[^\s"\'<>]*','',text,flags=re.I)
    return text

def run():
    manifest_path=ROOT/'capture/manifest.json'
    manifest=json.loads(manifest_path.read_text())
    auth_path=ROOT/'capture/authenticated/manifest.json'
    auth=json.loads(auth_path.read_text())
    report_path=ROOT/'evidence/publication-sanitation.json'
    changed=json.loads(report_path.read_text()).get('replaced_objects',{}) if report_path.exists() else {}
    def replace(entry,mime):
        if 'html' not in mime and 'json' not in mime:return
        old=entry['sha256'];body=(ROOT/'capture/objects'/old).read_bytes()
        decoded=gzip.decompress(body) if body.startswith(b'\x1f\x8b') else body
        if 'html' in mime:updated=clean_html(decoded.decode()).encode()
        elif 'json' in mime:updated=json.dumps(clean_json(json.loads(decoded)),separators=(',',':')).encode()
        else:return
        if updated==decoded:return
        new=hashlib.sha256(updated).hexdigest()
        (ROOT/'capture/objects'/new).write_bytes(updated)
        entry['original_sha256']=entry.get('original_sha256',old)
        entry['sha256']=new
        if 'size' in entry:entry['size']=len(updated)
        entry['publication_transform']='remove captured security values and production account data; preserve original components'
        changed[old]=new
    for e in manifest['resources'].values():replace(e,e.get('content_type',''))
    for e in auth['documents'].values():replace(e,'text/html')
    manifest['resources']={clean_url(u):{**e,**({'final_url':clean_url(e['final_url'])} if 'final_url' in e else {})} for u,e in manifest['resources'].items()}
    manifest['documents']={k:clean_url(v) for k,v in manifest['documents'].items()}
    manifest=clean_metadata(manifest)
    manifest_path.write_text(json.dumps(manifest,indent=2))
    auth_path.write_text(json.dumps(auth,indent=2))
    report={'scope':'publication sanitation only; no UI reconstruction','replaced_objects':changed}
    (ROOT/'evidence/publication-sanitation.json').write_text(json.dumps(report,indent=2))
    print(json.dumps({'sanitized_objects':len(changed)}))

if __name__=='__main__':run()
