"""Capture public browser-delivered resources; never use a Roblox login cookie."""
import argparse
import concurrent.futures
import hashlib
import gzip
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ALLOWED = ('roblox.com', 'rbxcdn.com')


def allowed(url):
    p = urllib.parse.urlsplit(url)
    return p.scheme == 'https' and not p.username and not p.password and any(
        p.hostname == h or (p.hostname or '').endswith('.' + h) for h in ALLOWED)


class Dependencies(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = set()

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag in ('script', 'img', 'source', 'video', 'audio') and d.get('src'):
            self.urls.add(d['src'])
        if tag == 'link' and d.get('href') and any(
            x in d.get('rel', '') for x in ('stylesheet', 'icon', 'preload')):
            self.urls.add(d['href'])


def dependencies(body, mime, base):
    if body.startswith(b'\x1f\x8b'):
        body = gzip.decompress(body)
    if body.startswith(b'#EXTM3U'):
        lines = body.decode().splitlines()
        refs = {line.strip() for line in lines if line.strip() and not line.startswith('#')}
        refs |= set(re.findall(r'URI="([^"]+)"', body.decode()))
        variables = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(base).query))
        resolved = {re.sub(r'\{\$([A-Za-z0-9_-]+)\}', lambda m: variables.get(m[1], m[0]), r) for r in refs}
        return {u for r in resolved if '{$' not in r and allowed(u := urllib.parse.urljoin(base, r))}
    if not any(x in mime for x in ('javascript', 'text/', 'json')):
        return set()
    s = body.decode('utf-8', errors='replace').replace('\\/', '/')
    refs = set()
    if 'assetdelivery.roblox.com' in base and 'json' in mime:
        try:
            def walk(x):
                if isinstance(x, dict):
                    for k, v in x.items():
                        if k == 'location' and isinstance(v, str) and allowed(v):
                            refs.add(v)
                        else:
                            walk(v)
                elif isinstance(x, list):
                    for y in x:
                        walk(y)
            walk(json.loads(s))
        except ValueError:
            pass
    if 'html' in mime:
        p = Dependencies()
        p.feed(s)
        refs |= p.urls
    if 'css' in mime or 'html' in mime:
        refs |= set(re.findall(r'url\(\s*[\"\']?([^\s\)\"\']+)', s))
    # Exact, complete CDN resource literals only. Do not invent webpack hashes.
    for url in re.findall(r'(?:https?:)?//[a-zA-Z0-9.-]+\.rbxcdn\.com/[^\s\"\'<>`\\(){}]+', s):
        if re.search(r'\.(?:js|css|png|jpg|jpeg|webp|svg|woff2?|ttf|gif|ico)(?:[?#]|$)', url):
            refs.add(url)
    return {u for r in refs if allowed(u := urllib.parse.urljoin(base, r))}


def fetch(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0', 'Accept-Encoding': 'identity'})
    started = time.time()
    try:
        with urllib.request.urlopen(req, timeout=35) as r:
            body = r.read(30 * 1024 * 1024 + 1)
            if len(body) > 30 * 1024 * 1024:
                raise ValueError('Resource exceeds capture limit; not saved or silently truncated')
            sha = hashlib.sha256(body).hexdigest()
            path = ROOT / 'capture' / 'objects' / sha
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
            entry = {'url': url, 'final_url': r.url, 'status': r.status,
                     'content_type': r.headers.get('Content-Type', 'application/octet-stream'),
                     'sha256': sha, 'size': len(body), 'captured_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                     'headers': {k: r.headers[k] for k in ('ETag', 'Last-Modified', 'Date', 'Content-Encoding') if k in r.headers}}
            return entry, dependencies(body, entry['content_type'], r.url)
    except Exception as e:
        return {'url': url, 'error': str(e), 'elapsed': round(time.time() - started, 2)}, set()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('urls', nargs='*', default=['https://www.roblox.com/login', 'https://www.roblox.com/'])
    ap.add_argument('--max-resources', type=int, default=1200)
    args = ap.parse_args()
    path = ROOT / 'capture' / 'manifest.json'
    manifest = json.loads(path.read_text()) if path.exists() else {'resources': {}, 'failures': {}, 'documents': {}}
    pending = set(args.urls)
    seen = set()
    for u in args.urls:
        if not allowed(u):
            raise SystemExit('Only public HTTPS Roblox/CDN resources are accepted')
    while pending and len(seen) < args.max_resources:
        batch = sorted(pending - seen)[:args.max_resources - len(seen)]
        pending.clear()
        if not batch:
            break
        seen.update(batch)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futures = {}
            for url in batch:
                if url in manifest['resources']:
                    e = manifest['resources'][url]
                    pending |= dependencies((ROOT/'capture'/'objects'/e['sha256']).read_bytes(), e['content_type'], e['final_url'])
                else:
                    futures[pool.submit(fetch, url)] = url
            for future in concurrent.futures.as_completed(futures):
                e, refs = future.result()
                url = e['url']
                if 'error' in e:
                    manifest['failures'][url] = e
                else:
                    manifest['resources'][url] = e
                    manifest['failures'].pop(url, None)
                    if 'text/html' in e['content_type']:
                        manifest['documents'][urllib.parse.urlsplit(url).path or '/'] = url
                    pending |= refs
                if len(manifest['resources']) % 25 == 0:
                    print('captured', len(manifest['resources']), 'failed', len(manifest['failures']), flush=True)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix('.tmp')
        temporary.write_text(json.dumps(manifest, indent=2))
        temporary.replace(path)
        print('wave complete:', len(manifest['resources']), 'resources;', len(pending - seen), 'new references', flush=True)
    print(json.dumps({'resources': len(manifest['resources']), 'failures': len(manifest['failures']),
                      'bytes': sum(x['size'] for x in manifest['resources'].values()), 'documents': manifest['documents']}, indent=2))


if __name__ == '__main__':
    main()
