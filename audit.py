"""Verify capture provenance and extract exact auth-code evidence."""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def audit():
    manifest = json.loads((ROOT/'capture'/'manifest.json').read_text())
    invalid, empty, documents = [], [], []
    for url, entry in manifest['resources'].items():
        path = ROOT/'capture'/'objects'/entry['sha256']
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != entry['sha256']:
            invalid.append(url)
        if entry['size'] == 0:
            empty.append(url)
    for path, url in manifest['documents'].items():
        e = manifest['resources'][url]
        from urllib.parse import urlsplit
        final_path = urlsplit(e['final_url']).path
        documents.append({'route': path, 'source': url, 'final_url': e['final_url'], 'sha256': e['sha256'],
                          'kind': 'redirect' if path.lower() != final_path.lower() else 'document'})
    evidence = ROOT/'evidence'
    evidence.mkdir(exist_ok=True)
    for url, entry in manifest['resources'].items():
        if url.endswith('-CoreUtilities.js'):
            text = (ROOT/'capture'/'objects'/entry['sha256']).read_text()
            anchor = text.index("document.querySelector('meta[name=\"user-data\"]')")
            start = text.rfind('nf=function()', 0, anchor)
            end = text.index(';function nh', anchor)
            code = 'var ' + text[start:end] + ';'
            (evidence/'original-auth-check.js').write_text(code+'\n')
            (evidence/'original-auth-check.json').write_text(json.dumps({
                'source_url': url, 'source_sha256': entry['sha256'], 'start_offset': start,
                'end_offset': end, 'functions': {'nf': 'read user-data dataset', 'nd': 'isAuthenticated', 'np': 'authenticatedUser'},
                'altered': False}, indent=2))
        if url.endswith('-GameLaunch.js'):
            text = (ROOT/'capture'/'objects'/entry['sha256']).read_text()
            parts = {}
            for name, start_marker, end_marker in [
                ('guestRestriction', 'var sz={restrictGuests:', ',sV=window.CoreUtilities'),
                ('loginRedirect', 'rH=function()', ',rG=function('),
                ('authenticatedLaunchGuard', 'rG=function(', ',rz=function('),
            ]:
                start = text.index(start_marker)
                end = text.index(end_marker, start)
                code = text[start:end]
                if not code.startswith('var '):
                    code = 'var ' + code
                filename = 'original-play-' + name + '.js'
                (evidence/filename).write_text(code+';\n')
                parts[name] = {'file': filename, 'start_offset': start, 'end_offset': end}
            (evidence/'original-play-branches.json').write_text(json.dumps({
                'source_url': url, 'source_sha256': entry['sha256'], 'altered': False,
                'parts': parts,
                'observed_public_behavior': {
                    'page': 'https://www.roblox.com/games/15101393044/Dress-To-Impress',
                    'date': '2026-10-26', 'authenticated': False,
                    'control': 'data-testid=play-button',
                    'result': 'Original Sign in or create a free account dialog, with Sign Up and Log In choices',
                    'bundle_url_verified_in_rendered_document': True,
                    'production_game_data_imported': False,
                },
                'scope': 'Original code preservation and branch tests. Local game detail routes and game-session services are not implemented.',
            }, indent=2))
    report = {'capture_resource_count': len(manifest['resources']),
              'nonempty_resources': len(manifest['resources'])-len(empty),
              'bytes': sum(e['size'] for e in manifest['resources'].values()),
              'hash_failures': invalid, 'empty_responses': empty,
              'download_failures': manifest['failures'], 'documents': documents,
              'custom_html_pages': list(str(x.relative_to(ROOT)) for x in ROOT.rglob('*.html')),
              'authenticated_home_captured': False}
    auth_path=ROOT/'capture'/'authenticated'/'manifest.json'
    if auth_path.exists():
        authenticated=json.loads(auth_path.read_text())
        report['authenticated_documents']=authenticated['documents']
        report['authenticated_home_captured']='/home' in authenticated['documents']
        report['captured_account_records_imported']=authenticated['captured_account_records_imported']
        for route,entry in authenticated['documents'].items():
            path=ROOT/'capture'/'objects'/entry['sha256']
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=entry['sha256']:
                invalid.append('authenticated-template:'+route)
    (evidence/'capture-audit.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    return report


if __name__ == '__main__':
    raise SystemExit(bool(audit()['hash_failures']))
