import gzip
import json
import re
import unittest
from pathlib import Path
from tools.sanitize_publication import clean_html,clean_json,clean_url,clean_metadata
from capture_store import read_object

ROOT=Path(__file__).resolve().parents[1]


class PublicationTests(unittest.TestCase):
    def test_html_removes_security_values_preserving_original_mounts(self):
        original='<html><head><meta name="csrf-token" data-token="private-captured-value"><script nonce="captured-nonce">window.original=true</script></head><body><div id="original-mount"></div></body></html>'
        result=clean_html(original)
        self.assertNotIn('private-captured-value',result)
        self.assertNotIn('captured-nonce',result)
        self.assertIn('<div id="original-mount"></div>',result)
        self.assertIn('window.original=true',result)

    def test_catalog_account_fields_are_removed_but_categories_survive(self):
        original={'categories':[{'name':'Accessories','id':3}], 'robloxUserId':1,'robloxUserName':'CapturedAccount','creatorFilters':[{'userId':1,'name':'CapturedAccount'}]}
        cleaned=clean_json(original)
        self.assertEqual(cleaned['categories'],original['categories'])
        self.assertEqual(cleaned['creatorFilters'],[])
        self.assertNotIn('CapturedAccount',json.dumps(cleaned))

    def test_signed_media_queries_are_unnecessary_for_offline_paths(self):
        cleaned=clean_url('https://cdn.example/video.webm?Signature=private&Policy=private&__token__=private&v=2')
        self.assertEqual(cleaned,'https://cdn.example/video.webm?v=2')
        self.assertEqual(clean_metadata({'url':'https://cdn.example/video.webm?Signature=private','headers':{'Set-Cookie':'private'}}),{'url':'https://cdn.example/video.webm','headers':{}})

    def test_split_capture_reconstructs_exact_original_media(self):
        import hashlib
        index=json.loads((ROOT/'capture/object-chunks.json').read_text())
        for digest,parts in index.items():
            body=read_object(ROOT,digest)
            self.assertEqual(hashlib.sha256(body).hexdigest(),digest)
            self.assertEqual(len(body),sum(p['size'] for p in parts))

    def test_active_html_contains_no_captured_csrf_tokens_or_sentry_dsn(self):
        manifest=json.loads((ROOT/'capture/manifest.json').read_text())
        auth=json.loads((ROOT/'capture/authenticated/manifest.json').read_text())
        entries=[e for e in manifest['resources'].values() if 'html' in e['content_type']]+list(auth['documents'].values())
        for entry in entries:
            data=(ROOT/'capture/objects'/entry['sha256']).read_bytes()
            if data.startswith(b'\x1f\x8b'):data=gzip.decompress(data)
            self.assertNotRegex(data,rb'<meta\b[^>]*name=["\']csrf-token["\'][^>]*data-token=["\'][^"\']+["\']')
            self.assertNotRegex(data,rb'https?://[^\s"\'<>]*@[^\s"\'<>]*sentry')


if __name__=='__main__':unittest.main()
