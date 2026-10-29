"""Read exact captured bytes, including media split for transfer-size limits."""
import hashlib
import json


def read_object(root,digest):
    index_path=root/'capture/object-chunks.json'
    index=json.loads(index_path.read_text()) if index_path.exists() else {}
    parts=index.get(digest)
    if parts is None:
        return (root/'capture/objects'/digest).read_bytes()
    bodies=[]
    for part in parts:
        body=(root/'capture/objects'/part['sha256']).read_bytes()
        if len(body)!=part['size'] or hashlib.sha256(body).hexdigest()!=part['sha256']:
            raise ValueError('Captured media chunk failed integrity check')
        bodies.append(body)
    body=b''.join(bodies)
    if hashlib.sha256(body).hexdigest()!=digest:
        raise ValueError('Reassembled original capture failed integrity check')
    return body
