"""Read static interface constants from the preserved bundles, without running JS."""
import hashlib
import json
import re


def bundle(root, manifest, name):
    candidates=[(url,e) for url,e in manifest['resources'].items() if url.endswith('-'+name+'.js')]
    if len(candidates)!=1:
        raise ValueError('Expected one captured '+name+' bundle')
    url,entry=candidates[0]
    body=(root/'capture/objects'/entry['sha256']).read_bytes()
    if hashlib.sha256(body).hexdigest()!=entry['sha256']:
        raise ValueError('Client contract source failed integrity check')
    return body.decode(), {'url':url,'sha256':entry['sha256']}


def literal_array(source, marker):
    start=source.index(marker)+len(marker)
    if source[start]!='[':
        raise ValueError('Original array contract changed')
    level=0; quoted=False; escaped=False
    for end in range(start,len(source)):
        char=source[end]
        if quoted:
            if escaped: escaped=False
            elif char=='\\': escaped=True
            elif char=='"': quoted=False
        elif char=='"': quoted=True
        elif char=='[': level+=1
        elif char==']':
            level-=1
            if level==0:
                literal=source[start:end+1]
                # These original constants contain only JSON-compatible values
                # with unquoted object keys. Never evaluate captured code here.
                return json.loads(re.sub(r'(?<=[{,])([A-Za-z_]\w*):',r'"\1":',literal))
    raise ValueError('Unterminated original constant')


class ClientContracts:
    def __init__(self,root,manifest):
        inventory,inv_source=bundle(root,manifest,'Inventory')
        settings,settings_source=bundle(root,manifest,'UserSettings')
        self.inventory_categories=literal_array(inventory,'inventoryCategories:')
        theme_enum=re.search(r'hK=\(\(Fv=\{\}\)(.*?)Fv\)',settings)[1]
        self.account_themes=tuple(re.findall(r'Fv\.\w+="([A-Za-z0-9]+)"',theme_enum))
        self.provenance={'inventory_categories':inv_source,'account_themes':settings_source}
