import json,collections
def pk(p):
    d=json.load(open(p,encoding='utf-8')); return {(v['VulnerabilityID'],v['PkgName']) for r in d['Results'] for v in r.get('Vulnerabilities') or []}
ours={l.split()[0].split(':')[0] for l in open('../pkgs-ours.txt') if l.strip()}
b=pk('base-trivy.json'); x=pk('fixed-trivy.json')
c=collections.Counter()
for k in b-x:
    c['bump(libssl3/openssl)' if k[1] in('libssl3','openssl') else 'pkg absent from ours' if k[1] not in ours else 'other (pkg still present)']+=1
print(c)
print(sorted(k for k in b-x if k[1] in ours and k[1] not in('libssl3','openssl'))[:20])
print('nginx rows baseline:',[k for k in b if k[1]=='nginx'],'ours:',[k for k in x if k[1]=='nginx'])
