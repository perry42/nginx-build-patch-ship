import json,sys,collections
def trivy(p):
    d=json.load(open(p,encoding='utf-8')); s=set(); sev={}
    for r in d.get('Results',[]):
        for v in r.get('Vulnerabilities') or []:
            k=(v['VulnerabilityID'],v['PkgName']); s.add(k); sev[k]=v.get('Severity','').upper()
    return s,sev
def grype(p):
    d=json.load(open(p,encoding='utf-8')); s=set(); sev={}
    for m in d['matches']:
        k=(m['vulnerability']['id'],m['artifact']['name']); s.add(k); sev[k]=m['vulnerability']['severity'].upper()
    return s,sev
for name,f in (('trivy',trivy),('grype',grype)):
    b,bs=f(f'base-{name}.json'); x,xs=f(f'fixed-{name}.json')
    print(f'== {name}: baseline {len(b)} (CVE,pkg) pairs, fixed {len(x)}, removed {len(b-x)}, new {len(x-b)}')
    print(' baseline by severity',dict(collections.Counter(bs.values())))
    print(' fixed by severity   ',dict(collections.Counter(xs.values())))
    for k in sorted(x-b): print(' NEW',k,xs[k])
    for cve in ('CVE-2026-31789','CVE-2025-15467','CVE-2024-6119'):
        print(' ',cve,'baseline:',sorted(p for c,p in b if c==cve),'fixed:',sorted(p for c,p in x if c==cve))
    print(' libssl3/openssl rows still in fixed:',sorted((c,p,xs[(c,p)]) for c,p in x if p in('libssl3','openssl')))
    cur=[k for k in b if 'curl' in k[1]]; print(' curl-pkg rows in baseline:',len(cur),'remaining',len([k for k in x if 'curl' in k[1]]))
