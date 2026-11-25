"""Compare scans of the fixed image without and with vex.json (run from scans/rescan)."""
import json

def trivy(p):
    d = json.load(open(p, encoding='utf-8'))
    return {(v['VulnerabilityID'], v['PkgName']) for r in d['Results'] for v in r.get('Vulnerabilities') or []}

def grype(p):
    d = json.load(open(p, encoding='utf-8'))
    return {(m['vulnerability']['id'], m['artifact']['name']) for m in d['matches']}, \
           {(m['vulnerability']['id'], m['artifact']['name']) for m in d.get('ignoredMatches') or []}

a, b = trivy('fixed-trivy.json'), trivy('vex-trivy.json')
print(f'Trivy: {len(a)} rows without VEX, {len(b)} with VEX. Removed: {sorted(a - b)}. Added: {sorted(b - a)}.')
a, _ = grype('fixed-grype.json'); b, ign = grype('vex-grype.json')
print(f'Grype: {len(a)} rows without VEX, {len(b)} with VEX. Removed: {sorted(a - b)} (ignoredMatches: {sorted(ign)}). Added: {sorted(b - a)}.')
