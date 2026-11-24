#!/usr/bin/env python3
"""Reproducible vulnerability triage for the Echo take-home.

Inputs (all regenerated automatically when missing; cached under scans/):
  scans/trivy.json       Trivy 0.76.2 JSON of nginx:1.25-bookworm
  scans/grype.json       Grype v0.122.1 JSON of nginx:1.25-bookworm
  scans/tmp/facts_main   ldd closure + dpkg source map from the baseline image
  scans/tmp/facts_slim   apt candidate versions inside debian:bookworm-slim
  scans/tmp/adv.html     nginx.org security advisories page
Outputs:
  docs/triage.csv                 one row per (package, CVE) finding
  docs/triage-nginx-upstream.csv  nginx.org advisories that affect 1.25.5
                                  (neither scanner sees these)

Usage: python scripts/triage.py [--refresh]
Needs: docker (for refresh only), python 3.9+. No third-party packages.
Windows/Git Bash: MSYS_NO_PATHCONV is set internally for docker calls.
"""
import csv, html, json, os, re, subprocess, sys, urllib.request
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCANS, TMP, DOCS = ROOT / "scans", ROOT / "scans" / "tmp", ROOT / "docs"
BASE = "nginx:1.25-bookworm"
SLIM = "debian:bookworm-slim"
TRIVY_IMG, GRYPE_IMG = "aquasec/trivy:0.76.2", "anchore/grype:v0.122.1"
ENV = dict(os.environ, MSYS_NO_PATHCONV="1")


def sh(args):
    return subprocess.run(args, env=ENV, check=True, capture_output=True, text=True,
                          encoding="utf-8").stdout


# ---------------------------------------------------------------- data gathering
MAIN_SCRIPT = r"""
echo "## MAIN"; for l in $(ldd /usr/sbin/nginx | grep -o "=> /[^ ]*" | cut -c4-); do { dpkg -S $(readlink -f $l) || dpkg -S $l; } 2>/dev/null; done | cut -d: -f1 | sort -u
for m in /usr/lib/nginx/modules/*[a-z].so; do case $m in *debug*) continue;; esac
 echo "## MOD $(basename $m)"; for l in $(ldd $m | grep -o "=> /[^ ]*" | cut -c4-); do { dpkg -S $(readlink -f $l) || dpkg -S $l; } 2>/dev/null; done | cut -d: -f1 | sort -u; done
echo "## SRC"; dpkg-query -W -f '${binary:Package}\t${Version}\t${source:Package}\n' | sed 's/:amd64//'
"""


def ensure_inputs(refresh):
    TMP.mkdir(parents=True, exist_ok=True)
    sock = ["-v", "/var/run/docker.sock:/var/run/docker.sock"]
    if refresh or not (SCANS / "trivy.json").exists():
        subprocess.run(["docker", "run", "--rm", *sock, "-v", "trivy-cache:/root/.cache",
                        "-v", f"{SCANS}:/out", TRIVY_IMG, "image", "-q", "--skip-db-update",
                        "--format", "json", "-o", "/out/trivy.json", BASE], env=ENV, check=True)
    if refresh or not (SCANS / "grype.json").exists():
        out = sh(["docker", "run", "--rm", *sock, "-v", "grype-db:/.cache/grype",
                  "-e", "GRYPE_DB_AUTO_UPDATE=false", GRYPE_IMG, BASE, "-o", "json"])
        (SCANS / "grype.json").write_text(out, encoding="utf-8")
    f = TMP / "facts_main.txt"
    if refresh or not f.exists():
        f.write_text(sh(["docker", "run", "--rm", "--entrypoint", "sh", BASE, "-c", MAIN_SCRIPT]),
                     encoding="utf-8")
    f = TMP / "facts_slim.txt"
    if refresh or not f.exists():
        pk = sorted({v["PkgName"] for v in trivy()} | {m["artifact"]["name"] for m in grype()})
        script = ('apt-get update -qq >/dev/null 2>&1; echo "## DATE $(date -u +%F)"; '
                  'for p in ' + " ".join(pk) + '; do '
                  'c=$(apt-cache policy $p 2>/dev/null | sed -n "s/^  Candidate: //p"); '
                  'echo "CAND|$p|${c:-NONE}"; done; '
                  'dpkg-query -W -f "SLIM|\\${binary:Package}\\n" | sed "s/:amd64//"')
        f.write_text(sh(["docker", "run", "--rm", SLIM, "sh", "-c", script]), encoding="utf-8")
    f = TMP / "adv.html"
    if refresh or not f.exists():
        req = urllib.request.Request("https://nginx.org/en/security_advisories.html",
                                     headers={"User-Agent": "triage-script"})
        f.write_bytes(urllib.request.urlopen(req, timeout=60).read())


_cache = {}


def trivy():
    if "t" not in _cache:
        d = json.loads((SCANS / "trivy.json").read_text(encoding="utf-8"))
        _cache["t"] = [v for r in d["Results"] for v in r.get("Vulnerabilities", [])]
    return _cache["t"]


def grype():
    if "g" not in _cache:
        _cache["g"] = json.loads((SCANS / "grype.json").read_text(encoding="utf-8"))["matches"]
    return _cache["g"]


# ---------------------------------------------------------------- dpkg version compare
def _order(c):
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _cmp_part(a, b):
    while a or b:
        da, db = re.match(r"\D*", a).group(), re.match(r"\D*", b).group()
        a, b = a[len(da):], b[len(db):]
        for i in range(max(len(da), len(db))):
            ca = _order(da[i]) if i < len(da) else 0
            cb = _order(db[i]) if i < len(db) else 0
            if ca != cb:
                return -1 if ca < cb else 1
        na, nb = re.match(r"\d*", a).group(), re.match(r"\d*", b).group()
        a, b = a[len(na):], b[len(nb):]
        ia, ib = int(na or 0), int(nb or 0)
        if ia != ib:
            return -1 if ia < ib else 1
    return 0


def _split(v):
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e)
    if "-" in v:
        up, _, rev = v.rpartition("-")
    else:
        up, rev = v, "0"
    return epoch, up, rev


def dpkg_cmp(a, b):
    ea, ua, ra = _split(a)
    eb, ub, rb = _split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _cmp_part(ua, ub) or _cmp_part(ra, rb)


# ---------------------------------------------------------------- facts
def load_facts():
    main, mods, src, sect = set(), defaultdict(set), {}, None
    for line in (TMP / "facts_main.txt").read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            sect = line[3:]
            continue
        if not line.strip():
            continue
        if sect == "MAIN":
            main.add(line.strip())
        elif sect.startswith("MOD "):
            mods[sect[4:]].add(line.strip())
        elif sect == "SRC":
            p, v, s = line.split("\t")
            src[p] = s
    cand, slim, date = {}, set(), ""
    for line in (TMP / "facts_slim.txt").read_text(encoding="utf-8").splitlines():
        if line.startswith("## DATE"):
            date = line.split()[-1]
        elif line.startswith("CAND|"):
            _, p, c = line.split("|")
            cand[p] = None if c == "NONE" else c
        elif line.startswith("SLIM|"):
            slim.add(line.split("|")[1])
    return main, mods, src, cand, slim, date


# ---------------------------------------------------------------- triage
SEV = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW",
       "negligible": "NEGLIGIBLE", "unknown": "UNKNOWN", "": ""}
# Heuristic: OpenSSL APIs/arches that a plain nginx TLS server does not use
SSL_UNUSED = re.compile(r"CMS|PKCS|CMP\b|S/MIME|TimeStamp|DTLS|PowerPC|32-bit|SM2|X9\.42|DSA|"
                        r"GF\(2|EVP_|PEM_|RFC 3211|OCB|GCM-SIV", re.I)
TIER_A_PKGS = {"libc6"}
TIER_B_WHY = {
    "libssl3": "TLS only (listen ... ssl / quic); default config is plain HTTP on :80",
    "libpcre2-8-0": "regex locations/rewrite/map; patterns come from admin config, not from the client",
    "zlib1g": "gzip/gunzip/gzip_static directives; off in default config",
    "libcrypt1": "auth_basic htpasswd crypt(); off in default config",
}


def build_rows():
    main, mods, src, cand, slim, date = load_facts()
    mod_only = set().union(*mods.values()) - main
    linked_src = {src[p] for p in main if p in src}
    T = {(v["PkgName"], v["VulnerabilityID"]): v for v in trivy()}
    G = {(m["artifact"]["name"], m["vulnerability"]["id"]): m for m in grype()}
    rows = []
    for (pkg, cve) in sorted(set(T) | set(G)):
        t, g = T.get((pkg, cve)), G.get((pkg, cve))
        inst = (t or {}).get("InstalledVersion") or g["artifact"]["version"]
        sev_t = (t or {}).get("Severity", "")
        gv = g["vulnerability"] if g else {}
        sev_g = SEV.get(gv["severity"].lower(), gv["severity"].upper()) if g else ""
        kev = ("yes" if gv.get("knownExploited") else "no") if g else ""
        epss = f'{gv["epss"][0]["epss"]:.5f}' if gv.get("epss") else ""
        tf = (t or {}).get("FixedVersion", "") or ""
        gf = ";".join(gv.get("fix", {}).get("versions", [])) if g else ""
        fixed = tf or gf
        note = ""
        if tf and gf and tf != gf:
            note = f" [fixed_version differs: trivy={tf} grype={gf}; trivy shown]"
        status = (t or {}).get("Status") or gv.get("fix", {}).get("state", "")
        c = cand.get(pkg)
        if not fixed:
            cleared = "no-fix"
        elif c and dpkg_cmp(c, fixed.split(";")[0]) >= 0:
            cleared = "yes"
        else:
            cleared = "fix-newer-than-bookworm"
        title = (t or {}).get("Title") or gv.get("description", "")
        sibling = pkg not in main and src.get(pkg) in linked_src
        why = []
        # ---- tier
        if pkg in TIER_A_PKGS:
            tier = "A"
            why.append("linked into /usr/sbin/nginx and executed on every default-config request "
                       "(libc); CVE-level reachability still depends on the API called")
        elif pkg in TIER_B_WHY:
            tier = "B"
            why.append(TIER_B_WHY[pkg])
        elif sibling:
            tier = "N"
            why.append(f"binary of source '{src[pkg]}' (same source as a linked lib); not itself linked by nginx")
        elif pkg in mod_only:
            tier = "C"
            why.append("only used by a dynamic nginx module (geoip/image_filter/njs/xslt); "
                       "needs load_module, absent from default config")
        elif pkg == "nginx":
            tier = "N"
            why.append("matched by name against Debian's own nginx source package (1.22.x); "
                       "our nginx is the nginx.org build")
        else:
            tier = "N"
            why.append("not linked by nginx; image userland only (shell, apt, tools)")
        if pkg in ("libssl3", "openssl") and SSL_UNUSED.search(title):
            why.append("heuristic: API/arch not used by a plain nginx TLS server")
        if "quic" in title.lower():
            why.append("QUIC only with 'listen ... quic'")
        # ---- action
        if pkg in main:
            if cleared == "yes":
                action = "bump"
                why.append(f"fixed in bookworm {fixed}; pin >= that (current bookworm {c})")
            elif fixed:
                action = "accept"
                why.append(f"fix {fixed} not in bookworm yet (current {c})")
            else:
                action = "accept"
                why.append(f"no fix in bookworm (status: {status})")
        elif sibling:
            if cleared == "yes":
                action = "bump"
                why.append(f"cleared together with the linked sibling by the same pin (>= {fixed}; current {c})")
            else:
                action = "accept"
                why.append(f"no fix in bookworm (status: {status})")
        elif pkg == "nginx":
            action = "accept"
            why.append("likely not applicable to the nginx.org build; verify before claiming")
        elif pkg in mod_only and pkg not in slim:
            action = "remove"
            why.append("absent from bookworm-slim; disappears unless module packages are shipped "
                       "(parity vs surface decision pending; removal does not count as a fix)")
        elif pkg not in slim:
            action = "remove"
            why.append("not in bookworm-slim base; simply not installed in the new image "
                       "(does not count as a fix)")
        else:
            action = "accept"
            why.append(("cleared automatically by building on a fresh bookworm-slim" if cleared == "yes"
                        else f"no fix in bookworm (status: {status})") + "; not nginx runtime")
        rows.append({
            "package": pkg, "installed_version": inst, "cve": cve,
            "severity_trivy": sev_t, "severity_grype": sev_g, "kev": kev, "epss": epss,
            "fixed_version": fixed, "linked_by_nginx": "yes" if pkg in main else "no",
            "reachability_tier": tier, "proposed_action": action,
            "reason": "; ".join(why) + note,
            "scanners": "+".join(x for x, y in (("trivy", t), ("grype", g)) if y),
            "status": status, "in_slim_base": "yes" if pkg in slim else "no",
            "bookworm_current": c or "", "cleared_by_fresh_bookworm": cleared,
        })
    return rows, date


# ---------------------------------------------------------------- nginx.org advisories
# Curated; each trigger verified by reading nginx.org/en/CHANGES and the Debian tracker text.
# tier: B = common production directive/protocol, C = non-default module or niche directive.
TRIGGER = {
    "CVE-2026-132779": ("ssl_early_data", "C"),
    "CVE-2026-123634": ("resolver + subrequests", "C"),
    "CVE-2026-123007": ("HTTP/2 listener (http2 on / listen ... http2)", "B"),
    "CVE-2026-121810": ("HTTP/3 (listen ... quic)", "C"),
    "CVE-2026-123633": ("HTTP/2 listener, worker_connections exhausted", "B"),
    "CVE-2026-118899": ("listen ... ssl with TLS 1.3, reading request body", "B"),
    "CVE-2026-113425": ("mail proxy module", "C"),
    "CVE-2026-125283": ("try_files + alias + map variable", "C"),
    "CVE-2026-120967": ("stream module, ssl_verify_client + SNI", "C"),
    "CVE-2026-123640": ("stream ssl_preread", "C"),
    "CVE-2026-15176": ("alias + rewrite", "B"),
    "CVE-2026-95101": ("HTTP/3", "C"),
    "CVE-2026-97629": ("TLS session ticket key rotation", "C"),
    "CVE-2026-97205": ("aio + SSI include virtual", "C"),
    "CVE-2026-42533": ("map with regex captures used in a string", "B"),
    "CVE-2026-60005": ("slice module / cache background update", "C"),
    "CVE-2026-56434": ("ssi module", "C"),
    "CVE-2026-42055": ("proxy to HTTP/2 or gRPC backend, ignore_invalid_headers off", "C"),
    "CVE-2026-48142": ("charset_map", "C"),
    "CVE-2026-9256": ("rewrite with overlapping regex captures + redirect or ?args", "B"),
    "CVE-2026-42945": ("rewrite followed by rewrite/if/set using $1 with '?' in replacement", "B"),
    "CVE-2026-42946": ("scgi_pass / uwsgi_pass", "C"),
    "CVE-2026-42934": ("charset_map", "C"),
    "CVE-2026-40460": ("HTTP/3", "C"),
    "CVE-2026-40701": ("ssl_ocsp + resolver", "C"),
    "CVE-2026-27654": ("dav module COPY/MOVE + alias", "C"),
    "CVE-2026-27784": ("mp4 module (32-bit only)", "C"),
    "CVE-2026-32647": ("mp4 module", "C"),
    "CVE-2026-27651": ("mail CRAM-MD5/APOP", "C"),
    "CVE-2026-28753": ("mail auth_http/XCLIENT", "C"),
    "CVE-2026-28755": ("stream ssl_ocsp", "C"),
    "CVE-2026-1642": ("proxy_pass https:// (SSL upstream)", "B"),
    "CVE-2025-53859": ("mail smtp", "C"),
    "CVE-2025-23419": ("TLS 1.3 + SNI + client certs", "C"),
    "CVE-2024-7347": ("mp4 module + mp4 directive", "C"),
    "CVE-2024-32760": ("HTTP/3", "C"),
    "CVE-2024-31079": ("HTTP/3", "C"),
    "CVE-2024-35200": ("HTTP/3", "C"),
    "CVE-2024-34161": ("HTTP/3", "C"),
}
# Fix commits taken from the Debian Security Tracker notes and GitHub; applicability
# checked with `patch --dry-run` against the nginx-1.25.5 tarball.
FIXES = {
    "CVE-2026-42945": ("524977e7c534 (rel-1.30.1) = mainline 2046b45aa0c6; 1 line",
                       "yes (patch --dry-run, clean)"),
    "CVE-2026-9256": ("3f135ae2eb60 (rel-1.30.2) = mainline ca4f92a27464; 13+/7-, apply after 42945",
                      "yes (applied in sequence, clean)"),
    "CVE-2026-118899": ("1b723277aa55 + d1640655f46c (rel-1.30.7); 1 hunk + HTTP/3 twin",
                        "yes (clean / offset)"),
    "CVE-2026-123007": ("b89c4100bf67 (rel-1.30.7) = mainline e27f5fa84fe6; 3 files",
                        "yes (offsets, fuzz 1)"),
    "CVE-2026-125283": ("b99b6b528b64 (rel-1.30.7) = mainline d1ffe6fa89fe; 1 line",
                        "yes (fuzz 1)"),
    "CVE-2024-7347": ("88955b1044ef + 7362d01658b6 (rel-1.27.1); also nginx.org/download/patch.2024.mp4.txt",
                      "yes (-p1 clean)"),
}


def vtuple(s):
    return tuple(int(x) for x in s.split("."))


def affects(rng, ver=(1, 25, 5)):
    for part in rng.split(","):
        lo, _, hi = part.strip().partition("-")
        if not hi:
            hi = lo
        if vtuple(lo) <= ver <= vtuple(hi):
            return True
    return False


def advisories(scanner_cves):
    s = (TMP / "adv.html").read_text(encoding="utf-8", errors="replace")
    out = []
    for it in re.findall(r"<li><p>(.*?)</li>", s, re.S):
        t = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", it)))
        m = re.search(r"(.*?) Severity: (\w+).*?(CVE-\d+-\d+).*?Not vulnerable: (.*?) Vulnerable: (.*)$", t)
        if not m:
            continue
        title, sev, cve, nv, vul = (x.strip() for x in m.groups())
        vul = re.sub(r"\s*(The patch|pgp|\[).*", "", vul).strip()
        try:
            if not affects(vul):
                continue
        except ValueError:      # old entries such as "nginx/Windows 0.x"
            continue
        trig, tier = TRIGGER.get(cve, ("UNCLASSIFIED", "?"))
        fx = FIXES.get(cve, ("", ""))
        out.append({"cve": cve, "title": title, "nginx_severity": sev, "vulnerable": vul,
                    "not_vulnerable": nv, "trigger": trig, "tier": tier,
                    "fix_commits": fx[0], "applies_to_1.25.5": fx[1],
                    "flagged_by_trivy_or_grype": "yes" if cve in scanner_cves else "no",
                    "default_config_reachable": "no"})
    return out


def main():
    ensure_inputs("--refresh" in sys.argv)
    rows, date = build_rows()
    DOCS.mkdir(exist_ok=True)
    with open(DOCS / "triage.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, list(rows[0].keys()), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    adv = advisories({r["cve"] for r in rows})
    with open(DOCS / "triage-nginx-upstream.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, list(adv[0].keys()), lineterminator="\n")
        w.writeheader()
        w.writerows(adv)
    print(f"apt candidates fetched {date}; rows={len(rows)}; unique CVEs={len({r['cve'] for r in rows})}")
    print("scanners:", dict(Counter(r["scanners"] for r in rows)))
    print("tier:", dict(Counter(r["reachability_tier"] for r in rows)))
    print("action:", dict(Counter(r["proposed_action"] for r in rows)))
    print("nginx.org advisories affecting 1.25.5:", len(adv), "| flagged by scanners:",
          sum(a["flagged_by_trivy_or_grype"] == "yes" for a in adv),
          "| unclassified:", [a["cve"] for a in adv if a["tier"] == "?"])


if __name__ == "__main__":
    main()
