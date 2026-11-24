# Backport candidates that the scanners LIST (VEX-demonstrable)

Date: 2026-11-24. Data: `docs/triage.csv`. Throwaway evidence in `scans/bp/` (git-ignored): `build.sh`, `poc.c`, `Dockerfile.zlib`, `vex-test.json`, `*.patch`, scan JSON.
Rule: every URL below was opened (tracker pages via WebFetch, commits via curl, NVD via its REST API). Anything else is marked UNVERIFIED.

## Filter result

Packages nginx links: zlib1g, libpcre2-8-0, libc6, libcrypt1 (libssl3 is the bump).
- libpcre2-8-0: every CVE is already fixed in bookworm (10.42-1+deb12u2), so those are bumps, not backports. Excluded.
- libcrypt1: no open CVE rows in triage.csv.
- zlib1g (1:1.2.13.dfsg-1, no bookworm fix): 3 open rows. CVE-2023-45853 is MiniZip (not built, Trivy only, will_not_fix): not backportable, not built. CVE-2026-27171 and CVE-2026-85091 remain.
- libc6 (2.36-9+deb12u7 in baseline): ~30 open rows (affected/fix_deferred, no bookworm fix). Two have small upstream fixes (below).
- Result: 3 usable candidates (C1 zlib, C2 and C3 glibc, where C2 and C3 share ONE glibc rebuild). CVE-2026-85091 is rejected (see end).

## Ranking

### C1. zlib CVE-2026-27171 (RECOMMENDED: cheapest, fully demonstrated)
- Package: zlib1g 1:1.2.13.dfsg-1. Scanners: Trivy MEDIUM, Grype MEDIUM (EPSS 0.00244).
- CVSS: NVD 5.5 (AV:L/AC:L/PR:L/A:H), CNA MITRE 2.9. NVD status Analyzed, published 2026-02-18 (REST API, opened).
- Debian tracker (opened) https://security-tracker.debian.org/tracker/CVE-2026-27171: bookworm "vulnerable", no fixed version, note `<no-dsa> (Minor issue)`; fixed upstream in 1.3.2; introduced in 1.2.12 (so 1.2.13 is affected).
- Upstream fix (opened): https://github.com/madler/zlib/commit/ba829a458576d1ff0f26fc7230c6de816d1f6a77 "Check for negative lengths in crc32_combine functions". Maintainer confirmed it fixes this CVE: https://github.com/madler/zlib/issues/904 (opened).
- Patch size: 2 files, +6/-2 (4 lines of code: `if (len2 < 0) return 0;` in `crc32_combine64` and `crc32_combine_gen64`, plus 2 doc lines in zlib.h).
- Applies cleanly? NO as-is. `patch -p1 --dry-run` against `apt source zlib` 1.2.13.dfsg-1: `crc32.c Hunk #1 FAILED at 1019, Hunk #2 FAILED at 1032; zlib.h Hunk #1 FAILED` (1.2.13 uses K&R function style). The logic hand-ports trivially (insert the same 2 lines after the `{` of each function; I did this with a script in `scans/bp/build.sh`). The shipped patch must be authored as a backport file with a header explaining the port; this is the real "backport" skill.
- Rebuild: `apt-get source zlib`, `apt-get build-dep zlib`, patch, `dpkg-buildpackage -b -uc -us -nc`. MEASURED: 25 s wall time (8 cores). Output zlib1g_1.2.13.dfsg-1_amd64.deb, same version string.
- Test/PoC (MEASURED): `crc32_combine(1,2,(z_off_t)-1)` in `scans/bp/poc.c`. Stock libz: infinite loop, killed by `timeout 5` (rc=124). Patched libz: prints `crc32_combine(1,2,-1)=0`, rc=0. Deterministic, no crash needed.
- Tier: NOT reachable from nginx at all. `nm -D --undefined-only /usr/sbin/nginx` shows only `deflate*`, `inflate*` from libz; no `crc32_combine*`. libz IS loaded on every start (`ldd`), so the component is tier A but the CVE is tier N/C. Say this plainly in the README.
- What this means (interview): "zlib has a function that merges two checksums. If you pass a negative length it loops forever, because it shifts a signed number right and never reaches zero. Upstream added a two-line guard. Debian marks it minor and has not shipped it for bookworm, so I backported the guard into Debian's 1.2.13 source, rebuilt the package, proved the hang is gone with a 10-line C program, and told the scanners via VEX. nginx never calls that function, so this is hygiene, not a live attack path."

### C2. glibc CVE-2026-5450 (scanf %mc one-byte heap overflow)
- libc6 2.36-9+deb12u7 baseline (bookworm now 2.36-9+deb12u14 is also "vulnerable"). Scanners: Trivy MEDIUM, Grype CRITICAL (EPSS 0.00511).
- Tracker (opened) https://security-tracker.debian.org/tracker/CVE-2026-5450: bookworm vulnerable, no fixed version, `<no-dsa> (Minor issue)`; note "%mc is not really usable unless bug 12701 is fixed as well". CVSS: NOT retrieved (UNVERIFIED).
- Fix (opened, as patch): https://sourceware.org/git/?p=glibc.git;a=commit;h=839898777226a3ed88c0859f25ffe712519b4ead; bug https://sourceware.org/bugzilla/show_bug.cgi?id=34008.
- Patch size: code change 3 one-line edits in `stdio-common/vfscanf-internal.c` (`width - 1` becomes `width`), plus a new test and a Makefile hunk.
- Applies? YES for code: `patch -p1 --dry-run` on `apt source glibc` 2.36-9+deb12u14: vfscanf-internal.c hunks 1-3 "succeeded (offset -50/-52 lines)", test file creates; only the `stdio-common/Makefile` test hunk FAILED (drop it, tests are not needed). Note: I tested against the u14 source; baseline u7 source not tested (UNVERIFIED but the file is unchanged upstream-wise).
- Rebuild: glibc is a large build (multi-arch libc6, locales). Estimate 30-90 min with `DEB_BUILD_OPTIONS=nocheck`, more with tests. NOT built (UNVERIFIED estimate). Risk: libc6 is Essential and all-pervasive; a custom libc6 in the runtime image is a large trust jump.
- Test/PoC: `sscanf(buf, "%1040mc", &p)` with a 1040-char input under `MALLOC_CHECK_=3` / valgrind (the upstream test). Not run.
- Tier: component A (every process), CVE N (nginx does not call scanf %mc; I did not check nginx imports for scanf, UNVERIFIED).
- Interview: "glibc under-sized a buffer by one byte when growing it for scanf %mc with a width over 1024. Upstream fix is changing width-1 to width. Nginx never reads input that way, so it is scanner-visible but not an HTTP risk."

### C3. glibc CVE-2026-5928 (ungetwc reads before buffer)
- Scanners: Trivy MEDIUM, Grype HIGH (EPSS 0.00376). Tracker (opened) https://security-tracker.debian.org/tracker/CVE-2026-5928: bookworm vulnerable, `<no-dsa> (Minor issue)`, fixed forky 2.43-7 and trixie 2.41-12+deb13u5. Affects charsets whose single-byte and multibyte forms overlap; Unicode not affected. CVSS UNVERIFIED.
- Fix (opened): https://sourceware.org/git/?p=glibc.git;a=commit;h=ef3bfb5f910011f3780cb06aa47e730035f53285 (bug 33998). Code: `libio/wgenops.c`, 2 changed lines (+2/-2). Dry-run on 2.36-9+deb12u14: wgenops.c "succeeded (offset -2)"; only the `libio/Makefile` test hunk FAILED (drop it).
- Same rebuild as C2 (one glibc rebuild can carry both patches). Same cost/risk. Test: needs a non-Unicode locale; awkward.
- Tier: same as C2 (N).

### Rejected: zlib CVE-2026-85091 (gz_write overflow, HIGH both scanners)
- NVD (opened, REST): Awaiting Analysis, 7.4 v3.1 (VulnCheck). Tracker (opened): bookworm vulnerable; says 1.2.11 through 1.3.2 affected; fix commit df84af25dc1942490e1d1c899a07619152a46148 (v1.4) https://github.com/madler/zlib/commit/df84af25dc1942490e1d1c899a07619152a46148 (opened).
- `patch --dry-run` on 1.2.13: `gzwrite.c Hunk #1 FAILED`: the fixed code (non-blocking `state->again`) does not exist in 1.2.13, so the upstream diff has no meaning there; we would have to write our own fix. That is not a backport. Also gzwrite is unused by nginx.
- It does remain a nice VEX `not_affected`/`vulnerable_code_not_in_execute_path` extra, but I did not verify that claim, so do not rely on it.

## Same version string: how the scanners treat a rebuilt package (TESTED)

Scanners match by package name plus version string against vendor data. They never look at the code. Debian marks 27171 "vulnerable" with no fixed version, so ANY zlib1g 1:1.2.13.dfsg-1 (patched or not) is listed. That is exactly what we want: the finding stays and the VEX statement then removes it.

Test: built the patched zlib1g (version unchanged), installed in a bookworm-slim image (`zlib-patched-test`), exported with `docker save`:
- Trivy 0.76.2: still lists CVE-2023-45853, CVE-2026-85091, CVE-2026-27171 (MEDIUM). With `--vex vex-test.json`: CVE-2026-27171 gone, other two remain.
- Grype v0.122.1: still lists CVE-2026-85091 and CVE-2026-27171. With `--vex`: 27171 moves to ignoredMatches (`vex-status: fixed`).
- Proven VEX statement (`scans/bp/vex-test.json`): `status: fixed`, ONE statement, TWO product ids, because the purl formats differ:
  - Trivy: `pkg:deb/debian/zlib1g@1.2.13.dfsg-1?arch=amd64&distro=debian-12.15&epoch=1`
  - Grype: `pkg:deb/debian/zlib1g@1%3A1.2.13.dfsg-1?arch=amd64&distro=debian-12.15&upstream=zlib`
- First attempt with only the Trivy purl did NOT suppress in Grype. This is the main trap.

## Things that could block the demo
1. purl mismatch: the `distro=debian-12.15` qualifier is baked into the product id. If the base image moves to 12.16 the purl changes and the VEX stops matching. Pin the base digest, or list purls per distro version, and generate the VEX purl from the actual scan JSON.
2. If we later add a Debian-style suffix (e.g. `+echo1`) the purl must change too, and Trivy/Grype still list it (no fixed version in tracker), but the VEX product id must match the new version.
3. The baseline image installs zlib1g in the final image only if our patched .deb is installed there (and not replaced by an apt upgrade). Pin or `apt-mark hold`.
4. Trivy VEX is marked EXPERIMENTAL; the flag works in 0.76.2 as tested. Grype needs about 3 min for first DB download (use a cache volume).
5. glibc (C2/C3) rebuild is the only candidate with real cost/risk; not needed if C1 alone is the backport. If two backport CVEs are wanted, pairing C1 with the glibc pair is the only way to add a second scanner-visible one.
