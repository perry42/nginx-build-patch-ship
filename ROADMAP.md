# Roadmap

How the work went, in the order I did it and why, and what I would do next. The numbers come from the files in `reports/` and the tests in `test/`.

## Done, in order

| Step | What I did | Why in this order | Evidence |
|---|---|---|---|
| 1. Baseline | Pulled `nginx:1.25-bookworm`, recorded the digest, `nginx -V` and the package list. Scanned with Trivy and Grype, both pinned. | I measured before choosing anything. | `baseline-trivy.txt`, `baseline-grype.txt` |
| 2. Triage | Sorted CVEs into bump, backport or out of scope. Removal never counts. | The brief asks for different techniques and a clear reason for each pick. | README, per-CVE table |
| 3. Build | Own script builds nginx 1.25.5 from the upstream tarball (pinned hash) with the baseline's configure flags, then packs a `.deb`. | A real artifact I can inspect, and no pre-built binaries. | `build/build.sh` |
| 4. Fixes | Bump: `libssl3` to 3.0.22-1~deb12u2. Backports: nginx CVE-2026-42945 and CVE-2026-9256 (upstream commits, unchanged). Backport: zlib CVE-2026-27171 (hand-port, Debian ships 1.2.13). | Each covers a different part of the brief. | `build/patches/`, `build/build-zlib.sh` |
| 5. Drop-in image | Same Debian 12.5 base as the original, user 101, entrypoint, ports, log symlinks, the files the nginx package ships. | Fixes only count if nothing else changes. | `Containerfile`, `docker inspect` diff |
| 6. Tests | pytest + requests boot both images and compare status, headers and body. Fix tests must fail on the original and pass on ours. | A test that passes on the unpatched build proves nothing. | `test/`, 79 tests, 8 intended failures on the original |
| 7. Rescan and VEX | Rescanned both images in one session. Wrote `vex.json` and rescanned with `--vex`. | Scanners match version strings, so a backport needs a VEX statement. | `reports/` |
| 8. CI and rehearsal | GitHub Actions builds once, then runs the tests, `make verify` and the scans in parallel. Fresh-clone `make all --no-cache` before the freeze. | What a reviewer would do, on a second Docker setup too. | `.github/workflows/ci.yml`, README |

## Numbers

- Frozen-database run of 2026-11-25: Trivy 955 to 365 rows, Grype 889 to 345. Of the removed Trivy rows, 96 are the libssl3 bump and 496 come from packages I left out (not counted as fixes). The first baseline (older databases) had 960 and 892.
- VEX: Trivy 365 to 364, Grype 345 to 344. Only the zlib row disappears.
- Image size: 179 MB against 276 MB.

## What I got wrong on the way (and fixed)

- My first expected output for the 42945 test was wrong. I now record the output of both builds.
- My first zlib proof-of-concept passed on the unpatched build too (a missing macro). Now it is compiled with that warning as an error.
- apt silently upgraded pcre2. Now versions are pinned and the package list is diffed against the baseline.
- A host-port race made 27 tests error at once. It was the test harness, not nginx. Fixed with unique ports and retries.
- Docker once left the patched zlib library out of an image layer on GitHub Actions (same size and file time as the original). Found by comparing the layers; fixed with a later `SOURCE_DATE_EPOCH`. Before the fix 2 of 6 CI runs failed, after it 0 of 9.
- The scanner databases moved in the middle of a run, and Grype never stored its database in the cache volume. Now one update per run, then frozen.

## Residual risk and next steps

- 6 libssl3 CVEs have no Debian fix yet, and 36 more nginx advisories are open. nginx 1.25.5 is end of life.
- The `.dsc`, PGP signatures and the VEX file are unsigned. The build depends on snapshot.debian.org.
- Next, in order: more library bumps one at a time (libc6, pcre2, gnutls, systemd libraries, liblzma, tzdata); more nginx backports; signing with cosign and an SBOM; a nightly rescan in CI; a reproducible `.deb` (`SOURCE_DATE_EPOCH`).
- The AI-assisted pipeline I would build is in `docs/future-ai-remediation-pipeline.md`. It is a spec, not implemented.
