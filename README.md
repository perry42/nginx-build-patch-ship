# Echo: Build It, Patch It, Ship It

A drop-in replacement for `nginx:1.25-bookworm`, built from the upstream nginx 1.25.5 source on a pinned `debian:bookworm-slim`, with three real security changes covering five CVEs: one library bump (48 unique CVEs cleared on libssl3 and openssl; I highlight the three that matter most) and two upstream patches backported onto the version we ship (one CVE each).

I wrote this as I went, so the decisions come with the reasons I made them, including the places where I changed my mind.

## What is in here

| Path | What it is |
|---|---|
| `build/build.sh`, `build/Dockerfile` | Fetches the nginx 1.25.5 tarball, checks its SHA-256, applies `build/patches/`, builds, and packs a `.deb`. |
| `build/patches/CVE-*.patch` | The two backports, byte-identical to the upstream commits. |
| `build/pkgfiles/`, `image/rootfs/` | Config files, welcome page and entrypoint scripts copied from the baseline image (same checksums). |
| `Containerfile` | Two stages: build the `.deb`, then install it on the same Debian the baseline uses. |
| `test/` | pytest + requests suite that boots both images and compares them. |
| `Makefile` | One entry point for everything below. |
| `reports/` | Trivy and Grype output for both images, and the per-CVE diff. |
| `baseline-trivy.txt`, `baseline-grype.txt` | The first baseline scans. |

## Build and run

You need Docker (BuildKit), GNU make and Python 3.10+. Nothing else.

```sh
make image      # builds the .deb from source, then echo/nginx:1.25-patched
make deps       # pip install -r test/requirements.txt
make test       # boots nginx:1.25-bookworm and our image, compares them, exits non-zero on any mismatch
make scan       # Trivy + Grype on both images, same session (about 12 minutes)
make diff       # CVE diff of the scans, written to reports/cve-diff.generated.txt (git-ignored; reports/cve-diff.txt is the committed copy with notes)
make sizes      # image sizes
make all        # all of the above
make deb        # only the .deb, exported to dist/
```

Run it: `docker run --rm -p 8080:80 echo/nginx:1.25-patched`.

## Image size

| Image | Size |
|---|---|
| `nginx:1.25-bookworm` | 276 MB |
| `echo/nginx:1.25-patched` | 179 MB |

This is not an achievement. Most of the 97 MB is components I did not include (see "Intended differences"), and the brief is clear that removal does not count as a fix. I list it because it was asked for, and because it is a side effect I want to be honest about.

## The base: why it is pinned

The first question I asked was "against what do I patch?" If my image sat on today's `debian:bookworm-slim`, libssl3 would already be at its fixed version and a "bump" would be a story I tell, not a change I make. So the baseline's Debian is the reference: 12.5, with the same `base-files`, `libc6` and library versions.

- Base: `debian:bookworm-20240513-slim`, pinned by digest in the `Containerfile`.
- apt points at `snapshot.debian.org` dated 2024-05-13, so old versions are installable.
- Exact version pins everywhere. A bare `apt-get install pcre2` silently upgraded pcre2 to `10.42-1+deb12u2` in one of my first builds, and I only noticed from the package diff. That is why the package list is diffed after every build.

## The three changes

Counting unit for scan numbers below: one row is one CVE on one package, so a CVE on libssl3 and openssl counts twice. Unique-CVE counts are in `reports/cve-diff.txt`.

| CVE | Severity | Technique | What it is | Evidence |
|---|---|---|---|---|
| CVE-2026-31789 | Critical (Trivy and Grype) | **Bump** (libssl3 and openssl 3.0.11-1~deb12u2 to 3.0.22-1~deb12u2) | OpenSSL | gone from libssl3 and openssl in both scanners: `reports/cve-diff.txt`, `reports/fixed-trivy.txt`, `reports/fixed-grype.txt` |
| CVE-2025-15467 | High per Trivy, Critical per Grype | **Bump** (same) | OpenSSL CMS parsing; nginx never parses CMS, so this is cleared but not reachable through nginx | same files |
| CVE-2024-6119 | High (Trivy and Grype; CVSS 7.5) | **Bump** (same) | X.509 name check, relevant when nginx verifies certificates. Trivy's fixed version for it is 3.0.14; we ship 3.0.22 | same files; https://nvd.nist.gov/vuln/detail/CVE-2024-6119 |
| CVE-2026-42945 | Medium per nginx.org, High (8.1) per NVD | **Backport** onto nginx 1.25.5 | Rewrite module: wrong escaping of a capture and a possible buffer overrun | `build/patches/CVE-2026-42945.patch` (upstream commit [`2046b45aa0c6`](https://github.com/nginx/nginx/commit/2046b45aa0c6e712c216b9075886f3f26e9b4ca9)); test `test_cve_2026_42945_capture_unescaping_differs` |
| CVE-2026-9256 | Medium per nginx.org (affects 0.1.17 to 1.31.0) | **Backport** onto nginx 1.25.5 | Rewrite module: heap overflow with overlapping captures. Crashes the original worker | `build/patches/CVE-2026-9256.patch` (upstream commit [`ca4f92a27464`](https://github.com/nginx/nginx/commit/ca4f92a27464ae6c2082245e4f67048c633aa032)); test `test_cve_2026_9256_overlapping_captures` |

Sources: https://nginx.org/en/security_advisories.html, https://www.cve.org/CVERecord?id=CVE-2026-42945.

### The bump

The `.deb` declares `libssl3 (>= 3.0.22-1~deb12u2)`, so the runtime cannot install without it. That version only exists in a newer Debian security snapshot (20261123), so the `Containerfile` adds that snapshot for one step and apt installs only what is missing: libssl3. Nothing already installed is upgraded.

Proof that it is the bump and not scanner noise: the installed libssl3 version is newer than the scanner's fixed version for the CVEs that disappear, so it is a real version-against-advisory comparison.

Result, Trivy (CVE, package) rows: 960 down to 370. Only 96 of the 592 rows that disappeared come from the bump (one of the two Trivy Criticals among them: CVE-2026-31789; Grype also rates CVE-2025-15467 Critical). See "Scan results" for the rest.

### The two backports

Both patches are the upstream commits unchanged, from the GitHub mirror (hg.nginx.org is decommissioned). `build.sh` applies them with `patch -p1 --fuzz=0`: if a hunk needed fuzz to land, the build would fail instead of quietly guessing.

I made two mistakes while proving them, and both taught me something:
- For 42945 I first wrote down the wrong "expected" output. nginx decodes the URL before the rewrite, so the patched answer `myvar=[/a/x y&z/q]` is the correct one. The original gives `myvar=[/a/x%20y%2]`. The test compares both exactly.
- For 9256 my first proof-of-concept URL, 30 characters, did not crash the original. A URL of 3000 `+` characters does, reliably (found by test-agent). A backport you cannot show failing before and working after is a claim, not evidence, so the test needs the failing side.

Why two nginx backports and not a library one: the brief asks for a CVE fixed upstream only in later versions, ported onto what we ship. These are in the module that handles every `rewrite`, I can show both failing and fixed with plain HTTP requests, and the patches are small enough to review line by line.

## Scan results

Trivy 0.76.2 and Grype v0.122.1, both images scanned back to back, so a database update cannot look like a difference between them.

| | Trivy rows | Grype rows | Trivy unique CVEs | Grype unique CVEs |
|---|---|---|---|---|
| Baseline | 960 | 892 | 604 | 538 |
| Ours | 370 | 348 | 211 | 191 |

What the 592 removed Trivy rows are made of:
- **96** are the libssl3/openssl bump. This is the fix.
- **496** are packages that our image does not contain (curl, the module libraries, and so on). This is removal, and I do not count it as a fix.

So the headline drop of 62% would be dishonest if it stood alone. The honest number is: the bump cleared 96 rows, including the Critical CVE-2026-31789 (and CVE-2025-15467, which Grype rates Critical and Trivy High).

## Scanners do not see the backports

Neither scanner ever lists CVE-2026-42945 or CVE-2026-9256, before or after. They match package metadata against distro advisories, and they do not read nginx.org advisories. So the scan diff cannot show the backports, and I prove them with the tests instead. This also means the brief's VEX demonstration cannot use the nginx CVEs; VEX status is in the next section.

## VEX (bonus)

Not done yet. A VEX statement can only hide a row that a scanner printed, and neither scanner prints our nginx CVEs, so it has nothing to remove. The only scanner-visible candidate I found is zlib CVE-2026-27171 (listed by both scanners, no Debian fix, a two-line upstream fix). It is optional and I am treating it as the last item.

## Tests: what "working correctly" means

The suite boots `nginx:1.25-bookworm` and our image as separate containers, sends identical requests and compares status line, all headers except `Date`, and the body. It exits non-zero on any mismatch.

Covered (63 tests):
- default config responses (`/`, `/missing`, `/50x.html`) and identical entrypoint startup log lines
- mounted `conf.d`, and `envsubst` templates
- `rewrite` last/break/redirect/permanent, captures, malformed `%` escapes
- large bodies: 5 MB accepted, over the limit gives 413, per-location limit
- raw-socket malformed requests: bad method, long request line, missing Host, invalid header, bare LF, garbage
- custom config: `server_tokens off`, `add_header`, named vhost
- TLS: same response and same negotiated protocol and cipher
- `docker inspect` fields, file layout, modes, owners, and SHA-256 of every file under `/etc/nginx` and the html folder
- log symlinks, user `nginx` (UID 101), graceful `docker stop`

Not covered: HTTP/2, proxying, gzip, reload and signals beyond the SIGQUIT stop, runtime log content.

The suite can fail on purpose. Run it with both sides set to the original image and exactly four tests fail: the two CVE tests and two documented-difference tests (environment variables and labels). I use that to check that the tests really detect a missing patch.

## Intended differences

The brief says to match "the upstream image's filesystem layout, user, working directory, ports, and entrypoint exactly". User, working directory, port 80, entrypoint, command and stop signal are identical (checked with `docker inspect`). For the filesystem, my image contains nothing the baseline lacks, and everything the `nginx` package itself ships is present with the same mode, owner and checksum, including `nginx-debug`, `/etc/default`, the init scripts, logrotate and systemd units. What is missing is whole packages: curl and its dependencies, and the four dynamic modules. I read "layout" as where nginx's own files live, and I consider extra packages a separate question; a stricter reader could disagree, and the entries below are the cost of that reading.

Everything below is a deliberate difference from the official image.

| Difference | Why |
|---|---|
| `PKG_RELEASE` is `1~echo1`, not `1~bookworm` | Honest naming. I never spoof a version string. |
| No `NJS_*` environment variables, no `maintainer` label | The label names the nginx Docker maintainers; I am not them. |
| No curl, libcurl4, or their dependency chain | See below. |
| No dynamic modules: geoip, image-filter, njs, xslt | See below. |
| 93 packages against the baseline's 149 | 56 packages are missing, all from the items above (curl chain, module libraries). No package was added. Three versions differ: libssl3 and openssl (the bump) and nginx itself. |

### Why curl is not in the image

This was the decision I went back and forth on most, so here is the reasoning.

My first instinct was "the brief says drop-in, so match everything". Then I checked what curl is actually used for in the official image. nginx does not link libcurl (`ldd` shows nothing), and none of the entrypoint scripts call curl. In the official image it is a leftover from the Dockerfile's repository setup.

Leaving it out removes 104 rows from each scanner. That is exactly why I distrust the decision: it makes my scan look better, which is a bad reason to do anything. So I decided on one condition: I would not count it as a fix, and I would write it down here instead of hoping nobody notices.

The cost is real. Anyone who runs `curl` inside the container, for example in a `HEALTHCHECK`, gets "command not found". Their fix is `apt-get install curl` in a derived image, and then they inherit Debian's curl CVEs, several of which Debian has not fixed in bookworm. If I had more time I would publish an optional variant with curl, pinned to the same snapshot.

### Why the modules are not in the image

Same logic: they are separate packages in the official image, not part of the nginx binary. The binary is configured with the same flags as the baseline (`nginx -V` is identical apart from the `-ffile-prefix-map` path; it is built against libssl-dev 3.0.11 and runs on 3.0.22), so the core is the same. Adding the four modules back needs their libraries pinned from the snapshot, a bigger test surface, and more CVE rows. I chose a smaller, fully tested core over a bigger, half-tested one.

## Residual risk: what remains and why

- **Eight libssl3 CVEs have no fixed Debian version** (CVE-2025-27587, CVE-2026-107493, -107494, -107496, -121481, -121482, -84786, -95690). Grype rates five of them High, Trivy rates one (CVE-2026-107494) High. The two scanners disagree, so I would not rely on either rating alone. Next step: check upstream OpenSSL for fixes and backport the ones that apply to what nginx uses.
- **nginx 1.25.5 is end-of-life, and 36 more upstream advisories affect it.** `docs/triage-nginx-upstream.csv` lists 38 nginx.org advisories whose affected range includes 1.25.5. I fixed two. The other 36 stay, and each is marked not reachable in the default config. The ones I would look at first: CVE-2026-123007 (HTTP/2 flow control, major, only when HTTP/2 is enabled), CVE-2026-118899 (TLS 1.3 request body loop, major), CVE-2026-42533 (`map` with regex captures, major), CVE-2026-15176 (`alias` with `rewrite`, medium). Backporting each one is the wrong long-term answer; the real fix is rebasing onto a supported 1.30.x, which I did not do because the brief asks to patch the version we ship.
- **Everything else the scanners still report** (370 rows for Trivy) is in packages that are in both images and that Debian has not fixed, or that nginx does not use. I did not try to fix these, and the next step would be to triage them the same way.
- **The omitted components** (above) are a risk reduction by removal, not a fix.
- **The `.deb` is not byte-reproducible.** I did not set `SOURCE_DATE_EPOCH`. Two builds give the same contents but different bytes.
- **The build depends on snapshot.debian.org being up.** If it is down, the build fails; I did not mirror it.
- **I verify the tarball by SHA-256 but not by its PGP signature.** The checksum is pinned in the repo, so an attacker would need to replace the file and the repo, but I did not check upstream's signature.
- **Backports are verified by tests that I wrote.** A different regression in the same module could still exist.

## Surprises, and what I would do differently

- **Trivy flags our `nginx` package, not the baseline's.** Trivy reports CVE-2009-4487 and CVE-2013-0337 (both LOW, old issues in Debian's own `nginx` package, which is version 1.22.1) on our package but not on the baseline's. These are false positives for upstream 1.25.5. I probed the cause: setting our package's Maintainer to the nginx.org packager made both rows disappear; changing only the version suffix did not. Grype reports both CVEs on both images, so it ignores the Maintainer. I tried only one alternative maintainer and found no documentation of the mechanism, so this is an observation, not an explanation. I did not copy the nginx.org maintainer into our package to hide the rows: we are not them. The deeper lesson is the same as the backport blind spot: scanners match package metadata, not what the binary contains.
- **apt silently upgraded pcre2.** Fixed with exact version pins.
- **IPv6 listen was off in my first image.** I only found it by comparing startup logs of both images. The entrypoint script compares `default.conf` to the checksum that dpkg recorded, so the config files must ship as dpkg conffiles, like the official package does.
- **Config files arrived executable.** They came through a Windows checkout. Fixed with `chmod 0644` in `build.sh`.
- **My first `.deb` was unstripped** (8.4 MB binary) and shipped a `/var/run` directory.
- **Severity depends on who you ask.** For CVE-2026-42945 nginx.org says medium and NVD says 8.1 High.
- **One transient failure I did not explain.** A back-to-back run with both sides set to the original once had 27 errors that never reproduced. I could not find the cause. The full suite passed after that, but if you see random errors on a first run, re-run and tell me.
- **What I would do differently:** write the tests as I build, not at the end (I changed to this halfway through, after noticing I had scheduled them last), and pin every apt version from the first build instead of after the first drift.

## AI tools used

I used Claude Code (Sonnet 5.5) with four project agents defined in `.claude/agents/`: a product-manager (scope and acceptance criteria), a packaging-expert (build details), a security-reviewer (scan triage and review) and a test-agent (the pytest suite). The main assistant did the hands-on build with me, step by step, and the reviewers checked each step.

Where it helped:
- test-agent found the reliable crash trigger for CVE-2026-9256 and the missing `maintainer` label.
- security-reviewer verified that the patches are byte-identical to upstream, and recomputed my scan numbers from the raw JSON.
- Having the same assistant explain each step as it built made me understand the pieces: `dpkg`, conffiles, the snapshot repositories, and how scanners match.

Where it hurt:
- It stated a wrong "expected" output for the 42945 test and a 30-character crash URL that did not crash anything. I caught both by running them.
- A subagent report said removing curl dropped "about 40" rows. The real number is 104 per scanner, and I only found out by counting.
- I once believed Grype showed the same maintainer effect as Trivy; the reviewer checked and it does not.

The rule I took from this: every number or claim in this README comes from a command I ran or a file in `reports/`, not from a summary.
