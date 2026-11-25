# Echo: Build It, Patch It, Ship It

A drop-in replacement for `nginx:1.25-bookworm`, built from the upstream nginx 1.25.5 source on a pinned `debian:bookworm-slim`, with four real security changes: one library bump (48 unique CVEs cleared on libssl3 and openssl; I highlight the three that matter most) and three backported patches, two in nginx's rewrite module and one in zlib (one CVE each).

I wrote this as I went, so the decisions come with the reasons I made them, including the places where I changed my mind.

## Verify me in 5 minutes

I wrote `make verify` so you can check my claims without reading my code. It needs both images to exist already (`nginx:1.25-bookworm` and `echo/nginx:1.25-patched`, after `make image`). It does not build or scan.

It runs the three tests that prove my fixes (four test cases, because the zlib one runs in two modes). First against my image, where they pass. Then a second time with the original image in both slots, where they must fail. That failure is the point: a fix test that also passes on the unfixed image proves nothing. It also compares image sizes and the libssl3 version in both images, and prints my saved VEX diff from `reports/vex-diff.txt`. That last part is a saved report, not recomputed.

It does not prove drop-in parity (that is the full `make test`) or the scan results (`make scan vex diff`, part of `make all`). Do not run it at the same time as `make test`: the test fixtures remove each other's containers.

```sh
make verify
```

The last line reads `VERIFY: PASS (n/n checks)` or `VERIFY: FAIL (names of the failed checks)`. On my machine, with both images already built, it took 3 minutes 5 seconds. The 5 second zlib hang runs in both passes, and the proof of concept is compiled in each pass. The nginx CVE-2026-9256 test is probabilistic (it looks for a crash), so a rare FAIL on the nginx CVE line means run it once more. The control run only proves that the tests detect the bugs on the original. It does not prove that nothing else differs between the two images. If a check fails, it prints the failing test names with their messages and the last lines of the pytest output.

## What is in here

| Path | What it is |
|---|---|
| `build/build.sh`, `build/Dockerfile` | Fetches the nginx 1.25.5 tarball, checks its SHA-256, applies `build/patches/`, builds, and packs a `.deb`. |
| `build/patches/CVE-*.patch` | The two nginx backports, byte-identical to the upstream commits. `build/patches/zlib/` holds the zlib one, a hand-port (see below). |
| `build/build-zlib.sh` | Rebuilds Debian's zlib1g from its source package with the zlib patch, as a second `.deb`. |
| `vex.json` | OpenVEX statements for the three backports. |
| `build/pkgfiles/`, `image/rootfs/` | Config files, welcome page and entrypoint scripts copied from the baseline image (same checksums). |
| `Containerfile` | Two stages: build the `.deb`, then install it on the same Debian the baseline uses. |
| `test/` | pytest + requests suite that boots both images and compares them. |
| `Makefile` | One entry point for everything below. |
| Git history | `git log --first-parent --oneline main` lists the work in order, one merge per milestone (baseline, build, layout, zlib backport, VEX, `make verify`, CI, reproducible builds). I kept the real history, including early stacked branches, and did not rewrite it. |
| `reports/` | Trivy and Grype output for both images, and the per-CVE diff. |
| `baseline-trivy.txt`, `baseline-grype.txt` | The first baseline scans. |

## Build and run

You need Docker (BuildKit), GNU make and Python 3.10+. Nothing else. The Makefile calls `python` by default; on a machine that only has `python3`, add `PY=python3` (for example `make PY=python3 deps test`), and if pip refuses to install system-wide (PEP 668), create a virtualenv first and pass its interpreter, for example `PY=.venv/bin/python`. The zlib tests compile a small C program inside a container, so they need network access to `snapshot.debian.org`.

```sh
make image      # builds the .deb from source, then echo/nginx:1.25-patched
make deps       # pip install -r test/requirements.txt
make test       # boots nginx:1.25-bookworm and our image, compares them, exits non-zero on any mismatch
make scan       # Trivy + Grype on both images, same session (about 12 minutes). Updates the scanner databases once, then every scan in the run uses that copy; `make scan DB=fresh` lets every scan update its own
make vex        # rescan our image with vex.json applied; the zlib row disappears
make diff       # CVE diff of the scans, written to reports/cve-diff.generated.txt (git-ignored; reports/cve-diff.txt is the committed copy with notes)
make sizes      # image sizes
make all        # all of the above
make deb        # only the .deb, exported to dist/
make repro      # build both .deb files from scratch and check their sha256 against build/deb.sha256
```

Run it: `docker run --rm -p 8080:80 echo/nginx:1.25-patched`.

## Image size

| Image | Size |
|---|---|
| `nginx:1.25-bookworm` | 276 MB |
| `echo/nginx:1.25-patched` | 179 MB |

These are the sizes `docker image ls` shows on my machine (Docker Desktop on Windows). Docker on Linux counts image size differently: on a GitHub Actions runner the same two images show 188 MB and 116 MB. The reduction is about 38% in both. This is not an achievement. Most of the 97 MB is components I did not include (see "Intended differences"), and the brief is clear that removal does not count as a fix. I list it because it was asked for, and because it is a side effect I want to be honest about.

## The base: why it is pinned

The first question I asked was "against what do I patch?" If my image sat on today's `debian:bookworm-slim`, libssl3 would already be at its fixed version and a "bump" would be a story I tell, not a change I make. So the baseline's Debian is the reference: 12.5, with the same `base-files`, `libc6` and library versions.

- Base: `debian:bookworm-20240513-slim`, pinned by digest in the `Containerfile`.
- apt points at `snapshot.debian.org` dated 2024-05-13, so old versions are installable.
- Exact version pins everywhere. A bare `apt-get install pcre2` silently upgraded pcre2 to `10.42-1+deb12u2` in one of my first builds, and I only noticed from the package diff. That is why the package list is diffed after every build.

## The four changes

Counting unit for scan numbers below: one row is one CVE on one package, so a CVE on libssl3 and openssl counts twice. Unique-CVE counts are in `reports/cve-diff.txt`.

| CVE | Severity | Technique | What it is | Evidence |
|---|---|---|---|---|
| CVE-2026-31789 | Critical (Trivy and Grype) | **Bump** (libssl3 and openssl 3.0.11-1~deb12u2 to 3.0.22-1~deb12u2) | OpenSSL | gone from libssl3 and openssl in both scanners: `reports/cve-diff.txt`, `reports/fixed-trivy.txt`, `reports/fixed-grype.txt` |
| CVE-2025-15467 | High per Trivy, Critical per Grype | **Bump** (same) | OpenSSL CMS parsing; nginx never parses CMS, so this is cleared but not reachable through nginx | same files |
| CVE-2024-6119 | High (Trivy and Grype; CVSS 7.5) | **Bump** (same) | X.509 name check, relevant when nginx verifies certificates. Trivy's fixed version for it is 3.0.14; we ship 3.0.22 | same files; https://nvd.nist.gov/vuln/detail/CVE-2024-6119 |
| CVE-2026-42945 | Medium per nginx.org, High (8.1) per NVD | **Backport** onto nginx 1.25.5 | Rewrite module: wrong escaping of a capture and a possible buffer overrun | `build/patches/CVE-2026-42945.patch` (upstream commit [`2046b45aa0c6`](https://github.com/nginx/nginx/commit/2046b45aa0c6e712c216b9075886f3f26e9b4ca9)); test `test_cve_2026_42945_capture_unescaping_differs` |
| CVE-2026-9256 | Medium per nginx.org (affects 0.1.17 to 1.31.0) | **Backport** onto nginx 1.25.5 | Rewrite module: heap overflow with overlapping captures. Crashes the original worker | `build/patches/CVE-2026-9256.patch` (upstream commit [`ca4f92a27464`](https://github.com/nginx/nginx/commit/ca4f92a27464ae6c2082245e4f67048c633aa032)); test `test_cve_2026_9256_overlapping_captures` |
| CVE-2026-27171 | Medium (Trivy and Grype) | **Backport** onto Debian's zlib 1.2.13 | zlib: infinite loop in `crc32_combine64` and `crc32_combine_gen64` when the length is negative. nginx never calls these, so it is not reachable through nginx | `build/patches/zlib/CVE-2026-27171.patch`, a hand-port of upstream [`ba829a45`](https://github.com/madler/zlib/commit/ba829a458576d1ff0f26fc7230c6de816d1f6a77); test `test_cve_2026_27171_poc`; the scanner row disappears with VEX: `reports/vex-diff.txt` |

Sources: https://nginx.org/en/security_advisories.html, https://www.cve.org/CVERecord?id=CVE-2026-42945.

### The bump

The `.deb` declares `libssl3 (>= 3.0.22-1~deb12u2)`, so the runtime cannot install without it. That version only exists in a newer Debian security snapshot (20261123), so the `Containerfile` adds that snapshot for one step and apt installs only what is missing: libssl3. Nothing already installed is upgraded.

Proof that it is the bump and not scanner noise: the installed libssl3 version is newer than the scanner's fixed version for the CVEs that disappear, so it is a real version-against-advisory comparison.

Result, Trivy (CVE, package) rows: 955 down to 365. Only 96 of the 592 rows that disappeared come from the bump (one of the two Trivy Criticals among them: CVE-2026-31789; Grype also rates CVE-2025-15467 Critical). See "Scan results" for the rest.

### The backports

The two nginx patches are the upstream commits unchanged, from the GitHub mirror (hg.nginx.org is decommissioned). `build.sh` applies them with `patch -p1 --fuzz=0`: if a hunk needed fuzz to land, the build would fail instead of quietly guessing.

I made two mistakes while proving them, and both taught me something:
- For 42945 I first wrote down the wrong "expected" output. nginx decodes the URL before the rewrite, so the patched answer `myvar=[/a/x y&z/q]` is the correct one. The original gives `myvar=[/a/x%20y%2]`. The test compares both exactly.
- For 9256 my first proof-of-concept URL, 30 characters, did not crash the original. A URL of 3000 `+` characters does, reliably (found by test-agent). A backport you cannot show failing before and working after is a claim, not evidence, so the test needs the failing side.

Why two nginx backports: the brief asks for a CVE fixed upstream only in later versions, ported onto what we ship. These are in the module that handles every `rewrite`, I can show both failing and fixed with plain HTTP requests, and the patches are small enough to review line by line.

### The zlib backport

Neither scanner lists the nginx CVEs, so I needed one backport on something they do list, to show the VEX step the brief asks for. zlib CVE-2026-27171 is listed by both, Debian has no fixed bookworm version, and upstream has a two-line fix.

- **It is a hand-port, not upstream's commit.** Upstream's patch is written for the current zlib layout. Debian ships zlib 1.2.13, whose `crc32.c` uses old-style C function definitions, so upstream's patch does not apply. I put the same two guards (`if (len2 < 0) return 0;`) in the same two functions and produced a patch against Debian's real source, `build/patches/zlib/CVE-2026-27171.patch`. I left out upstream's comment-only change to `zlib.h`.
- **How it is built.** `build/build-zlib.sh` fetches Debian's source package (`apt source zlib=1:1.2.13.dfsg-1`, the version the baseline has), applies the patch with `--fuzz=0`, and runs `dpkg-buildpackage`. This is a second `.deb`. The `Containerfile` reinstalls it over the stock package with `dpkg -i`.
- **The version string stays `1:1.2.13.dfsg-1` on purpose.** The scanners therefore still flag it, and `vex.json` is the declaration that it is fixed. `dpkg -V zlib1g` reports the same two missing changelog files on both images, so dpkg's checksums match the rebuilt library.
- **The proof.** `test/fixtures/zlib/poc.c` calls both functions with a length of -1, linked against whichever libz the image provides. On the original image it never returns (killed after 5 seconds, exit 124). On ours it returns 0 at once. My first version of this program did not hang on the original either: without `#define _LARGEFILE64_SOURCE`, zlib.h does not declare the 64-bit functions, so the call passed a 32-bit integer and never sent a negative length. The compiler warned about it. It is now compiled with that warning as an error, and I only believed the test once the original really hung.
- **Since I replaced zlib, I also test what nginx uses it for.** gzip responses (and `gzip_static`) are byte-identical on both images, including the compressed bytes.

## Bump or backport: how I decided

For every CVE I asked the same two questions, in this order.

1. **Does Debian already ship a fixed version of the package I have?** Then it is a **bump**: I install that version. This is what happened with libssl3 (`3.0.22-1~deb12u2` exists, so I use it).
2. **If not, does upstream have a small fix commit?** Then it is a **backport**: I take only that fix and apply it to the version I ship. This is what happened with the two nginx rewrite bugs, and it is what I did for zlib CVE-2026-27171 (Debian has no fixed bookworm version, upstream has a two-line fix).

The tempting third option is to swap in a much newer upstream release (nginx 1.30, or zlib 1.3.x). I did not, because that is a big change: it carries every other change made since, the package stops being Debian's package, and the compatibility risk is mine. The brief asks for a drop-in replacement, not a re-imagining, and for a patch applied to the version we ship. Taking only the lines that fix the bug keeps everything else byte-for-byte the same as the baseline.

The two techniques also look different to a scanner, which is why the brief wants both:

| | Version string | What the scanner does | How I show the fix |
|---|---|---|---|
| Bump | changes (libssl3 `3.0.11` to `3.0.22`) | stops flagging by itself | the row disappears in the rescan |
| Backport | stays the same | keeps flagging, if it flagged at all | tests that fail before and pass after, and a VEX statement |

I deliberately do not raise the version number of a backported package to make a scanner happy. That would be a false claim. The honest way to say "this CVE no longer applies to my build" is VEX.

One honest limit on the zlib backport: nginx only uses zlib's `deflate` and `inflate` and never calls the vulnerable `crc32_combine` functions, so this fix is not reachable through nginx. It is there to show the backport-plus-VEX path with a CVE the scanners really list, not because it makes nginx safer.

## Scan results

Trivy 0.76.2 and Grype v0.122.1, both images scanned back to back. The vulnerability databases are updated once at the start and then frozen for the whole run (`make scan`, recorded in `scans/rescan/db-versions.txt`). The numbers below are from the run on 2026-11-25 with Trivy's database updated 2026-11-25 01:10 UTC and Grype's built 2026-11-25 06:22 UTC. **Row counts move whenever a database changes**: my first baseline scan, taken earlier with older databases, had 960 Trivy and 892 Grype rows (`baseline-*.txt`), and a GitHub Actions run on the same day gave exactly today's numbers. The shape does not move: the bump removes the same 96 rows and VEX removes only the zlib row.

I learned this the hard way. An earlier run of mine showed the VEX rescan removing nine Trivy rows instead of one, because Trivy updated its database between two scans. I also found that Grype's database was never stored in the cache volume (its cache directory is `/.cache/grype` in the container), so every Grype run downloaded its own copy. The Makefile now points Grype's cache at the volume.

| | Trivy rows | Grype rows | Trivy unique CVEs | Grype unique CVEs |
|---|---|---|---|---|
| Baseline | 955 | 889 | 602 | 537 |
| Ours | 365 | 345 | 209 | 190 |

What the 592 removed Trivy rows are made of:
- **96** are the libssl3/openssl bump. This is the fix.
- **496** are packages that our image does not contain (curl, the module libraries, and so on). This is removal, and I do not count it as a fix.

So the headline drop of 62% would be dishonest if it stood alone. The honest number is: the bump cleared 96 rows, including the Critical CVE-2026-31789 (and CVE-2025-15467, which Grype rates Critical and Trivy High).

## Scanners do not see the backports

Neither scanner ever lists CVE-2026-42945 or CVE-2026-9256, before or after. They match package metadata against distro advisories, and they do not read nginx.org advisories. So the scan diff cannot show the backports, and I prove them with the tests instead. This also means the brief's VEX demonstration cannot use the nginx CVEs; VEX status is in the next section.

## VEX (bonus)

`vex.json` is an OpenVEX v0.2.0 document with one statement per backport. I applied it with both scanners to the same image, in the same session, with the same pinned versions (`make vex`):

| | rows without VEX | rows with VEX | what changed |
|---|---|---|---|
| Trivy 0.76.2 | 365 | 364 | CVE-2026-27171 on zlib1g removed |
| Grype v0.122.1 | 345 | 344 | CVE-2026-27171 on zlib1g removed (Grype moves it to its ignored list) |

Nothing else changed in either scanner. Evidence: `reports/vex-diff.txt`, `reports/vex-trivy.txt` and `reports/vex-grype.txt`, compared with `reports/fixed-trivy.txt` and `reports/fixed-grype.txt`.

The VEX file also says the two nginx CVEs are fixed, but neither scanner lists them with or without VEX, so those two statements document the fix and remove no row. The product identifiers in the zlib statement are the ones each scanner reported for the package (they write the epoch differently), so both match.

## Tests: what "working correctly" means

The suite boots `nginx:1.25-bookworm` and our image as separate containers, sends identical requests and compares status line, all headers except `Date`, and the body. It exits non-zero on any mismatch.

Covered (79 tests):
- default config responses (`/`, `/missing`, `/50x.html`) and identical entrypoint startup log lines
- mounted `conf.d`, and `envsubst` templates
- `rewrite` last/break/redirect/permanent, captures, malformed `%` escapes
- large bodies: 5 MB accepted, over the limit gives 413, per-location limit
- raw-socket malformed requests: bad method, long request line, missing Host, invalid header, bare LF, garbage
- custom config: `server_tokens off`, `add_header`, named vhost
- TLS: same response and same negotiated protocol and cipher
- `docker inspect` fields, file layout, modes, owners, and SHA-256 of every file under `/etc/nginx` and the html folder
- log symlinks, user `nginx` (UID 101), graceful `docker stop`
- the files the `nginx` package itself ships (`nginx-debug`, `/etc/default`, init scripts, logrotate, systemd units): mode, owner and checksum, the dpkg conffile list, the `dpkg -L` file list, and that `nginx-debug` runs and serves the same page
- the installed package set: the only version differences are libssl3, openssl and nginx, we have no package the baseline lacks, and the 56 missing packages are exactly the documented list (so the extra security snapshot used for the bump cannot silently pull in anything else)
- gzip and `gzip_static` responses, including the compressed bytes (zlib was replaced)
- the zlib CVE-2026-27171 proof-of-concept (hangs on the original, returns on ours), and that the zlib1g version string is identical while the library file differs

Not covered: HTTP/2, proxying, reload and signals beyond the SIGQUIT stop, runtime log content.

The suite can fail on purpose. Run it with both sides set to the original image and exactly eight tests fail, all intended: the two nginx CVE tests, the zlib proof-of-concept (two cases), the zlib version/library check, the installed-package-set test, and two documented-difference tests (environment variables and labels). I use that to check that the tests really detect a missing patch.

## Intended differences

The brief says to match "the upstream image's filesystem layout, user, working directory, ports, and entrypoint exactly". User, working directory, port 80, entrypoint, command and stop signal are identical (checked with `docker inspect`). For the filesystem, my image contains nothing the baseline lacks, and everything the `nginx` package itself ships is present with the same mode, owner and checksum, including `nginx-debug`, `/etc/default`, the init scripts, logrotate and systemd units. What is missing is whole packages: curl and its dependencies, and the four dynamic modules. I read "layout" as where nginx's own files live, and I consider extra packages a separate question; a stricter reader could disagree, and the entries below are the cost of that reading.

Everything below is a deliberate difference from the official image.

| Difference | Why |
|---|---|
| `PKG_RELEASE` is `1~echo1`, not `1~bookworm` | Honest naming. I never spoof a version string. |
| No `NJS_*` environment variables, no `maintainer` label | The label names the nginx Docker maintainers; I am not them. |
| No curl, libcurl4, or their dependency chain | See below. |
| No dynamic modules: geoip, image-filter, njs, xslt | See below. |
| zlib1g has the same version string but different contents | The CVE-2026-27171 backport. `libz.so.1.2.13` differs from the baseline's, and a test documents it. |
| 93 packages against the baseline's 149 | 56 packages are missing, all from the items above (curl chain, module libraries). No package was added. Three versions differ: libssl3 and openssl (the bump) and nginx itself. zlib1g keeps its version but its contents differ (row above). |

### Why curl is not in the image

This was the decision I went back and forth on most, so here is the reasoning.

My first instinct was "the brief says drop-in, so match everything". Then I checked what curl is actually used for in the official image. nginx does not link libcurl (`ldd` shows nothing), and none of the entrypoint scripts call curl. In the official image it is a leftover from the Dockerfile's repository setup.

Leaving it out removes 104 rows from each scanner. That is exactly why I distrust the decision: it makes my scan look better, which is a bad reason to do anything. So I decided on one condition: I would not count it as a fix, and I would write it down here instead of hoping nobody notices.

The cost is real. Anyone who runs `curl` inside the container, for example in a `HEALTHCHECK`, gets "command not found". Their fix is `apt-get install curl` in a derived image, and then they inherit Debian's curl CVEs, several of which Debian has not fixed in bookworm. If I had more time I would publish an optional variant with curl, pinned to the same snapshot.

### Why the modules are not in the image

Same logic: they are separate packages in the official image, not part of the nginx binary. The binary is configured with the same flags as the baseline (`nginx -V` is identical apart from the `-ffile-prefix-map` path; it is built against libssl-dev 3.0.11 and runs on 3.0.22), so the core is the same. Adding the four modules back needs their libraries pinned from the snapshot, a bigger test surface, and more CVE rows. I chose a smaller, fully tested core over a bigger, half-tested one.

## Residual risk: what remains and why

- **Six libssl3 CVEs have no fixed Debian version** (CVE-2025-27587, CVE-2026-107493, -107496, -121481, -84786, -95690). Grype rates three of them High (-107493, -107496, -84786), Trivy rates none above Medium. The two scanners disagree, so I would not rely on either rating alone. Two more that an earlier run listed (-107494 and -121482) are not reported by today's databases, and I did not look into why. Next step: check upstream OpenSSL for fixes and backport the ones that apply to what nginx uses.
- **nginx 1.25.5 is end-of-life, and 36 more upstream advisories affect it.** `docs/triage-nginx-upstream.csv` lists 38 nginx.org advisories whose affected range includes 1.25.5. I fixed two. The other 36 stay, and each is marked not reachable in the default config. The ones I would look at first: CVE-2026-123007 (HTTP/2 flow control, major, only when HTTP/2 is enabled), CVE-2026-118899 (TLS 1.3 request body loop, major), CVE-2026-42533 (`map` with regex captures, major), CVE-2026-15176 (`alias` with `rewrite`, medium). Backporting each one is the wrong long-term answer; the real fix is rebasing onto a supported 1.30.x, which I did not do because the brief asks to patch the version we ship.
- **Everything else the scanners still report** (365 rows for Trivy) is in packages that are in both images and that Debian has not fixed, or that nginx does not use. I did not try to fix these, and the next step would be to triage them the same way.
- **The omitted components** (above) are a risk reduction by removal, not a fix.
- **Reproducible `.deb`, checked on two machines.** Building both packages from scratch (`make repro`) gives the same sha256 on my laptop and on a GitHub Actions runner: nginx `065024b0a6642a7cac1397cadfcd6ef7eeceba7578b24e7cebecc49be1b53a39` and zlib1g `84bcd27e013789e7a72b7370ee7496ea75d5bd7ae07a03d49ec5703b6fd807dd` (`build/deb.sha256`; CI fails if they change). It was not true at first. The nginx package differed between builds, and then between machines, and each time only in file times: every file's content, mode and owner was identical, including both nginx binaries. First the build time was in the files; then, after I clamped times to a fixed date, config files copied from the repo still carried the time of each checkout, which is older than the date and differs per machine. The fix is a fixed `SOURCE_DATE_EPOCH` and setting every file time to it in `build/build.sh` and `build/build-zlib.sh`. Two machines is evidence, not proof for everyone: the base image and the snapshot are pinned, but I have not tried another architecture. If you change a patch or a build flag, the nginx hash changes on purpose and `build/deb.sha256` has to be updated.
- **The build depends on snapshot.debian.org being up.** If it is down, the build fails; I did not mirror it.
- **I verify the tarball by SHA-256 but not by its PGP signature.** The checksum is pinned in the repo, so an attacker would need to replace the file and the repo, but I did not check upstream's signature.
- **Backports are verified by tests that I wrote.** A different regression in the same module could still exist. The zlib patch in particular is my hand-port, not upstream's commit, and its only proof is my own proof-of-concept program.
- **`apt-get source` does not verify the source package's `.dsc` signature** (there is no Debian keyring in the builder). Trust rests on apt's signed `Release` and `Sources` index for the pinned snapshot date. Like the nginx tarball signature, I did not close this gap.
- **`vex.json` is a self-asserted, unsigned statement.** Anyone consuming it has to trust whoever wrote it. Signing it (and the image) is a next step.
- **The runtime still has a full Debian userland** (shell, apt, dpkg). A distroless or much smaller runtime would shrink the attack surface further, but it would also stop being a drop-in replacement, so I left it as a proposal.

## Surprises, and what I would do differently

- **Trivy flags our `nginx` package, not the baseline's.** Trivy reports CVE-2009-4487 and CVE-2013-0337 (both LOW, old issues in Debian's own `nginx` package, which is version 1.22.1) on our package but not on the baseline's. These are false positives for upstream 1.25.5. I probed the cause: setting our package's Maintainer to the nginx.org packager made both rows disappear; changing only the version suffix did not. Grype reports both CVEs on both images, so it ignores the Maintainer. I tried only one alternative maintainer and found no documentation of the mechanism, so this is an observation, not an explanation. I did not copy the nginx.org maintainer into our package to hide the rows: we are not them. The deeper lesson is the same as the backport blind spot: scanners match package metadata, not what the binary contains.
- **My first zlib proof-of-concept proved nothing.** It ran fine on the original image too, because a missing macro made it pass a 32-bit integer instead of a negative 64-bit one. The compiler warned and I read the test result, not the warnings. A test that passes on the unpatched build tells you nothing, so every fix test of mine now has to fail on the original first.
- **apt silently upgraded pcre2.** Fixed with exact version pins.
- **IPv6 listen was off in my first image.** I only found it by comparing startup logs of both images. The entrypoint script compares `default.conf` to the checksum that dpkg recorded, so the config files must ship as dpkg conffiles, like the official package does.
- **Config files arrived executable.** They came through a Windows checkout. Fixed with `chmod 0644` in `build.sh`.
- **My first `.deb` was unstripped** (8.4 MB binary) and shipped a `/var/run` directory.
- **Severity depends on who you ask.** For CVE-2026-42945 nginx.org says medium and NVD says 8.1 High.
- **A test flake that turned out to be my harness.** A back-to-back run once had 27 errors at the same time. 27 is the number of tests that share one fixture. The fixture asked the OS for a free port, released it, and only later ran `docker start`, so another container or the previous run could take the port in between. It was not nginx and not the image. The fixture now uses a different port for every container in a session, retries startup up to three times with fresh ports and a fresh name, and removes leftover test containers first (so never run two suites at once). I explained it from the code and the error count; I did not reproduce the race on purpose.
- **Docker once left my zlib fix out of the image, and CI caught it.** On GitHub Actions one run in two of the same commit failed three zlib tests: the image had the original `libz`. The build log was fine (patch applied, package installed). I downloaded the image artifacts of the good and the bad run and compared their layers. The good image had a second `libz.so.1.2.13` with my patched hash. In the bad one the zlib layer had 20 files instead of 29 to 34, and the library and `md5sums` were missing. My rebuilt library has the same size and, because Debian clamps file times to the changelog date, the same time as the original. Docker's own layer diff code compares metadata (it never reads content), so a changed file that looks the same can be skipped. That matches what I saw, but I did not confirm which code path the runner used, so I call it strongly supported, not proven. The fix is a fixed, later `SOURCE_DATE_EPOCH` in `build/build-zlib.sh`, so the rebuilt files never have the baseline's time. Before the fix 2 of 6 CI runs failed; after it 0 of 9. My tests caught it; the build alone did not. It only showed up on a second Docker setup, which is the reason for the CI workflow.
- **What I would do differently:** write the tests as I build, not at the end (I changed to this halfway through, after noticing I had scheduled them last), and pin every apt version from the first build instead of after the first drift.

## AI tools used

I used Claude Code (Sonnet 5.5) with four project agents defined in `.claude/agents/`: a product-manager (scope and acceptance criteria), a packaging-expert (build details), a security-reviewer (scan triage and review) and a test-agent (the pytest suite). The main assistant did the hands-on build with me, step by step, and the reviewers checked each step.

I also used Gemini in Antigravity as a separate, read-only study and review companion. It did not touch the repo. I used it to go through the work by hand, ask questions in areas I did not know, and learn them (for example how Debian handles security fixes in an older release). It is where I checked my own understanding of the README before relying on it.

Where it helped:
- test-agent found the reliable crash trigger for CVE-2026-9256 and the missing `maintainer` label.
- security-reviewer verified that the patches are byte-identical to upstream, and recomputed my scan numbers from the raw JSON.
- Having the same assistant explain each step as it built made me understand the pieces: `dpkg`, conffiles, the snapshot repositories, and how scanners match.

Where it hurt:
- It stated a wrong "expected" output for the 42945 test and a 30-character crash URL that did not crash anything. I caught both by running them.
- A subagent report said removing curl dropped "about 40" rows. The real number is 104 per scanner, and I only found out by counting.
- I once believed Grype showed the same maintainer effect as Trivy; the reviewer checked and it does not.

The rule I took from this: every number or claim in this README comes from a command I ran or a file in `reports/`, not from a summary.
