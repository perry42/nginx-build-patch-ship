# Roadmap: how I did this, and what I would do next

The short version for a reader in a hurry. Every number here comes from a file in `reports/` or a test in `test/`; the README has the detail.

## In 30 seconds

I rebuilt `nginx:1.25-bookworm` from source on the same pinned Debian, so it is a drop-in replacement, and fixed four CVEs in it:

| Fix | CVE | How |
|---|---|---|
| libssl3 and openssl 3.0.11 to 3.0.22 | many, including the Critical CVE-2026-31789 | **Bump** (Debian ships the fix) |
| nginx rewrite module | CVE-2026-42945, CVE-2026-9256 | **Backport** of the upstream commits, unchanged |
| zlib 1.2.13 | CVE-2026-27171 | **Backport**, hand-ported (Debian's source is older than upstream's patch) |

Removing packages is not counted as a fix. The image is 179 MB against 276 MB, mostly from removal, and I say so in the README.

## How I proved it, not just claimed it

- **79 tests** boot both images and compare status, headers and body. Eight fail on the original on purpose: the fix tests and the documented differences. A fix test has to fail on the original first, or it proves nothing.
- **`make verify`** (about 3 minutes) re-runs only the fix tests twice, once against the original and once against mine, and fails if the original passes.
- **Scans:** Trivy and Grype, databases frozen for the run. Trivy 955 to 365 rows, Grype 889 to 345. A VEX file (`vex.json`) removes exactly one more row in each scanner, the zlib one.
- **Reproducible build:** `make repro` builds both `.deb` files from scratch and checks their hashes. They match on my laptop and on a GitHub runner.
- **CI** builds once, then runs the tests, `make verify` and the reproducibility check in parallel (plus the scans weekly).

## Order of work, and why

1. **Baseline first.** Pulled the image, pinned its digest, saved the Trivy and Grype reports. I measured before choosing anything.
2. **Triage.** Sorted CVEs into bump, backport or out of scope. Picked ones with different techniques, a real fix, and something I can test.
3. **Build from source.** My own script: pinned tarball hash, the baseline's configure flags, a hand-built `.deb`.
4. **Drop-in image.** Same Debian 12.5 base, user 101, entrypoint, ports, log symlinks, the files the package ships.
5. **Tests as I went**, not at the end (I changed to this halfway through).
6. **Rescan and VEX.** Scanners match version strings, so a backport needs a VEX statement to disappear from a scan.
7. **Verify, CI, reproducible builds.** Added at the end, because each one caught something (below).

## What went wrong, and what I learned

- **Two proofs of concept passed on the unpatched build.** One was missing a macro. Lesson: every fix test must fail on the original first.
- **apt silently upgraded pcre2.** Lesson: pin versions and diff the package list against the baseline.
- **A flaky test run (27 errors at once)** was my harness, not nginx: a host port taken between "find a free port" and "start the container".
- **Docker once left my zlib fix out of the image on GitHub Actions.** The fixed library had the same size and file time as the original, and Docker compares only that. I found it by comparing the image layers of a good and a bad run. Before the fix 2 of 6 CI runs failed, after it 0 of 9. This only showed up on a second Docker setup.
- **My scan numbers drifted** because the databases updated mid-run, and Grype never stored its database in the cache volume. Now one update per run, then frozen.
- **The `.deb` was not reproducible**, first because of build times, then because config files carried each checkout's time. Fixed with a fixed date on every file; checked on two machines.

## How I used AI agents

Claude Code (Sonnet 5.5) with four agents, defined in [`.claude/agents/`](.claude/agents/):

- **product-manager**: scope and acceptance criteria.
- **packaging-expert**: build script, patches, Containerfile, Makefile.
- **security-reviewer**: scans, triage, VEX, residual risk.
- **test-agent**: the pytest parity suite.

The flow: product-manager sets the criteria, packaging-expert builds, then test-agent and security-reviewer check it in parallel, and the builder fixes what they find. The agents never merge or push; I decide and merge. Two rules I gave them: numbers must come from a command, not a summary, and a failing test is reported, never weakened. They also got things wrong (for example "about 40 curl rows" when the real number was 104), and I caught that by counting. `docs/future-ai-remediation-pipeline.md` is the spec for how I would turn this into a repeatable pipeline; it is an idea, not implemented.

## What remains, and what I would do next

- **Open risk:** six libssl3 CVEs with no Debian fix; 36 more nginx advisories (I fixed two); nginx 1.25.5 is end of life, so the real fix is a supported release, which the brief rules out.
- **Unsigned:** the source package, the PGP signatures and `vex.json`. The build depends on `snapshot.debian.org`.
- **Next, in order:** more library bumps one at a time (libc6, pcre2, gnutls, systemd libraries, liblzma, tzdata); more nginx backports; sign the image and VEX with cosign and add an SBOM; a nightly rescan that opens an issue; try another CPU architecture for the reproducible build.
