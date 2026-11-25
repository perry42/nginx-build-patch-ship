# Idea and spec: an AI-assisted CVE remediation pipeline

Status: **idea, not implemented.** This is what I would build next, based on what went wrong and right while doing this assignment by hand. Nothing here is claimed to exist in this repo today, except where it points at a file.

## Goal

Given an image like `nginx:1.25-bookworm`, find fixable CVEs, propose the smallest change that fixes each one (a bump or a backport), prove the fix with tests, and publish evidence. An AI drafts the changes. Tests and a human decide whether they ship.

The point is not "an AI patches things". The point is that every claim the AI makes is checked by something that cannot be talked into agreeing.

## What this assignment taught me (and what to automate against)

Each item below happened here, and each is a check the pipeline should do on purpose.

| What happened | Rule it becomes |
|---|---|
| My first expected output for the 42945 test was wrong. | Never accept an AI-written expected value. Run it against the unpatched build and the patched build, and record both. |
| My first PoC for 9256, and my first zlib PoC, did not reproduce the bug on the original. The zlib one silently passed a 32-bit int. | A fix test must fail on the unpatched build first (an expected-failure gate). A test that passes on both proves nothing. |
| apt silently upgraded pcre2 when I installed by name. | Pin exact versions, and diff the full package list against the baseline after every build. |
| Scanners never listed the nginx CVEs, and listed ours under a different maintainer than the baseline's. | Treat scanner output as evidence of what the scanner matched, not of what is fixed. Always pair a scan diff with a behavior test. |
| A backport leaves the version string unchanged, so the scanner keeps flagging it. | Generate a VEX statement from each backport patch, and rescan with `--vex` to show the row go away. |
| A subagent said curl removal dropped "about 40" rows. The real number was 104. | Numbers come from commands over raw scan JSON, never from a summary. |

## Pipeline stages and gates

```
detect -> triage -> propose -> prove -> review -> publish
                       ^                    |
                       +---- fix and retry -+
```

1. **Detect.** Scheduled scan of the baseline and of our image, with pinned scanner and database versions, saved as JSON. Output: the list of new fixable findings (CVE, package, fixed version).
2. **Triage.** Classify each CVE as bump, backport or out of scope, with the reason: is the package linked by the binary, is it reachable in the default config, does a Debian fix exist, does an upstream fix commit exist. A human approves the picks. Removal never counts as a fix.
3. **Propose.** The AI drafts one change per CVE:
   - Bump: an exact version pin and the snapshot it comes from.
   - Backport: the upstream commit. It must apply with `patch -p1 --fuzz=0`. If it does not apply, the AI may hand-port it, and the patch is then labelled as a hand-port with the upstream commit linked.
4. **Prove.** All of these must pass before review:
   - Build from a clean base, with the base pinned by digest.
   - A per-CVE test that fails on the unpatched build and passes on the patched one.
   - The parity suite, original against patched: status, headers and body.
   - Layout checks: user, workdir, ports, entrypoint, file modes and checksums, and an explained package diff.
   - Rescan: the bumped CVEs disappear on their own; the backported ones are listed with the VEX file applied.
5. **Review.** A second agent with a different job (it only reads and recomputes) checks numbers from raw JSON and checks that patches match upstream. A human reads the diff and merges. The AI never merges.
6. **Publish.** Tag, push the image, attach the evidence: scan diffs, the VEX document, an SBOM and the test report.

## Instructions for the AI (the "how to fix" document)

A short document the AI is given on every run:

- Never raise a version number to please a scanner. A backport keeps the version, and the claim goes in the VEX file.
- Never count removal as a fix.
- Never weaken or delete a test to make it pass. If a test fails, report it exactly.
- Every number or claim must cite the command or file it came from.
- Prefer the smallest change. Prefer the upstream commit byte-for-byte. Say plainly when a patch is a hand-port.
- Do not merge, push or tag. Stop at a pull request.
- If stuck, write down what was tried and move on.

## CI/CD that could run it

GitHub Actions is enough:

| Workflow | Trigger | Does |
|---|---|---|
| `pr.yml` | pull request | lint (`shellcheck`, `hadolint`), build the image, `make test`, scan both images, post the scan diff as a PR comment, fail if a fix test passes on the unpatched build |
| `nightly.yml` | schedule | rescan with a fresh database, open an issue with new fixable findings, optionally let the AI open a draft PR for the best candidate |
| `release.yml` | tag | build, push to GHCR, sign with cosign, attach SBOM (syft) and the VEX file |
| dependency updates | Renovate or Dependabot | proposes new base-image digests and scanner versions as PRs, each going through `pr.yml` |

Things to add for trust: `SOURCE_DATE_EPOCH` so the `.deb` is reproducible, a verified PGP signature for the upstream tarball, and a mirror of the snapshot packages so a build does not depend on one site being up.

## Risks

- The AI invents CVE data or a "fixed in" version. Mitigation: look it up in the raw advisory or the tracker, and have the reviewer agent do it again independently.
- Tests give a false pass. Mitigation: the fails-before-passes-after gate.
- Scanners disagree, or react to package metadata. Mitigation: report both and say so.
- A drafted patch is subtly wrong. Mitigation: prefer byte-identical upstream patches, and require a human to read every hand-port.
- Cost and noise from nightly runs. Mitigation: only draft a PR when there is a new fixable finding.

## Suggested first version (about a week)

1. A script that scans, diffs against the last run, and outputs the fixable list as JSON.
2. The fails-before-passes-after test harness, as a reusable fixture (the zlib PoC in `test/fixtures/zlib/` is the pattern).
3. `pr.yml` with build, tests and the scan diff.
4. The "instructions for the AI" file, and an agent that drafts exactly one bump or backport per run, ending at a pull request.

Later: nightly runs, signing and SBOM, and the VEX document generated from the patches.
