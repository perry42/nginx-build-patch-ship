# Echo: Build It, Patch It, Ship It

Take-home (PDF in repo root). Ship a drop-in replacement for `nginx:1.25-bookworm`, **built from source** on `debian:bookworm-slim`, with **>= 2 CVEs eliminated**: >= 1 by dependency/version bump, >= 1 by backporting an upstream patch. Removing components is an extra and does not count. Two well-fixed beats ten half-fixed.

**Deadline: 2026-11-25 (inclusive).** Plan and status: `ROADMAP.md`.

## Working style
- Mentor mode, not a black box. At every step, teach anything new (configure flags, patches, dpkg, OpenVEX, scanners): explain the why, then ask "Does this make sense, or want to dive in first?" After approval, execute that slice efficiently.
- Involve the user in every big decision (CVE choice, scope, tradeoffs, tooling) with a recommendation and the tradeoffs. Decide trivial things yourself.
- Every decision is recorded with its rationale (decision log) so the author can explain it.
- Chat in English. Deliverables (README, code, commits) in English. Any personal study notes are not ground truth.
- The baseline is exactly `nginx:1.25-bookworm` as named in the assignment; verify and pin its digest before relying on it.

## Git workflow
- Never commit directly to `main`. Work on a branch per milestone (`feat/...`, `fix/...`, `test/...`, `docs/...`), commit as needed with Conventional Commits.
- Merge into `main` (no-fast-forward) only after the user approves. Ask first, every time.
- Never push without asking first.

## Model policy
Sonnet at most for all agents and implementation. Fable only for planning, only when the candidate asks, per session. Never change agent models on your own.

## Agents (`.claude/agents/`)
`product-manager` (scope, plan, DR, acceptance), `packaging-expert` (source, patches, .deb, Containerfile, Makefile), `security-reviewer` (scans, triage, VEX, residual risk), `test-agent` (pytest + requests parity suite).

### Agent flow
`product-manager` (scope, acceptance criteria) -> `packaging-expert` (builds) -> `test-agent` and `security-reviewer` in parallel (verify and review) -> back to `packaging-expert` for fixes -> repeat until both pass.
- Handoffs are explicit: each agent receives the previous one's output and acceptance criteria.
- The builder gives `test-agent` a list of the tests and checks it already ran, so tests are not duplicated. `test-agent` reads existing `test/` first and only adds what is missing.

## Brief checklist (from the assignment PDF; check every decision against this FIRST)
Rule: before proposing or deciding anything, check it against this list. Ask the user only about what the brief does not settle.
1. **Goal:** drop-in replacement for `nginx:1.25-bookworm`, >= 2 CVEs eliminated, using different techniques. Removal does not count.
2. **Bump:** >= 1 CVE fixed by bumping a dependency version (system library or upstream source).
3. **Backport:** >= 1 CVE fixed by backporting a patch from a newer upstream commit onto the version we ship.
4. **Baseline:** pull, scan with Trivy AND Grype, save `baseline-trivy.txt` / `baseline-grype.txt`.
5. **Triage:** for each CVE in the reports: binary or library, upstream fix and version, bump/backport/remove. Pick CVEs and write down why.
6. **Build:** our own script (Debian tooling allowed, own script preferred); fetch upstream source, apply patches, build the `.deb`; from clean `debian:bookworm-slim`, no pre-baked binaries; one command (Makefile or single script).
7. **Image:** install the `.deb` into a minimal Debian base; match layout, user, workdir, ports, entrypoint exactly.
8. **Rescan (bonus):** scan the fixed image, diff vs baseline; VEX for a backport-patched CVE; re-run with `--vex` to show the CVE disappear.
9. **Test:** Go or Python; boot original and ours as separate containers; same requests (root, custom config, large body, malformed...); assert status + headers + body; exit non-zero on mismatch; document what "working correctly" means and what is covered.
10. **Repo:** `build/` (script/Dockerfile + `patches/` named after each CVE), `Containerfile`, `test/` + `make test`, `README.md`.
11. **README:** build instructions; image size original vs new; per-CVE table (ID, severity, bump/backport/remove, evidence link); residual risk (what remains, why, next); surprises and what we would do differently; which AI tools were used and where they helped or hurt.
12. **Reminders:** a couple of CVEs end-to-end beats many; not production-grade; if stuck, write what was tried and move on.

## Deliverable layout
`build/` (Dockerfile or build.sh, `patches/CVE-*.patch`), `Containerfile`, `test/` (`test_compatibility.py`, `requirements.txt`), `Makefile`, `README.md` (build steps, image size old vs new, per-CVE table with evidence links, residual risk, surprises and AI usage), `vex.json`, `baseline-trivy.txt`, `baseline-grype.txt`.

## Drop-in criteria
Compare with `docker inspect nginx:1.25-bookworm` and the official docker-nginx Dockerfile: user (UID 101 `nginx`), workdir, port 80, Entrypoint and Cmd, Env, STOPSIGNAL, filesystem layout, logs symlinked to stdout/stderr.

## Base image rule
Our image must sit on the same Debian as the baseline: Debian 12.5, same base-files, libc6 and library versions. Build and runtime base is `debian:bookworm-20240513-slim`, with apt pointed at `snapshot.debian.org` dated 2024-05-13 so old versions (for example libssl3 3.0.11-1~deb12u2) are installable. Each fix (bump or backport) is then a real change against that same base. After every build, diff the package list (`dpkg -l`) of the baseline against ours and explain every difference.

## Test rules
Boot both images, send identical requests (root, custom config, large body, malformed), assert status + headers + body, exit non-zero on mismatch. Happy path must be identical; any intended difference on exploit or malformed requests must be documented.
