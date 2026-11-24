# Echo: Build It, Patch It, Ship It

Take-home (PDF in repo root). Ship a drop-in replacement for `nginx:1.25-bookworm`, **built from source** on `debian:bookworm-slim`, with **>= 2 CVEs eliminated**: >= 1 by dependency/version bump, >= 1 by backporting an upstream patch. Removing components is an extra and does not count. Two well-fixed beats ten half-fixed.

**Deadline: 2026-11-25 (inclusive).** Plan and status: `ROADMAP.md`.

## Working style
- Mentor mode, not a black box. At every step, teach anything new (configure flags, patches, dpkg, OpenVEX, scanners): explain the why, then ask "Does this make sense, or want to dive in first?" After approval, execute that slice efficiently.
- Involve the user in every big decision (CVE choice, scope, tradeoffs, tooling) with a recommendation and the tradeoffs. Decide trivial things yourself.
- Every decision is recorded with its rationale (decision log) so the author can explain it.
- Chat in English. Deliverables (README, code, commits) in English. Any personal study notes are not ground truth.
- The baseline is exactly `nginx:1.25-bookworm` as named in the assignment; verify and pin its digest before relying on it.

## Model policy
Sonnet at most for all agents and implementation. Fable only for planning, only when the candidate asks, per session. Never change agent models on your own.

## Agents (`.claude/agents/`)
`product-manager` (scope, plan, DR, acceptance), `packaging-expert` (source, patches, .deb, Containerfile, Makefile), `security-reviewer` (scans, triage, VEX, residual risk), `test-agent` (pytest + requests parity suite).

## Deliverable layout
`build/` (Dockerfile or build.sh, `patches/CVE-*.patch`), `Containerfile`, `test/` (`test_compatibility.py`, `requirements.txt`), `Makefile`, `README.md` (build steps, image size old vs new, per-CVE table with evidence links, residual risk, surprises and AI usage), `vex.json`, `baseline-trivy.txt`, `baseline-grype.txt`.

## Drop-in criteria
Compare with `docker inspect nginx:1.25-bookworm` and the official docker-nginx Dockerfile: user (UID 101 `nginx`), workdir, port 80, Entrypoint and Cmd, Env, STOPSIGNAL, filesystem layout, logs symlinked to stdout/stderr.

## Test rules
Boot both images, send identical requests (root, custom config, large body, malformed), assert status + headers + body, exit non-zero on mismatch. Happy path must be identical; any intended difference on exploit or malformed requests must be documented.
