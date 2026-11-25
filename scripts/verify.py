#!/usr/bin/env python3
"""Check the claims about the fixes without reading the code (make verify).

Usage: python scripts/verify.py ORIGINAL_IMAGE PATCHED_IMAGE   (run from the repo root)

What it does, using only the standard library plus the docker and pytest that
`make test` already needs:
  1. image sizes (ours must not be larger than the original)
  2. the two nginx CVE tests: pass against our image (REAL run), and fail when
     the "patched" slot holds the original image (CONTROL run)
  3. the zlib CVE-2026-27171 proof of concept, same two runs
  4. libssl3 version in both images
  5. the saved VEX diff (reports/vex-diff.txt), printed as is

Exit codes: 0 all checks pass, 1 a check failed, 2 cannot run (no docker, image
missing, docker daemon stopped, pytest missing, timeout or Ctrl-C,
another test suite running).

Do not run this at the same time as `make test`: the test fixtures remove every
container named echo-test-*, so two runs would kill each other's containers.
"""
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent

# Test names (as pytest reports them) that must fail on the original image.
NGINX_TESTS = [
    "test/test_compatibility.py::test_cve_2026_42945_capture_unescaping_differs",
    "test/test_compatibility.py::test_cve_2026_9256_overlapping_captures",
]
ZLIB_TESTS = ["test/test_zlib.py::test_cve_2026_27171_poc"]
NGINX_NAMES = {"test_cve_2026_42945_capture_unescaping_differs",
               "test_cve_2026_9256_overlapping_captures"}
ZLIB_NAMES = {"test_cve_2026_27171_poc[c]", "test_cve_2026_27171_poc[g]"}
EXPECTED = NGINX_NAMES | ZLIB_NAMES

ENV = dict(os.environ, MSYS_NO_PATHCONV="1")
results = []  # (name, ok, detail)


def check(name, ok, detail):
    results.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}")


def docker(*args):
    return subprocess.run(["docker", *args], capture_output=True, text=True, env=ENV)


def die(msg):
    print(msg, file=sys.stderr)
    sys.exit(2)


def image_size(image):
    return int(docker("image", "inspect", "--format", "{{.Size}}", image).stdout.strip())


def libssl_version(image):
    r = docker("run", "--rm", "--entrypoint", "dpkg-query", image,
               "-W", "-f=${Version}", "libssl3")
    return r.stdout.strip() if r.returncode == 0 else f"error: {r.stderr.strip()[:80]}"


def cleanup_containers():
    ids = docker("ps", "-aq", "--filter", "name=echo-test-").stdout.split()
    if ids:
        docker("rm", "-f", *ids)


TAILS = {}  # label -> last lines of pytest output, printed when a check fails


def run_pytest(original, patched, tmp, label):
    """Run the selected tests; return {test name: (status, message)}.

    status is 'passed', 'failed' (junit <failure>), 'error' (junit <error>: fixture
    or setup problem) or 'skipped'. Exits 2 if pytest cannot run or is interrupted.
    """
    xml = Path(tmp) / f"{label}.xml"
    env = dict(ENV, ORIGINAL_IMAGE=original, PATCHED_IMAGE=patched)
    cmd = [sys.executable, "-m", "pytest", *NGINX_TESTS, *ZLIB_TESTS,
           "-q", "-p", "no:cacheprovider", f"--junitxml={xml}"]
    print(f"... {label} run: ORIGINAL_IMAGE={original} PATCHED_IMAGE={patched}", flush=True)
    try:
        proc = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True, timeout=1800)
    except subprocess.TimeoutExpired:
        cleanup_containers()
        die(f"pytest ({label} run) timed out after 1800 s; removed leftover echo-test-* containers")
    except KeyboardInterrupt:
        cleanup_containers()
        die(f"interrupted during the {label} run; removed leftover echo-test-* containers")
    tail = chr(10).join((proc.stdout + proc.stderr).strip().splitlines()[-30:])
    TAILS[label] = tail
    if not xml.exists():
        if "No module named" in tail or proc.returncode in (1, 2, 3, 4, 5):
            die(f"cannot run: pytest wrote no result file (is pytest/requests installed? "
                f"see test/requirements.txt). Output tail: {tail}")
        return {}
    out = {}
    for case in ET.parse(xml).getroot().iter("testcase"):
        fail, err = case.find("failure"), case.find("error")
        if fail is not None:
            out[case.get("name")] = ("failed", (fail.get("message") or fail.text or "").strip())
        elif err is not None:
            out[case.get("name")] = ("error", (err.get("message") or err.text or "").strip())
        elif case.find("skipped") is not None:
            out[case.get("name")] = ("skipped", "")
        else:
            out[case.get("name")] = ("passed", "")
    return out


def report_details(label, res):
    """Print every test that did not behave as hoped, with its message, plus the output tail."""
    print(f"    --- details of the {label} run ---")
    for name, (status, msg) in sorted(res.items()):
        print(f"    {name}: {status}" + (f": {msg[:400]}" if msg else ""))
    print("    last lines of pytest output:")
    for line in TAILS.get(label, "").splitlines():
        print(f"      {line}")


def main():
    if len(sys.argv) != 3 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0 if len(sys.argv) == 2 else 2)
    original, patched = sys.argv[1], sys.argv[2]
    if original.startswith("-") or patched.startswith("-"):
        die("image names must not start with '-'")

    try:
        if docker("info").returncode != 0:
            die("docker is installed but the daemon is not answering (is Docker Desktop running?)")
        for image in (original, patched):
            if docker("image", "inspect", image).returncode != 0:
                die(f"image {image} not found; run `make image` (and pull {original}) first")
        busy = docker("ps", "-aq", "--filter", "name=echo-test-").stdout.split()
    except FileNotFoundError:
        die("docker not found")
    if busy:
        die("echo-test-* containers exist: another test run may be active. "
            "Wait for it to finish (or remove them) and run again.")

    print("== 1. image size")
    so, sp = image_size(original), image_size(patched)
    # The README quotes the SIZE column of `docker image ls`; print that too, so the
    # numbers a reviewer sees match. The comparison itself uses the exact byte counts.
    shown = [docker("image", "ls", "--format", "{{.Size}}", i).stdout.strip() or "?" for i in (original, patched)]
    check("size", sp <= so,
          f"`docker image ls` says original {shown[0]}, ours {shown[1]}; "
          f"exact bytes: original {so / 1e6:.0f} MB, ours {sp / 1e6:.0f} MB")

    with tempfile.TemporaryDirectory(prefix="echo-verify-") as tmp:
        print("== 2/3. fix tests: REAL run (original vs ours), then CONTROL (original vs original)")
        real = run_pytest(original, patched, tmp, "real")
        control = run_pytest(original, original, tmp, "control")

    # Text that the control failure must contain, read from the assertions in test/:
    # test_compatibility.py asserts f"patched: {p}", test_zlib.py "patched did not return 0".
    # No text is required for 9256 (its assertions are about crashes and sizes).
    want = {"test_cve_2026_42945_capture_unescaping_differs": "patched",
            "test_cve_2026_27171_poc[c]": "did not return",
            "test_cve_2026_27171_poc[g]": "did not return"}
    bad = False
    for title, names in (("nginx CVE tests", NGINX_NAMES), ("zlib CVE-2026-27171 PoC", ZLIB_NAMES)):
        # a run that did not execute all four tests proves nothing, so it fails
        r_ok = set(real) == EXPECTED and all(real[n][0] == "passed" for n in names)
        c_ok = set(control) == EXPECTED and all(
            control[n][0] == "failed" and want.get(n, "") in control[n][1] for n in names)
        errs = [n for n in names if control.get(n, ("",))[0] == "error"]
        why = "original fails as expected"
        if not c_ok:
            why = ("original ERRORED in the control run (fixture/setup problem: " +
                   "; ".join(f"{n}: {control[n][1][:120]}" for n in errs) + ")") if errs else (
                  "original DOES NOT FAIL as expected (or run incomplete, or unexpected failure text)")
        check(title, r_ok and c_ok,
              f"ours {'pass' if r_ok else 'NOT passing'} ({len(names)} test(s)); {why}")
        bad = bad or not (r_ok and c_ok)
    if bad:
        report_details("real", real)
        report_details("control", control)
    if set(real) != EXPECTED or set(control) != EXPECTED:
        print(f"    ran {len(real)} test(s) in the real run and {len(control)} in the control, expected 4 each")
    if any(v[0] == "skipped" for v in real.values()):
        print("    some tests were skipped (PATCHED unset?)")

    print("== 4. libssl3")
    vo, vp = libssl_version(original), libssl_version(patched)
    check("libssl3", vo.startswith("3.0.11") and vp.startswith("3.0.22"),
          f"original {vo} (want 3.0.11*), ours {vp} (want 3.0.22*)")

    print("== 5. saved VEX diff (reports/vex-diff.txt, saved report from make vex, not recomputed)")
    vex = ROOT / "reports" / "vex-diff.txt"
    if vex.exists():
        text = vex.read_text(encoding="utf-8")
        print(text.rstrip())
        check("vex-diff", "CVE-2026-27171" in text and "zlib1g" in text,
              "report names CVE-2026-27171 on zlib1g" if "CVE-2026-27171" in text and "zlib1g" in text
              else "report does not mention CVE-2026-27171 and zlib1g")
    else:
        check("vex-diff", False, "reports/vex-diff.txt is missing")

    failed = [n for n, ok, _ in results if not ok]
    total = len(results)
    if failed:
        print(f"VERIFY: FAIL ({', '.join(failed)})")
        sys.exit(1)
    print(f"VERIFY: PASS ({total}/{total} checks)")


if __name__ == "__main__":
    main()
