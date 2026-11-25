"""zlib1g parity: the patched image ships zlib1g rebuilt with a backport of CVE-2026-27171.

Intended differences (marked `expected_diff`):
  * libz.so.1.2.13 content differs while the dpkg version string is identical
    (same-version rebuild, see build/patches/zlib/CVE-2026-27171.patch).
  * crc32_combine64(1,2,-1) and crc32_combine_gen64(-1) hang on the original
    (timeout 5 -> exit 124) and return 0 immediately on ours.
Everything else must stay identical: nginx gzip / gzip_static output (status,
headers except Date/ETag/Last-Modified, raw compressed bytes, decompressed body).
"""
import gzip
import os
import random
import subprocess
import uuid

import pytest
import requests

from conftest import ORIGINAL, PATCHED, FIXTURES, Server, _docker, _need_patched, _pair  # noqa: F401

BUILD_BASE = ("debian:bookworm-20240513-slim@sha256:"
              "804194b909ef23fb995d9412c9378fb3505fe2427b70f3cc425339e48a828fca")
SNAP = "http://snapshot.debian.org/archive"
COMPILE = f"""set -e
cat > /etc/apt/sources.list <<'EOL'
deb [check-valid-until=no] {SNAP}/debian/20240513T000000Z bookworm main
deb [check-valid-until=no] {SNAP}/debian-security/20240513T000000Z bookworm-security main
EOL
rm -f /etc/apt/sources.list.d/*
apt-get -o Acquire::Check-Valid-Until=false update -qq
apt-get install -y -qq --no-install-recommends gcc libc6-dev zlib1g-dev >/dev/null
gcc -O1 -Wall -Werror=implicit-function-declaration -o /tmp/poc /tmp/poc.c -lz
"""
IGNORED = {"date", "etag", "last-modified"}
LIBZ = "/lib/x86_64-linux-gnu/libz.so.1"


@pytest.fixture(scope="session")
def poc_binary(tmp_path_factory):
    out = str(tmp_path_factory.mktemp("poc") / "poc")
    name = f"echo-test-pocbuild-{uuid.uuid4().hex[:8]}"
    _docker("create", "--name", name, "--entrypoint", "sh", BUILD_BASE, "-c", COMPILE)
    try:
        _docker("cp", os.path.join(FIXTURES, "zlib", "poc.c"), f"{name}:/tmp/poc.c")
        r = _docker("start", "-a", name, check=False)
        assert r.returncode == 0, f"PoC compile failed:\n{r.stdout}\n{r.stderr}"
        _docker("cp", f"{name}:/tmp/poc", out)
    finally:
        _docker("rm", "-f", name, check=False)
    return out


def run_poc(image, binary, mode):
    """Run the PoC under `timeout 5` inside `image`; return (exit code, stdout)."""
    name = f"echo-test-poc-{uuid.uuid4().hex[:8]}"
    _docker("create", "--name", name, "--entrypoint", "sh", image, "-c",
            f"chmod +x /tmp/poc; exec timeout 5 /tmp/poc {mode}")
    try:
        _docker("cp", binary, f"{name}:/tmp/poc")
        r = _docker("start", "-a", name, check=False)
        code = int(_docker("inspect", name, "--format", "{{.State.ExitCode}}").stdout.strip())
        return code, r.stdout.strip()
    finally:
        _docker("rm", "-f", name, check=False)


@pytest.mark.expected_diff
@pytest.mark.parametrize("mode", ["c", "g"])
def test_cve_2026_27171_poc(_need_patched, poc_binary, mode):
    """Original must really hang (124), otherwise the test proves nothing; ours returns 0."""
    o = run_poc(ORIGINAL, poc_binary, mode)
    p = run_poc(PATCHED, poc_binary, mode)
    assert o[0] == 124, f"original did not hang (mode {mode}): {o} - PoC is not exercising the bug"
    assert p[0] == 0 and p[1].endswith("= 0"), f"patched did not return 0 (mode {mode}): {p}"
    assert o != p


# ------------------------------------------------------------ package identity
def _libz_facts(image):
    script = (f"dpkg-query -W -f='${{Version}}\n' zlib1g; md5sum {LIBZ} | cut -d' ' -f1")
    ver, md5 = _docker("run", "--rm", "--entrypoint", "sh", image, "-c", script).stdout.split()
    return ver, md5


@pytest.mark.expected_diff
def test_zlib1g_same_version_different_binary(_need_patched):
    (ov, om), (pv, pm) = _libz_facts(ORIGINAL), _libz_facts(PATCHED)
    assert ov == pv == "1:1.2.13.dfsg-1", (ov, pv)
    assert om != pm, "libz.so.1 is byte-identical: backport not in the image"


# ---------------------------------------------------------------- gzip parity
@pytest.fixture(scope="module")
def gz_pair(_need_patched, tmp_path_factory):
    d = tmp_path_factory.mktemp("gz")
    rnd = random.Random(1234)
    words = [("w%d" % rnd.randrange(3000)) for _ in range(40000)]
    text = (" ".join(words) + "\n").encode()[:200_000]
    (d / "big.txt").write_bytes(text)
    (d / "static.txt").write_bytes(text)
    (d / "static.txt.gz").write_bytes(gzip.compress(text, 9, mtime=0))
    yield from _pair("parity-gzip.conf", "gz", files=[(str(d), "/srv/gz")])


def _get(s, path, enc):
    r = requests.get(s.base + path, headers={"Accept-Encoding": enc}, stream=True, timeout=10)
    raw = r.raw.read(decode_content=False)
    hdrs = {k.lower(): v for k, v in r.headers.items() if k.lower() not in IGNORED}
    return r.status_code, hdrs, raw


@pytest.mark.parametrize("path", ["/big.txt", "/static.txt"])
def test_gzip_parity(gz_pair, path):
    a, b = (_get(s, path, "gzip") for s in gz_pair)
    assert a[0] == 200 and a[1].get("content-encoding") == "gzip", a[:2]
    assert b[1].get("content-encoding") == "gzip", b[:2]
    assert a[1] == b[1], f"headers\norig: {a[1]}\npatched: {b[1]}"
    assert gzip.decompress(a[2]) == gzip.decompress(b[2])
    assert len(gzip.decompress(a[2])) >= 190_000
    assert len(a[2]) < 100_000, "body was not really compressed"
    assert a[2] == b[2], "compressed bytes differ (deflate output changed)"


def test_gzip_not_applied_without_accept_encoding(gz_pair):
    a, b = (_get(s, "/big.txt", "identity") for s in gz_pair)
    assert "content-encoding" not in a[1] and a == b
    assert len(a[2]) >= 190_000
