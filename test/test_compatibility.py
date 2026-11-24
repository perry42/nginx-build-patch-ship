"""Parity suite: original nginx image vs our patched image.

"Working correctly" means: for the same request, the patched image returns the
same status code, the same headers and the same body as the original, and it
never crashes. The only allowed differences are the documented security fixes,
marked `expected_diff`; those tests assert the exact old and new behaviour and
FAIL if both images behave the same (i.e. the patch is missing).

Env: ORIGINAL_IMAGE (default nginx:1.25-bookworm), PATCHED_IMAGE (required,
tests skip without it). Run: pytest test/ -v

Covered: rewrite last/break/redirect/permanent, captures, literal '?',
trailing '?', malformed %-escape (400), CVE-2026-42945 and CVE-2026-9256;
large bodies (5 MB accepted, over client_max_body_size -> 413, per-location
limit); raw-socket malformed requests (bad method, long request line, missing
Host, invalid header, bare LF, garbage) compared by status line + headers;
custom config (server_tokens off, add_header, return/location mix, named
vhost); TLS (listen 443 ssl, self-signed cert generated at test time; same
response on both, negotiated protocol/cipher compared and printed).
test_image.py (real image, stock default config and entrypoint): `/`, `/missing`,
`/50x.html`; entrypoint startup log lines; mounted conf.d; envsubst templates;
docker inspect Config; file layout/mode/owner/content; log symlinks, `id nginx`;
graceful `docker stop` (exit 0, < 10 s). Its documented diffs (PKG_RELEASE,
missing NJS_* env, missing maintainer label, ignored ETag/Last-Modified on
static files) are listed in that module's docstring.
Not covered: HTTP/2, proxying, gzip, reload/signal handling beyond SIGQUIT stop,
runtime access/error log content.

Intended differences on malformed requests: none; both must match exactly.

Header comparison ignores only `Date` (changes every second); everything else,
including Server and Content-Length, must match.
"""
import socket
import ssl
import time

import pytest
import requests

IGNORED_HEADERS = {"date"}


def fetch(server, raw_path, method="GET"):
    """Send raw_path exactly as given (no re-encoding by requests)."""
    req = requests.Request(method, server.base + "/").prepare()
    req.url = server.base + raw_path
    with requests.Session() as s:
        return s.send(req, allow_redirects=False, timeout=5)


def norm(resp):
    headers = {k.lower(): v for k, v in resp.headers.items() if k.lower() not in IGNORED_HEADERS}
    return resp.status_code, headers, resp.content


def assert_parity(pair, path):
    orig, patched = pair
    a, b = norm(fetch(orig, path)), norm(fetch(patched, path))
    assert a == b, f"mismatch for {path}\noriginal: {a}\npatched:  {b}"
    return a


PARITY_PATHS = [
    "/",
    "/a/xyz",
    "/last/foo/bar",
    "/brk/foo?x=1",
    "/redir/a%20b",
    "/redir/a%26b",
    "/perm/a%20b%26c",
    "/setret/hello",
    "/ifre/captured",
    "/lit/anything",
    "/trail/abc",
]


@pytest.mark.parametrize("path", PARITY_PATHS)
def test_rewrite_parity(rewrite_pair, path):
    status, _, _ = assert_parity(rewrite_pair, path)
    assert status < 500


@pytest.mark.parametrize("path", ["/a/%00"])
def test_malformed_percent_is_400_on_both(rewrite_pair, path):
    for srv in rewrite_pair:
        assert fetch(srv, path).status_code == 400
    assert_parity(rewrite_pair, path)


@pytest.mark.expected_diff
def test_cve_2026_42945_capture_unescaping_differs(rewrite_pair):
    """Intended difference (CVE-2026-42945): with '?' in the rewrite replacement
    the original mishandles the escaped capture (truncated, still escaped);
    the patched image yields the correctly unescaped value. Fails if equal."""
    orig, patched = rewrite_pair
    path = "/a/x%20y%26z%2Fq"
    o = fetch(orig, path).text.strip()
    p = fetch(patched, path).text.strip()
    assert o == "myvar=[/a/x%20y%2]", f"original: {o}"
    assert p == "myvar=[/a/x y&z/q]", f"patched: {p}"
    assert o != p, "original == patched: patch missing"


@pytest.mark.expected_diff
def test_cve_2026_9256_overlapping_captures(crash_pair):
    """Intended difference (CVE-2026-9256): overlapping captures in a rewrite to
    an absolute URL overflow the buffer on the original (worker crash, dropped
    connection or truncated Location). Patched must return the full Location
    and never log `exited on signal`. Fails if original behaves like patched."""
    orig, patched = crash_pair
    path = "/" + "+" * 3000

    r = fetch(patched, path)
    assert r.status_code < 500
    if "Location" in r.headers:
        assert len(r.headers["Location"]) >= 3000
    assert "exited on signal" not in patched.logs()

    broken = 0
    for _ in range(3):
        try:
            ro = fetch(orig, path)
        except requests.ConnectionError:
            broken += 1
            continue
        loc = ro.headers.get("Location")
        if loc is None or len(loc) < 3000 or ro.status_code >= 500:
            broken += 1
    assert broken > 0, "original showed no crash/truncation: patch missing or PoC ineffective"


def test_liveness_after_crash_request(crash_pair):
    """Both images still serve after the crash PoC (master respawns workers)."""
    path = "/" + "+" * 3000
    for srv in crash_pair:
        try:
            fetch(srv, path)
        except requests.RequestException:
            pass
        ok = None
        for _ in range(10):
            try:
                ok = fetch(srv, "/ok")
                break
            except requests.RequestException:
                time.sleep(0.3)
        assert ok is not None and ok.status_code == 200 and ok.text == "alive"

