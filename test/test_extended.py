"""Extended parity tests: large bodies, malformed raw requests, custom config, TLS.

Same rules as test_compatibility.py (see its docstring): identical status,
headers (except Date) and body on original and patched. No intended differences
exist in this module; any mismatch is a regression.

Covered here:
  * large bodies: 5 MB accepted (200), 9 MB over client_max_body_size 8m (413),
    per-location limit (1k) both sides of the boundary.
  * malformed raw-socket requests (bad method, 10 KB request line, missing Host
    on HTTP/1.1, header without colon, header name with space, bare LF, TLS
    bytes sent to a plain port, bad HTTP version, duplicate Content-Length,
    Content-Length + Transfer-Encoding), compared by status line + headers;
    plus a liveness check afterwards.
  * custom config: second vhost with server_tokens off, add_header, exact /
    prefix / regex locations, 301, 403, 404, 410.
  * TLS: listen 443 ssl with a self-signed cert generated at test time;
    same response on both; negotiated protocol/cipher printed and compared.
"""
import socket
import ssl

import pytest
import requests

from test_compatibility import norm, fetch

CRLF = b"\r\n"


# ---------------------------------------------------------------- large bodies
def post(server, path, body):
    return requests.post(server.base + path, data=body, allow_redirects=False, timeout=30)


def test_large_body_5mb_parity(misc_pair):
    body = b"A" * (5 * 1024 * 1024)
    a, b = (norm(post(s, "/upload", body)) for s in misc_pair)
    assert a == b, f"orig {a[:2]} patched {b[:2]}"
    assert a[0] == 200 and a[2] == b"len=5242880\n"


def test_body_over_limit_is_413_on_both(misc_pair):
    body = b"A" * (9 * 1024 * 1024)  # server limit is 8m
    a, b = (norm(post(s, "/upload", body)) for s in misc_pair)
    assert a == b, f"orig {a[:2]} patched {b[:2]}"
    assert a[0] == 413


@pytest.mark.parametrize("size,want", [(512, 200), (4096, 413)])
def test_per_location_limit(misc_pair, size, want):
    a, b = (norm(post(s, "/small", b"x" * size)) for s in misc_pair)
    assert a == b and a[0] == want, f"size {size}: {a[:2]} vs {b[:2]}"


# ------------------------------------------------------- malformed raw requests
def raw(server, payload, port=80):
    """Send raw bytes; return (status_line, headers without Date)."""
    with socket.create_connection(("127.0.0.1", server.ports[port]), timeout=5) as sk:
        sk.sendall(payload)
        data = b""
        try:
            while CRLF + CRLF not in data:
                chunk = sk.recv(65536)
                if not chunk:
                    break
                data += chunk
        except (ConnectionResetError, socket.timeout):
            pass
    lines = data.split(CRLF + CRLF, 1)[0].decode("latin-1").split("\r\n")
    hdrs = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(":")
        if k.lower() != "date":
            hdrs[k.lower()] = v.strip()
    return lines[0], hdrs


def req(first, *headers, body=b"", eol=CRLF):
    head = eol.join([first.encode(), *[h.encode() for h in headers]])
    return head + eol + eol + body


MALFORMED = {
    "bad_method": req("GETX / HTTP/1.1", "Host: x", "Connection: close"),
    "long_request_line": req("GET /" + "a" * 10000 + " HTTP/1.1", "Host: x", "Connection: close"),
    "missing_host_http11": req("GET / HTTP/1.1", "Connection: close"),
    "invalid_header_no_colon": req("GET / HTTP/1.1", "Host: x", "BadHeader", "Connection: close"),
    "invalid_header_name": req("GET / HTTP/1.1", "Host: x", "Bad Header: v", "Connection: close"),
    "bare_lf": req("GET / HTTP/1.1", "Host: x", "Connection: close", eol=b"\n"),
    "garbage": bytes([0x16, 0x03, 0x01, 0x00, 0xFF, 0x01]) + b"garbage" + CRLF + CRLF,
    "bad_version": req("GET / HTTP/9.9", "Host: x", "Connection: close"),
    "dup_content_length": req("POST / HTTP/1.1", "Host: x", "Content-Length: 1",
                              "Content-Length: 2", "Connection: close", body=b"ab"),
    "cl_and_te": req("POST / HTTP/1.1", "Host: x", "Content-Length: 4",
                     "Transfer-Encoding: chunked", "Connection: close", body=b"0\r\n\r\n"),
}


@pytest.mark.parametrize("name", sorted(MALFORMED))
def test_malformed_raw_parity(misc_pair, name):
    a, b = (raw(s, MALFORMED[name]) for s in misc_pair)
    assert a == b, f"{name}\norig:    {a}\npatched: {b}"


@pytest.mark.parametrize("name", ["invalid_header_name", "garbage", "dup_content_length", "cl_and_te"])
def test_malformed_is_400(misc_pair, name):
    """(bad_method / header-without-colon / missing Host are accepted by nginx, 200 on both.)
    Guard against 'equal because both empty': these must be a real 400."""
    for s in misc_pair:
        status, _ = raw(s, MALFORMED[name])
        assert " 400 " in status, f"{name} on {s.image}: {status!r}"


def test_alive_after_malformed(misc_pair):
    for s in misc_pair:
        for payload in MALFORMED.values():
            raw(s, payload)
        assert fetch(s, "/ok").text == "alive"


# ------------------------------------------------------------- custom config
def vhost_get(server, path):
    r = requests.get(f"http://127.0.0.1:{server.ports[8081]}{path}",
                     headers={"Host": "custom.test"}, allow_redirects=False, timeout=5)
    return r


@pytest.mark.parametrize("path", ["/exact", "/prefix/a/b", "/x.php", "/moved", "/gone", "/nope", "/ok"])
def test_custom_vhost_parity(misc_pair, path):
    a, b = (norm(vhost_get(s, path)) for s in misc_pair)
    assert a == b, f"{path}\norig:    {a}\npatched: {b}"


def test_custom_headers_and_server_tokens(misc_pair):
    for s in misc_pair:
        r = vhost_get(s, "/exact")
        assert r.headers["Server"] == "nginx"  # server_tokens off: no version
        assert r.headers["X-Loc"] == "exact"
        # add_header in a location replaces (not merges with) server-level ones
        assert "X-Echo-Test" not in r.headers
        assert vhost_get(s, "/nope").headers["X-Echo-Test"] == "custom"
        assert vhost_get(s, "/gone").status_code == 410
    # default vhost still advertises the version on both (parity covered elsewhere)
    assert requests.get(misc_pair[1].base + "/", timeout=5).headers["Server"] == "nginx/1.25.5"


# ----------------------------------------------------------------------- TLS
def tls_info(server):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", server.ports[443]), timeout=5) as sk:
        with ctx.wrap_socket(sk, server_hostname="localhost") as t:
            return t.version(), t.cipher()


def test_tls_response_parity(tls_pair):
    res = [norm(requests.get(f"https://127.0.0.1:{s.ports[443]}/", verify=False, timeout=5))
           for s in tls_pair]
    assert res[0] == res[1], f"orig {res[0]}\npatched {res[1]}"
    assert res[0][0] == 200 and res[0][2] == b"tls root\n"


def test_tls_negotiation(tls_pair, capsys):
    """Informational print of protocol/cipher; also asserts they match, since a
    difference would signal an OpenSSL behaviour change worth documenting."""
    a, b = tls_info(tls_pair[0]), tls_info(tls_pair[1])
    with capsys.disabled():
        print(f"\n[tls] original={a} patched={b}")
    assert a[0] == b[0] == "TLSv1.3"
    assert a == b
