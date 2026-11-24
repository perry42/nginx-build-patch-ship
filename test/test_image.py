"""Real-image parity: default config, real entrypoint, drop-in metadata.

The other modules replace /etc/nginx/nginx.conf via `docker cp`, so they never
exercise the stock default.conf or /docker-entrypoint.sh. These tests boot both
images untouched (or with only an added conf.d / template file) and compare.

Intentional, documented differences (marked `expected_diff` where asserted):
  * Env PKG_RELEASE: `1~bookworm` (original) vs `1~echo1` (ours).
  * Env NJS_VERSION / NJS_RELEASE exist only in the original (njs module is not built).
  * Label `maintainer` exists only in the original.
  * Headers Date, ETag, Last-Modified are ignored in static-file responses:
    Date changes every second; ETag and Last-Modified derive from the mtime of
    the files in /usr/share/nginx/html, which differs per build. Bodies and
    Content-Length are still compared, so file content must match.
Everything else (status, all other headers, body, entrypoint log lines, user,
ports, entrypoint, cmd, stop signal, layout, modes, owners) must be identical.
"""
import json
import os
import subprocess
import time
import uuid

import pytest
import requests

from conftest import ORIGINAL, PATCHED, FIXTURES, _docker, _free_port, _need_patched  # noqa: F401

STATIC_IGNORED = {"date", "etag", "last-modified"}
ENTRYPOINT_PATHS = ["/etc/nginx", "/usr/share/nginx/html", "/docker-entrypoint.d",
                    "/var/log/nginx", "/docker-entrypoint.sh"]


class Real:
    """Container started with the image's own config and entrypoint."""

    def __init__(self, image, tag, files=(), env=(), extra_ports=()):
        self.image = image
        self.name = f"echo-test-{tag}-{uuid.uuid4().hex[:8]}"
        self.port = _free_port()
        self.ports = {80: self.port}
        args = ["-p", f"{self.port}:80"]
        for cp in extra_ports:
            self.ports[cp] = _free_port()
            args += ["-p", f"{self.ports[cp]}:{cp}"]
        for e in env:
            args += ["-e", e]
        _docker("create", "--name", self.name, *args, image)
        try:
            for src, dst in files:
                _docker("cp", src, f"{self.name}:{dst}")
            _docker("start", self.name)
            self._wait()
        except BaseException:
            self.stop()
            raise

    def url(self, path="/", port=80):
        return f"http://127.0.0.1:{self.ports[port]}{path}"

    def _wait(self):
        end = time.time() + 30
        while time.time() < end:
            try:
                requests.get(self.url(), timeout=2)
                return
            except requests.RequestException:
                time.sleep(0.3)
        raise RuntimeError(f"{self.name} not ready:\n" + self.logs())

    def logs(self):
        r = _docker("logs", self.name, check=False)
        return r.stdout + r.stderr

    def stop(self):
        _docker("rm", "-f", self.name, check=False)


def _pair(tag, **kw):
    servers = []
    try:
        for role, img in (("orig", ORIGINAL), ("patched", PATCHED)):
            servers.append(Real(img, f"{tag}-{role}", **kw))
        yield tuple(servers)
    finally:
        for s in servers:
            s.stop()


def _norm(resp, ignored=STATIC_IGNORED):
    return (resp.status_code,
            {k.lower(): v for k, v in resp.headers.items() if k.lower() not in ignored},
            resp.content)


@pytest.fixture(scope="module")
def default_pair(_need_patched):
    yield from _pair("def")


@pytest.fixture(scope="module")
def confd_pair(_need_patched, tmp_path_factory):
    f = tmp_path_factory.mktemp("confd") / "extra.conf"
    f.write_text('server {\n  listen 8081;\n  add_header X-Extra yes always;\n'
                 '  location /extra { return 200 "extra-ok\\n"; }\n'
                 '  location /moved { return 301 /extra; }\n}\n')
    yield from _pair("confd", extra_ports=(8081,), files=[(str(f), "/etc/nginx/conf.d/extra.conf")])


@pytest.fixture(scope="module")
def template_pair(_need_patched, tmp_path_factory):
    d = tmp_path_factory.mktemp("tpl")
    (d / "templates").mkdir()
    (d / "templates" / "x.conf.template").write_text(
        'server {\n  listen 8082;\n  location /env { return 200 "v=${VAR} host=$host\\n"; }\n}\n')
    yield from _pair("tpl", extra_ports=(8082,), env=["VAR=hello-envsubst"],
                     files=[(str(d / "templates"), "/etc/nginx/templates")])


# 1. default config ---------------------------------------------------------
@pytest.mark.parametrize("path,status", [("/", 200), ("/missing", 404), ("/50x.html", 200)])
def test_default_config_parity(default_pair, path, status):
    a, b = (_norm(requests.get(s.url(path), allow_redirects=False, timeout=5)) for s in default_pair)
    assert a == b, f"{path}\norig:    {a}\npatched: {b}"
    assert a[0] == status


def test_default_root_is_welcome_page(default_pair):
    for s in default_pair:
        r = requests.get(s.url("/"), timeout=5)
        assert "Welcome to nginx!" in r.text
        assert r.headers["Server"] == "nginx/1.25.5"


# 2. startup logs -----------------------------------------------------------
def _entrypoint_lines(srv):
    """Entrypoint script output = stdout lines that are not access-log entries.
    (nginx's own notices go to stderr with a timestamp and are not compared.)"""
    out = _docker("logs", srv.name, check=False).stdout.splitlines()
    return [ln for ln in out if ' HTTP/1.' not in ln]


def test_entrypoint_log_lines_identical(default_pair):
    a, b = (_entrypoint_lines(s) for s in default_pair)
    assert len(a) >= 8, f"too few entrypoint lines, wrong parsing? {a}"
    assert a == b, f"orig:\n" + "\n".join(a) + "\npatched:\n" + "\n".join(b)


# 3. mounted conf.d ---------------------------------------------------------
@pytest.mark.parametrize("path,status", [("/extra", 200), ("/moved", 301), ("/nope", 404)])
def test_confd_parity(confd_pair, path, status):
    a, b = (_norm(requests.get(s.url(path, 8081), allow_redirects=False, timeout=5), {"date"})
            for s in confd_pair)
    assert a == b, f"{path}\norig:    {a}\npatched: {b}"
    assert a[0] == status
    assert a[1].get("x-extra") == "yes"


def test_confd_does_not_break_default_server(confd_pair):
    a, b = (_norm(requests.get(s.url("/"), timeout=5)) for s in confd_pair)
    assert a == b and a[0] == 200


# 4. envsubst templates -----------------------------------------------------
def test_envsubst_template_parity(template_pair):
    a, b = (_norm(requests.get(s.url("/env", 8082), timeout=5), {"date"}) for s in template_pair)
    assert a == b, f"orig {a}\npatched {b}"
    assert a[2].startswith(b"v=hello-envsubst host=")  # ${VAR} substituted, $host left to nginx


def test_envsubst_log_line_identical(template_pair):
    a, b = (_entrypoint_lines(s) for s in template_pair)
    assert a == b
    assert any("x.conf.template to /etc/nginx/conf.d/x.conf" in ln for ln in a)


# 5. docker inspect ---------------------------------------------------------
def _config(image):
    return json.loads(_docker("inspect", image, "--format", "{{json .Config}}").stdout)


def test_inspect_config_parity(_need_patched):
    o, p = _config(ORIGINAL), _config(PATCHED)
    for key in ("User", "WorkingDir", "ExposedPorts", "Entrypoint", "Cmd", "StopSignal"):
        assert o.get(key) == p.get(key), f"{key}: {o.get(key)!r} vs {p.get(key)!r}"
    assert p["ExposedPorts"] == {"80/tcp": {}}
    assert p["Entrypoint"] == ["/docker-entrypoint.sh"]
    assert p["StopSignal"] == "SIGQUIT"


@pytest.mark.expected_diff
def test_inspect_env_documented_differences(_need_patched):
    """Intended: PKG_RELEASE value differs; NJS_VERSION/NJS_RELEASE missing in ours;
    nothing else may differ. Fails if the difference set changes."""
    def env(img):
        return dict(e.split("=", 1) for e in _config(img).get("Env") or [])
    o, p = env(ORIGINAL), env(PATCHED)
    changed = {k for k in o.keys() & p.keys() if o[k] != p[k]}
    assert changed == {"PKG_RELEASE"}, changed
    assert o["PKG_RELEASE"] == "1~bookworm" and p["PKG_RELEASE"] == "1~echo1"
    assert set(o) - set(p) == {"NJS_VERSION", "NJS_RELEASE"}
    assert set(p) - set(o) == set()


@pytest.mark.expected_diff
def test_inspect_label_documented_difference(_need_patched):
    """Intended: original carries the `maintainer` label, ours has none."""
    assert "maintainer" in (_config(ORIGINAL).get("Labels") or {})
    assert "maintainer" not in (_config(PATCHED).get("Labels") or {})


# 6. layout -----------------------------------------------------------------
def _sh(image, script):
    return _docker("run", "--rm", "--entrypoint", "sh", image, "-c", script).stdout


def test_layout_mode_owner_parity(_need_patched):
    script = ("find " + " ".join(ENTRYPOINT_PATHS) +
              r" -printf '%p|%y|%m|%u|%g|%l\n' | sort")
    a, b = _sh(ORIGINAL, script), _sh(PATCHED, script)
    assert len(a.splitlines()) > 15
    assert a == b, "layout differs:\n" + "\n".join(
        sorted(set(a.splitlines()) ^ set(b.splitlines())))


def test_log_symlinks_and_nginx_user(_need_patched):
    for img in (ORIGINAL, PATCHED):
        out = _sh(img, "readlink /var/log/nginx/access.log /var/log/nginx/error.log; id nginx")
        assert out.splitlines()[:2] == ["/dev/stdout", "/dev/stderr"], (img, out)
        assert out.splitlines()[2] == "uid=101(nginx) gid=101(nginx) groups=101(nginx)", (img, out)
    assert _sh(ORIGINAL, "id nginx") == _sh(PATCHED, "id nginx")


def test_config_file_contents_identical(_need_patched):
    script = "find /etc/nginx /docker-entrypoint.d /docker-entrypoint.sh /usr/share/nginx/html -type f -exec sha256sum {} + | sort -k2"
    a, b = _sh(ORIGINAL, script), _sh(PATCHED, script)
    assert a == b, "file content differs:\n" + "\n".join(
        sorted(set(a.splitlines()) ^ set(b.splitlines())))


# 7. graceful stop ----------------------------------------------------------
@pytest.mark.parametrize("which", ["orig", "patched"])
def test_graceful_stop(_need_patched, which):
    s = Real(ORIGINAL if which == "orig" else PATCHED, f"stop-{which}")
    try:
        t0 = time.time()
        _docker("stop", "-t", "10", s.name)
        took = time.time() - t0
        code = _docker("inspect", s.name, "--format", "{{.State.ExitCode}}").stdout.strip()
        assert code == "0", f"exit code {code} (SIGQUIT graceful shutdown expected)"
        assert took < 10, f"stop took {took:.1f}s (SIGKILL fallback?)"
    finally:
        s.stop()
