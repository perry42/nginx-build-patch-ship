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
import re
import subprocess
import time
import uuid

import pytest
import requests

from conftest import ORIGINAL, PATCHED, FIXTURES, _docker, _unique_port, _need_patched  # noqa: F401

STATIC_IGNORED = {"date", "etag", "last-modified"}
ENTRYPOINT_PATHS = ["/etc/nginx", "/usr/share/nginx/html", "/docker-entrypoint.d",
                    "/var/log/nginx", "/docker-entrypoint.sh"]


class Real:
    """Container started with the image's own config and entrypoint."""

    def __init__(self, image, tag, files=(), env=(), extra_ports=(), cmd=()):
        self.image = image
        last = None
        for attempt in range(3):  # fresh ports and name on each retry (port race)
            self.name = f"echo-test-{tag}-{uuid.uuid4().hex[:8]}"
            self.port = _unique_port()
            self.ports = {80: self.port}
            args = ["-p", f"{self.port}:80"]
            for cp in extra_ports:
                self.ports[cp] = _unique_port()
                args += ["-p", f"{self.ports[cp]}:{cp}"]
            for e in env:
                args += ["-e", e]
            try:
                _docker("create", "--name", self.name, *args, image, *cmd)
                for src, dst in files:
                    _docker("cp", src, f"{self.name}:{dst}")
                _docker("start", self.name)
                self._wait()
                return
            except BaseException as e:
                self.stop()
                if not isinstance(e, Exception):
                    raise
                last = e
                time.sleep(1)
        raise RuntimeError(f"{tag}: container failed to start after 3 attempts: {last}")

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


# 8. extra package files (nginx-debug, init, logrotate, systemd) -------------
EXTRA_FILES = ["/usr/sbin/nginx-debug", "/etc/default/nginx", "/etc/default/nginx-debug",
               "/etc/init.d/nginx", "/etc/init.d/nginx-debug", "/etc/logrotate.d/nginx",
               "/lib/systemd/system/nginx.service", "/lib/systemd/system/nginx-debug.service"]


def test_extra_files_mode_owner_md5(_need_patched):
    script = "for f in " + " ".join(EXTRA_FILES) + r"""; do
  stat -L -c '%n|%a|%u|%g' "$f" || echo "$f|MISSING"
  case "$f" in */sbin/*) ;; *) md5sum "$f" 2>&1;; esac; done"""
    # The nginx-debug binary is compiled from source, so its md5 cannot match the
    # baseline's binary; mode/uid/gid are compared, content is covered by -V and serving tests.
    a, b = _sh(ORIGINAL, script), _sh(PATCHED, script)
    assert "MISSING" not in a, a
    assert a == b, "extra files differ:\n" + "\n".join(sorted(set(a.splitlines()) ^ set(b.splitlines())))


def test_dpkg_conffiles_identical(_need_patched):
    script = "dpkg-query -W -f='${Conffiles}' nginx | sed 's/^ //' | sort"
    a, b = _sh(ORIGINAL, script), _sh(PATCHED, script)
    assert len(a.splitlines()) >= 5, a
    for f in EXTRA_FILES[1:6]:
        assert f in a, f"{f} not a conffile in original"
    assert a == b, "conffiles differ:\n" + "\n".join(sorted(set(a.splitlines()) ^ set(b.splitlines())))


def _configure_args(image, binary):
    out = _docker("run", "--rm", "--entrypoint", binary, image, "-V").stderr
    m = re.search(r"configure arguments: (.*)", out)
    assert m, out
    return out, m.group(1)


def test_nginx_debug_version_and_configure_args(_need_patched):
    for img in (ORIGINAL, PATCHED):
        out_n, args_n = _configure_args(img, "nginx")
        out_d, args_d = _configure_args(img, "nginx-debug")
        assert "--with-debug" in out_d, (img, out_d)
        assert out_d.splitlines()[0] == out_n.splitlines()[0], img  # version line
        strip = lambda x: re.sub(r"\s*-ffile-prefix-map=\S+", "", x)
        # nginx-debug = nginx args + --with-debug (same as upstream packaging)
        a = strip(args_d).replace(" --with-debug", "")
        assert a == strip(args_n), f"{img}\nnginx: {strip(args_n)}\ndebug-stripped: {a}"
        assert "--with-debug" not in args_n, img


def test_nginx_debug_configure_args_parity(_need_patched):
    strip = lambda x: re.sub(r"\s*-ffile-prefix-map=\S+", "", x)
    for binary in ("nginx", "nginx-debug"):
        a, b = (strip(_configure_args(i, binary)[1]) for i in (ORIGINAL, PATCHED))
        assert a == b, f"{binary}\norig:    {a}\npatched: {b}"


@pytest.fixture(scope="module")
def debug_pair(_need_patched):
    servers = []
    try:
        for role, img in (("orig", ORIGINAL), ("patched", PATCHED)):
            servers.append(Real(img, f"dbg-{role}", cmd=("nginx-debug", "-g", "daemon off;")))
        yield tuple(servers)
    finally:
        for s in servers:
            s.stop()


def test_nginx_debug_serves_root(debug_pair):
    a, b = (_norm(requests.get(s.url("/"), timeout=5)) for s in debug_pair)
    assert a == b, f"orig {a}\npatched {b}"
    assert a[0] == 200 and b"Welcome to nginx!" in a[2]
    for s in debug_pair:
        ps = _docker("exec", s.name, "sh", "-c", "cat /proc/1/cmdline | tr '\\0' ' '").stdout
        assert "nginx-debug" in ps, ps


@pytest.mark.parametrize("binary", ["nginx", "nginx-debug"])
def test_config_test_succeeds(_need_patched, binary):
    for img in (ORIGINAL, PATCHED):
        r = _docker("run", "--rm", "--entrypoint", binary, img, "-t", check=False)
        assert r.returncode == 0, (img, binary, r.stderr)
        assert "test is successful" in r.stderr, (img, r.stderr)


PKG_SCRIPT = r"""dpkg -L nginx | grep -v -e '^/usr/share/doc' -e '^/usr/share/man' | sort -u |
while read -r f; do
  if [ -L "$f" ] || [ -f "$f" ]; then stat -c '%n|%F|%a|%u|%g|%N' "$f"; fi
done | sort"""


def test_package_file_set_identical(_need_patched):
    a, b = _sh(ORIGINAL, PKG_SCRIPT), _sh(PATCHED, PKG_SCRIPT)
    names = lambda x: {ln.split("|")[0] for ln in x.splitlines()}
    assert len(a.splitlines()) >= 15, a
    assert names(a) == names(b), "package file set differs:\n" + "\n".join(
        sorted(names(a) ^ names(b)))
    assert a == b, "package file type/mode/owner/link differs:\n" + "\n".join(
        sorted(set(a.splitlines()) ^ set(b.splitlines())))


def test_no_extra_files_in_ours(_need_patched):
    script = r"find /etc /usr/sbin /usr/lib/nginx /lib/systemd \( -type f -o -type l \) | sort"
    a, b = _sh(ORIGINAL, script), _sh(PATCHED, script)
    extra = sorted(set(b.splitlines()) - set(a.splitlines()))
    missing = sorted(set(a.splitlines()) - set(b.splitlines()))
    print("files only in ours:", extra, "\nfiles only in baseline:", missing)
    assert not extra, f"ours has files the baseline lacks: {extra}"


# 9. installed package set (guards the extra 20261123 security snapshot) ----------
# Packages the baseline has and ours deliberately lacks (56): curl and its
# dependency chain, and the four dynamic modules (geoip, image-filter, njs, xslt)
# with their libraries (fonts, libgd3, libxml2, libxslt, libgeoip, image codecs...).
# Built from a real `dpkg-query` diff of the two images; see README "Intended differences".
ALLOWED_MISSING = sorted("""
curl fontconfig-config fonts-dejavu-core libabsl20220623 libaom3 libavif15 libbrotli1
libbsd0 libcurl4 libdav1d6 libde265-0 libdeflate0 libedit2 libexpat1 libfontconfig1
libfreetype6 libgav1-1 libgd3 libgeoip1 libgssapi-krb5-2 libheif1 libicu72 libjbig0
libjpeg62-turbo libk5crypto3 libkeyutils1 libkrb5-3 libkrb5support0 libldap-2.5-0
liblerc4 libnghttp2-14 libnuma1 libpng16-16 libpsl5 librav1e0 librtmp1 libsasl2-2
libsasl2-modules-db libssh2-1 libsvtav1enc1 libtiff6 libwebp7 libx11-6 libx11-data
libx265-199 libxau6 libxcb1 libxdmcp6 libxml2 libxpm4 libxslt1.1 libyuv0
nginx-module-geoip nginx-module-image-filter nginx-module-njs nginx-module-xslt
""".split())
ALLOWED_VERSION_DIFF = {
    "libssl3": ("3.0.11-1~deb12u2", "3.0.22-1~deb12u2"),
    "openssl": ("3.0.11-1~deb12u2", "3.0.22-1~deb12u2"),
    "nginx": ("1.25.5-1~bookworm", "1.25.5-1~echo1"),
}


def _packages(image):
    out = _sh(image, "dpkg-query -W -f='${Package} ${Version}\n'")
    return dict(ln.split(" ", 1) for ln in out.splitlines() if ln.strip())


@pytest.mark.expected_diff
def test_installed_package_set(_need_patched):
    """Only libssl3/openssl/nginx differ in version, ours has nothing extra, and the
    missing packages are exactly ALLOWED_MISSING. (zlib1g: same version, different
    content, is covered by test_zlib.py, not here.)"""
    o, p = _packages(ORIGINAL), _packages(PATCHED)
    changed = {k: (o[k], p[k]) for k in o.keys() & p.keys() if o[k] != p[k]}
    extra = sorted(set(p) - set(o))
    missing = sorted(set(o) - set(p))
    diff = ("full diff\n  version changes: %s\n  only in ours: %s\n  only in baseline: %s\n"
            "  unexpected missing: %s\n  allowed but present/not missing: %s"
            % (changed, extra, missing, sorted(set(missing) - set(ALLOWED_MISSING)),
               sorted(set(ALLOWED_MISSING) - set(missing))))
    assert changed == ALLOWED_VERSION_DIFF, diff
    assert not extra, diff
    assert missing == ALLOWED_MISSING, diff
