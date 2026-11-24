import os
import socket
import subprocess
import time
import uuid

import pytest
import requests

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
ORIGINAL = os.environ.get("ORIGINAL_IMAGE", "nginx:1.25-bookworm")
PATCHED = os.environ.get("PATCHED_IMAGE")


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _docker(*args, check=True):
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=check,
                          env={**os.environ, "MSYS_NO_PATHCONV": "1"})


class Server:
    """One nginx container with a fixture config copied in as nginx.conf."""

    def __init__(self, image, conf, tag, extra_ports=(), files=()):
        """extra_ports: container ports to publish too (host ports in self.ports).
        files: (host_path, container_path) pairs copied in before start."""
        self.image = image
        self.name = f"echo-test-{tag}-{uuid.uuid4().hex[:8]}"
        self.port = _free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self.ports = {80: self.port}
        args = ["-p", f"{self.port}:80"]
        for cp in extra_ports:
            self.ports[cp] = _free_port()
            args += ["-p", f"{self.ports[cp]}:{cp}"]
        _docker("create", "--name", self.name, *args, image)
        try:
            _docker("cp", os.path.join(FIXTURES, conf), f"{self.name}:/etc/nginx/nginx.conf")
            for src, dst in files:
                _docker("cp", src, f"{self.name}:{dst}")
            _docker("start", self.name)
            self._wait()
        except BaseException:
            self.stop()
            raise

    def _wait(self):
        end = time.time() + 30
        while time.time() < end:
            try:
                requests.get(self.base + "/ok", timeout=2)
                return
            except requests.RequestException:
                time.sleep(0.3)
        raise RuntimeError(f"{self.name} not ready:\n" + self.logs())

    def logs(self):
        r = _docker("logs", self.name, check=False)
        err = _docker("exec", self.name, "sh", "-c", "cat /tmp/*error.log 2>/dev/null", check=False)
        return r.stdout + r.stderr + err.stdout

    def stop(self):
        _docker("rm", "-f", self.name, check=False)


@pytest.fixture(scope="module")
def _need_patched():
    if not PATCHED:
        pytest.skip("PATCHED_IMAGE not set; set ORIGINAL_IMAGE/PATCHED_IMAGE to run parity tests")


def _pair(conf, tag, **kw):
    servers = []
    try:
        for role, img in (("orig", ORIGINAL), ("patched", PATCHED)):
            servers.append(Server(img, conf, f"{tag}-{role}", **kw))
        yield tuple(servers)
    finally:
        for s in servers:
            s.stop()


@pytest.fixture(scope="module")
def rewrite_pair(_need_patched):
    yield from _pair("parity-rewrite.conf", "rw")


@pytest.fixture(scope="module")
def crash_pair(_need_patched):
    yield from _pair("cve-2026-9256-container.conf", "c9256")


@pytest.fixture(scope="module")
def misc_pair(_need_patched):
    yield from _pair("parity-misc.conf", "misc", extra_ports=(8081,))


@pytest.fixture(scope="module")
def tls_certs(tmp_path_factory):
    """Self-signed cert generated at test time (no secrets committed)."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=2))
            .sign(key, hashes.SHA256()))
    d = tmp_path_factory.mktemp("certs")
    crt, k = d / "test.crt", d / "test.key"
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    k.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption()))
    return [(str(crt), "/etc/nginx/certs/test.crt"), (str(k), "/etc/nginx/certs/test.key")]


@pytest.fixture(scope="module")
def tls_pair(_need_patched, tls_certs):
    # docker cp needs the target dir to exist; copy the dir contents via a parent copy.
    yield from _pair("parity-tls.conf", "tls", extra_ports=(443,), files=_dir_files(tls_certs))


def _dir_files(certs):
    # Copy the whole cert dir to /etc/nginx/certs (creates the directory).
    import os as _os
    return [(_os.path.dirname(certs[0][0]), "/etc/nginx/certs")]
