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

    def __init__(self, image, conf, tag):
        self.image = image
        self.name = f"echo-test-{tag}-{uuid.uuid4().hex[:8]}"
        self.port = _free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        _docker("create", "--name", self.name, "-p", f"{self.port}:80", image)
        try:
            _docker("cp", os.path.join(FIXTURES, conf), f"{self.name}:/etc/nginx/nginx.conf")
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


def _pair(conf, tag):
    servers = []
    try:
        for role, img in (("orig", ORIGINAL), ("patched", PATCHED)):
            servers.append(Server(img, conf, f"{tag}-{role}"))
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
