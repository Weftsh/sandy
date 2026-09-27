"""Shared fixtures for the E2B compatibility suite.

The suite talks to a running Weft Sandboxes stack through the unmodified E2B
SDK, configured only with E2B_API_URL, E2B_DOMAIN and E2B_API_KEY (and, for
header routing, E2B_SANDBOX_URL). See scripts/dev-stack.sh.
"""
import json
import os
import ssl
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from e2b import Sandbox

RUN_ID = uuid.uuid4().hex[:8]


def http_client():
    """HTTP client for talking to the stack directly (not through the SDK).

    Environment proxies are ignored: the stack runs on this machine.
    """
    return httpx.Client(trust_env=False, verify=os.environ.get("SSL_CERT_FILE", True), timeout=30)


def admin(method, path, body=None):
    """Calls the Weft admin API with the development admin key."""
    with http_client() as client:
        resp = client.request(method, os.environ["E2B_API_URL"] + path, headers={"X-API-Key": os.environ["WEFT_ADMIN_KEY"]}, json=body)
    resp.raise_for_status()
    return resp.json() if resp.content else None


@pytest.fixture
def tag(request):
    """Metadata that identifies the sandboxes one test created."""
    return {"suite": "compat", "run": RUN_ID, "test": request.node.name[:60]}


@pytest.fixture
def sandbox(tag):
    sbx = Sandbox.create(metadata=tag, timeout=120)
    yield sbx
    Sandbox.kill(sbx.sandbox_id)


@pytest.fixture
def team_key():
    """A fresh team with its own API key and a way to set its egress policy."""
    created = admin("POST", "/weft/v1/teams", {"name": f"compat-{RUN_ID}-{uuid.uuid4().hex[:6]}"})
    team_id = created["team"]["teamId"]

    def set_policy(policy):
        admin("PUT", f"/weft/v1/teams/{team_id}/egress", policy)

    return created["apiKey"]["key"], set_policy


class _Echo(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="session")
def echo_server():
    """HTTPS upstream for echo.weft.test that returns the request headers.

    The development gateway resolves echo.weft.test to this server, so the
    egress tests need no internet access.
    """
    if "WEFT_DEV_ECHO_CERT" not in os.environ:
        pytest.skip("stack was not started by scripts/dev-stack.sh")
    server = ThreadingHTTPServer(("127.0.0.1", int(os.environ["WEFT_DEV_ECHO_PORT"])), _Echo)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.environ["WEFT_DEV_ECHO_CERT"], os.environ["WEFT_DEV_ECHO_KEY"])
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield "echo.weft.test"
    server.shutdown()
