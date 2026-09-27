"""Networking: user ports through the edge proxy, blocked envd internals,
deny-by-default egress, allowlists and the credential proxy."""
import json
import os
import time

import httpx
import pytest
from e2b import Sandbox

from conftest import admin, http_client

# Every outbound connection is intercepted, so any address works for names
# that only the egress gateway resolves (it routes by SNI and Host).
FAKE_IP = "203.0.113.10"


def edge_get(sbx, port, path="/", headers=None, method="GET"):
    """Requests a sandbox port through the edge proxy, like a browser would."""
    headers = dict(headers or {})
    base = os.environ.get("E2B_SANDBOX_URL")
    if base:
        headers.update({"E2b-Sandbox-Id": sbx.sandbox_id, "E2b-Sandbox-Port": str(port)})
        url = base.rstrip("/") + path
    else:
        url = f"https://{sbx.get_host(port)}{path}"
    with http_client() as client:
        return client.request(method, url, headers=headers)


def py(sbx, code, user=None):
    """Runs Python in the sandbox and returns the result without raising."""
    try:
        return sbx.commands.run(f"python3 -c {json.dumps(code)}", user=user, timeout=30)
    except Exception as e:  # CommandExitException carries the result
        return e


def test_user_port_is_reachable_through_the_edge(sandbox):
    sandbox.commands.run("mkdir -p /tmp/www && echo served > /tmp/www/index.html")
    sandbox.commands.run("cd /tmp/www && python3 -m http.server 8080 --bind 0.0.0.0", background=True)
    for _ in range(50):
        r = edge_get(sandbox, 8080, "/index.html")
        if r.status_code == 200:
            break
        time.sleep(0.2)
    assert r.status_code == 200 and r.text.strip() == "served"
    assert sandbox.get_host(8080).startswith(f"8080-{sandbox.sandbox_id}.")


def test_envd_internal_endpoints_are_not_reachable(sandbox):
    for method, path in [("POST", "/init"), ("POST", "/freeze"), ("POST", "/upgrade"), ("GET", "/envs"), ("POST", "/files/../init")]:
        r = edge_get(sandbox, 49983, path, method=method)
        assert r.status_code == 404, f"{method} {path} -> {r.status_code}"
    # The sandbox still works with its original token.
    assert sandbox.commands.run("echo intact").stdout.strip() == "intact"


def test_traffic_token_protects_user_ports(tag):
    sbx = Sandbox.create(metadata=tag, timeout=60, network={"allow_public_traffic": False})
    try:
        token = sbx.traffic_access_token
        assert token
        sbx.commands.run("python3 -m http.server 8081 --bind 0.0.0.0", background=True)
        time.sleep(1.5)
        assert edge_get(sbx, 8081).status_code == 403
        assert edge_get(sbx, 8081, headers={"e2b-traffic-access-token": token}).status_code == 200
    finally:
        sbx.kill()


def test_unknown_sandbox_answers_502():
    base = os.environ.get("E2B_SANDBOX_URL")
    with http_client() as client:
        if base:
            r = client.get(base + "/health", headers={"E2b-Sandbox-Id": "nosuchsandbox000000", "E2b-Sandbox-Port": "49983"})
        else:
            r = client.get(f"https://49983-nosuchsandbox000000.{os.environ['E2B_DOMAIN']}/health")
    assert r.status_code == 502


def test_egress_is_denied_by_default(sandbox):
    # No DNS answers for any name.
    r = py(sandbox, "import socket; socket.getaddrinfo('example.com', 443)")
    assert r.exit_code != 0 and "gaierror" in r.stderr
    # TCP to a public address carries no data.
    r = py(sandbox, "import ssl,socket; s=socket.create_connection(('93.184.215.14',443),timeout=5); ssl.create_default_context().wrap_socket(s, server_hostname='example.com')")
    assert r.exit_code != 0
    # The instance metadata service is unreachable.
    r = py(sandbox, "import urllib.request; print(urllib.request.urlopen('http://169.254.169.254/latest/meta-data/', timeout=5).status)")
    assert r.exit_code != 0
    # So is anything on the host, including the host agent's API.
    r = py(sandbox, "import socket; s=socket.create_connection(('169.254.0.22',5007),timeout=3); s.send(b'GET / HTTP/1.0\\r\\n\\r\\n'); print(s.recv(10))")
    assert r.exit_code != 0 or r.stdout.strip() in ("b''", "")


def test_allowlisted_host_works_over_tls_passthrough(team_key, echo_server, tag):
    key, set_policy = team_key
    set_policy({"allow": [{"host": echo_server, "ports": [443]}]})
    sbx = Sandbox.create(api_key=key, metadata=tag, timeout=60)
    try:
        sbx.files.write("/tmp/upstream-ca.pem", open(os.environ["WEFT_DEV_UPSTREAM_CA"]).read())
        sbx.commands.run(f"echo '{FAKE_IP} {echo_server}' >> /etc/hosts", user="root")
        r = py(sbx, f"import ssl,urllib.request; c=ssl.create_default_context(cafile='/tmp/upstream-ca.pem'); print(urllib.request.urlopen('https://{echo_server}/allowed', context=c, timeout=10).read().decode())")
        assert r.exit_code == 0, r.stderr
        assert json.loads(r.stdout)["path"] == "/allowed"
        # Other hosts stay blocked.
        r = py(sbx, "import socket; socket.getaddrinfo('example.com', 443)")
        assert r.exit_code != 0
    finally:
        sbx.kill()


def test_sdk_can_narrow_but_not_widen_team_policy(team_key, echo_server, tag):
    key, set_policy = team_key
    set_policy({"allow": [{"host": echo_server, "ports": [443]}]})
    sbx = Sandbox.create(api_key=key, metadata=tag, timeout=60, allow_internet_access=False)
    try:
        sbx.commands.run(f"echo '{FAKE_IP} {echo_server}' >> /etc/hosts", user="root")
        r = py(sbx, f"import ssl,socket; s=socket.create_connection(('{echo_server}',443),timeout=5); ssl._create_unverified_context().wrap_socket(s, server_hostname='{echo_server}')")
        assert r.exit_code != 0, "allow_internet_access=False must block even allowlisted hosts"
    finally:
        sbx.kill()
    with pytest.raises(Exception) as err:
        Sandbox.create(api_key=key, metadata=tag, network={"deny_out": ["0.0.0.0/0"], "allow_out": ["example.com"]})
    assert "not permitted" in str(err.value)


def test_credential_proxy_injects_secrets_the_sandbox_never_sees(team_key, echo_server, tag):
    key, set_policy = team_key
    set_policy(
        {
            "credentials": [
                {"host": echo_server, "header": "x-api-key", "secretId": "weft-dev-echo-secret", "format": "Key {{secret}}"}
            ]
        }
    )
    secret = os.environ["WEFT_DEV_ECHO_SECRET"]
    sbx = Sandbox.create(api_key=key, metadata=tag, timeout=60)
    try:
        sbx.commands.run(f"echo '{FAKE_IP} {echo_server}' >> /etc/hosts", user="root")
        # The sandbox trusts the gateway's CA through the system bundle.
        r = py(
            sbx,
            f"import urllib.request; req=urllib.request.Request('https://{echo_server}/headers', headers={{'x-api-key':'fake-from-sandbox'}}); print(urllib.request.urlopen(req, timeout=10).read().decode())",
        )
        assert r.exit_code == 0, r.stderr
        seen = json.loads(r.stdout)["headers"]
        assert seen["x-api-key"] == f"Key {secret}"
        # The secret is nowhere inside the sandbox.
        env = sbx.commands.run("env; cat /proc/*/environ 2>/dev/null | tr '\\0' '\\n'", user="root").stdout
        assert secret not in env
        grep = sbx.commands.run(f"grep -rIl -- '{secret}' /etc /home /root /tmp /usr/local /run 2>/dev/null || true", user="root")
        assert grep.stdout.strip() == ""
    finally:
        sbx.kill()


def test_egress_policy_admin_api_validates_input(team_key):
    _, set_policy = team_key
    with pytest.raises(httpx.HTTPStatusError):
        set_policy({"allow": [{"host": "*.com"}]})
    with pytest.raises(httpx.HTTPStatusError):
        set_policy({"credentials": [{"host": "a.com", "header": "Host", "secretId": "s"}]})
    admin("GET", "/weft/v1/teams")
