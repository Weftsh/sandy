import os
import uuid

import pytest
from e2b import Sandbox

FIRECRACKER = os.environ.get("WEFT_ESCAPE_RUNTIME") == "firecracker"


def pytest_configure(config):
    config.addinivalue_line("markers", "vm: needs the Firecracker runtime (a microVM boundary)")


def pytest_collection_modifyitems(config, items):
    if FIRECRACKER:
        return
    skip = pytest.mark.skip(reason="needs WEFT_ESCAPE_RUNTIME=firecracker")
    for item in items:
        if "vm" in item.keywords:
            item.add_marker(skip)


@pytest.fixture
def attacker():
    sbx = Sandbox.create(metadata={"suite": "escape"}, timeout=180)
    yield sbx
    Sandbox.kill(sbx.sandbox_id)


def run_py(sbx, code, user="root", timeout=60):
    """Runs a Python script as root in the sandbox; returns (exit_code, stdout, stderr)."""
    path = f"/tmp/escape-{uuid.uuid4().hex}.py"
    sbx.files.write(path, code)
    try:
        r = sbx.commands.run(f"python3 {path}", user=user, timeout=timeout)
    except Exception as e:
        r = e
    return r.exit_code, r.stdout, r.stderr
