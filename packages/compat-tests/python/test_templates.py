"""Custom templates built with the SDK's Template builder."""
import os
import uuid

import pytest
from e2b import Sandbox, Template
from e2b.exceptions import BuildException, TemplateException

from conftest import admin

IMAGE = os.environ.get("WEFT_DEV_IMAGE", "python:3.12-slim")


def test_build_from_image_with_env_and_workdir():
    name = f"compat-{uuid.uuid4().hex[:8]}"
    logs = []
    template = Template().from_image(IMAGE).set_envs({"COMPAT_TEMPLATE": "yes"}).set_workdir("/srv")
    info = Template.build(template, name, cpu_count=1, memory_mb=512, on_build_logs=logs.append)
    assert info.template_id
    assert logs, "the build streams log entries"

    sbx = Sandbox.create(template=name, timeout=60)
    try:
        result = sbx.commands.run("echo $COMPAT_TEMPLATE; pwd")
        assert result.stdout.split() == ["yes", "/srv"]
        assert sbx.get_info().template_id == info.template_id
    finally:
        sbx.kill()
        admin("DELETE", f"/weft/v1/templates/{info.template_id}")


def test_unsupported_build_steps_fail_with_a_clear_error():
    name = f"compat-{uuid.uuid4().hex[:8]}"
    template = Template().from_image(IMAGE).run_cmd("echo hi > /etc/motd")
    with pytest.raises((BuildException, TemplateException)) as err:
        Template.build(template, name)
    assert "RUN" in str(err.value) or "not supported" in str(err.value)
    # The refused build is recorded with its reason; then clean it up.
    [record] = [t for t in admin("GET", "/weft/v1/templates") if name in t["names"]]
    assert record["status"] == "error" and "RUN" in record["error"]
    admin("DELETE", f"/weft/v1/templates/{record['templateId']}")


def test_start_and_ready_commands_and_from_template():
    base = f"compat-{uuid.uuid4().hex[:8]}"
    child = f"compat-{uuid.uuid4().hex[:8]}"
    parent = Template().from_image(IMAGE).set_envs({"FROM_PARENT": "1"}).set_start_cmd(
        "python3 -m http.server 8123 --directory /tmp", "curl -sf http://127.0.0.1:8123/ || python3 -c 'import urllib.request; urllib.request.urlopen(\"http://127.0.0.1:8123/\")'"
    )
    built = [Template.build(parent, base, cpu_count=1, memory_mb=512)]
    try:
        built.append(Template.build(Template().from_template(base).set_envs({"FROM_CHILD": "1"}), child))
        sbx = Sandbox.create(template=base, timeout=60)
        try:
            check = "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8123/').status)"
            assert sbx.commands.run(f'python3 -c "{check}"').stdout.strip() == "200"
        finally:
            sbx.kill()
        sbx = Sandbox.create(template=child, timeout=60)
        try:
            assert sbx.commands.run("echo $FROM_PARENT$FROM_CHILD").stdout.strip() == "11"
        finally:
            sbx.kill()
    finally:
        for info in reversed(built):
            admin("DELETE", f"/weft/v1/templates/{info.template_id}")
