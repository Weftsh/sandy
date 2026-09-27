"""Sandbox lifecycle: create, list, info, timeout, pause, resume, kill."""
import time

import pytest
from e2b import Sandbox, SandboxQuery, SandboxState
from e2b.exceptions import NotFoundException, SandboxException


def test_create_returns_a_usable_sandbox(sandbox):
    assert sandbox.sandbox_id.isalnum() and sandbox.sandbox_id.islower()
    assert sandbox.is_running()
    assert sandbox.commands.run("echo ok").stdout.strip() == "ok"


def test_create_with_env_vars_and_metadata(tag):
    sbx = Sandbox.create(metadata=tag, envs={"COMPAT_VAR": "hello"}, timeout=60)
    try:
        assert sbx.commands.run("echo $COMPAT_VAR").stdout.strip() == "hello"
        info = sbx.get_info()
        assert info.metadata == tag
        assert info.state == SandboxState.RUNNING
        assert info.template_id
    finally:
        sbx.kill()


def test_list_filters_by_metadata_and_state(tag):
    a = Sandbox.create(metadata=tag, timeout=60)
    b = Sandbox.create(metadata=tag, timeout=60)
    try:
        listed = Sandbox.list(query=SandboxQuery(metadata=tag, state=[SandboxState.RUNNING])).next_items()
        assert {s.sandbox_id for s in listed} == {a.sandbox_id, b.sandbox_id}
        paused = Sandbox.list(query=SandboxQuery(metadata=tag, state=[SandboxState.PAUSED])).next_items()
        assert paused == []
    finally:
        a.kill()
        b.kill()


def test_list_paginates(tag):
    boxes = [Sandbox.create(metadata=tag, timeout=60) for _ in range(3)]
    try:
        pager = Sandbox.list(query=SandboxQuery(metadata=tag), limit=2)
        seen = list(pager.next_items())
        assert len(seen) == 2 and pager.has_next
        seen += pager.next_items()
        assert not pager.has_next
        assert {s.sandbox_id for s in seen} == {b.sandbox_id for b in boxes}
    finally:
        for b in boxes:
            b.kill()


def test_kill_is_idempotent(tag):
    sbx = Sandbox.create(metadata=tag, timeout=60)
    assert sbx.kill() is True
    assert Sandbox.kill(sbx.sandbox_id) is False
    with pytest.raises(NotFoundException):
        Sandbox.get_info(sbx.sandbox_id)


def test_timeout_kills_the_sandbox(tag):
    sbx = Sandbox.create(metadata=tag, timeout=60)
    sbx.set_timeout(2)
    deadline = time.time() + 30
    while time.time() < deadline:
        if not Sandbox.list(query=SandboxQuery(metadata=tag)).next_items():
            break
        time.sleep(1)
    assert Sandbox.list(query=SandboxQuery(metadata=tag)).next_items() == []
    assert not sbx.is_running()


def test_set_timeout_extends_end_time(sandbox):
    before = sandbox.get_info().end_at
    sandbox.set_timeout(600)
    assert sandbox.get_info().end_at > before


def test_pause_and_resume_keep_state(tag):
    sbx = Sandbox.create(metadata=tag, timeout=120)
    try:
        sbx.files.write("/home/user/state.txt", "survives pause")
        proc = sbx.commands.run("sleep 600", background=True)
        assert sbx.pause() is True
        assert Sandbox.get_info(sbx.sandbox_id).state == SandboxState.PAUSED
        assert Sandbox.pause(sbx.sandbox_id) is False, "pausing a paused sandbox returns False"
        resumed = Sandbox.connect(sbx.sandbox_id)
        assert Sandbox.get_info(sbx.sandbox_id).state == SandboxState.RUNNING
        assert resumed.files.read("/home/user/state.txt") == "survives pause"
        assert proc.pid in [p.pid for p in resumed.commands.list()]
    finally:
        Sandbox.kill(sbx.sandbox_id)


def test_connect_extends_a_running_sandbox(sandbox):
    same = Sandbox.connect(sandbox.sandbox_id, timeout=900)
    assert same.sandbox_id == sandbox.sandbox_id
    assert same.commands.run("echo again").stdout.strip() == "again"


def test_connect_to_unknown_sandbox_fails():
    with pytest.raises(SandboxException):
        Sandbox.connect("doesnotexist0000000000")


def test_unknown_template_is_rejected(tag):
    with pytest.raises(Exception) as err:
        Sandbox.create(template="no-such-template", metadata=tag)
    assert "not found" in str(err.value).lower()


def test_metrics(sandbox):
    metrics = sandbox.get_metrics()
    assert metrics and metrics[0].cpu_count >= 1 and metrics[0].mem_total > 0
