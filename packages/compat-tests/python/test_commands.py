"""Commands: foreground, background, stdin, users, exit codes, timeouts."""
import time

import pytest
from e2b import CommandExitException


def test_run_captures_output_and_exit_code(sandbox):
    r = sandbox.commands.run("echo out; echo err 1>&2")
    assert (r.exit_code, r.stdout, r.stderr) == (0, "out\n", "err\n")


def test_nonzero_exit_raises(sandbox):
    with pytest.raises(CommandExitException) as err:
        sandbox.commands.run("echo failing; exit 7")
    assert err.value.exit_code == 7
    assert err.value.stdout == "failing\n"


def test_default_user_cwd_and_env(sandbox):
    r = sandbox.commands.run("whoami; pwd; echo $HOME")
    assert r.stdout.split() == ["user", "/home/user", "/home/user"]
    assert sandbox.commands.run("whoami", user="root").stdout.strip() == "root"
    assert sandbox.commands.run("pwd", cwd="/tmp").stdout.strip() == "/tmp"
    assert sandbox.commands.run("echo $X", envs={"X": "per-command"}).stdout.strip() == "per-command"


def test_streaming_callbacks(sandbox):
    chunks = []
    sandbox.commands.run("for i in 1 2 3; do echo line$i; sleep 0.1; done", on_stdout=chunks.append)
    assert "".join(chunks) == "line1\nline2\nline3\n"


def test_background_list_and_kill(sandbox):
    handle = sandbox.commands.run("sleep 300", background=True)
    assert handle.pid in [p.pid for p in sandbox.commands.list()]
    assert sandbox.commands.kill(handle.pid) is True
    assert sandbox.commands.kill(handle.pid) is False


def test_stdin(sandbox):
    handle = sandbox.commands.run("read a; read b; echo $a-$b", background=True, stdin=True)
    sandbox.commands.send_stdin(handle.pid, "one\n")
    sandbox.commands.send_stdin(handle.pid, "two\n")
    assert handle.wait().stdout.strip() == "one-two"


def test_connect_to_running_process(sandbox):
    handle = sandbox.commands.run("sleep 1; echo done", background=True)
    again = sandbox.commands.connect(handle.pid)
    assert again.wait().stdout.strip() == "done"


def test_timeout_stops_the_process(sandbox):
    start = time.time()
    with pytest.raises(Exception):
        sandbox.commands.run("sleep 30", timeout=2)
    assert time.time() - start < 20


def test_large_output(sandbox):
    r = sandbox.commands.run("head -c 2000000 /dev/zero | tr '\\0' 'a'")
    assert len(r.stdout) == 2_000_000


def test_python_is_available(sandbox):
    assert sandbox.commands.run("python3 -c 'print(6*7)'").stdout.strip() == "42"
