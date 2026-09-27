"""PTY sessions."""
from e2b import PtySize


def test_pty_interactive_session(sandbox):
    out = []
    pty = sandbox.pty.create(size=PtySize(rows=24, cols=80))
    sandbox.pty.resize(pty.pid, PtySize(rows=40, cols=120))
    sandbox.pty.send_stdin(pty.pid, b"stty size; echo pty-$((6*7)); exit\n")
    pty.wait(on_pty=out.append)
    text = b"".join(out).decode(errors="replace")
    assert "pty-42" in text
    assert "40 120" in text


def test_pty_kill(sandbox):
    pty = sandbox.pty.create(size=PtySize(rows=24, cols=80))
    assert sandbox.pty.kill(pty.pid) is True
