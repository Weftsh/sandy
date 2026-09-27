"""Filesystem: read/write, listing, metadata operations, watches, signed URLs."""
import os
import time

from e2b import FileType, FilesystemEventType
from e2b.sandbox.filesystem.filesystem import WriteEntry

from conftest import http_client


def test_write_and_read_text_and_bytes(sandbox):
    info = sandbox.files.write("/home/user/a.txt", "hello")
    assert info.path == "/home/user/a.txt"
    assert sandbox.files.read("/home/user/a.txt") == "hello"
    blob = bytes(range(256)) * 64
    sandbox.files.write("/home/user/b.bin", blob)
    assert sandbox.files.read("/home/user/b.bin", format="bytes") == blob


def test_relative_paths_resolve_in_home(sandbox):
    sandbox.files.write("rel.txt", "relative")
    assert sandbox.files.read("/home/user/rel.txt") == "relative"


def test_write_many_files_and_nested_dirs(sandbox):
    out = sandbox.files.write_files(
        [WriteEntry(path="/home/user/x/1.txt", data="1"), WriteEntry(path="/home/user/x/y/2.txt", data="2")]
    )
    assert len(out) == 2
    assert sandbox.files.read("/home/user/x/y/2.txt") == "2"


def test_large_file_round_trip(sandbox):
    data = os.urandom(8 * 1024 * 1024)
    sandbox.files.write("/home/user/large.bin", data)
    assert sandbox.files.read("/home/user/large.bin", format="bytes") == data


def test_list_exists_info(sandbox):
    sandbox.files.make_dir("/home/user/d/e")
    sandbox.files.write("/home/user/d/f.txt", "f")
    names = {(e.name, e.type) for e in sandbox.files.list("/home/user/d")}
    assert names == {("e", FileType.DIR), ("f.txt", FileType.FILE)}
    deep = {e.path for e in sandbox.files.list("/home/user/d", depth=2)}
    assert "/home/user/d/e" in deep
    assert sandbox.files.exists("/home/user/d/f.txt")
    assert not sandbox.files.exists("/home/user/d/missing")
    info = sandbox.files.get_info("/home/user/d/f.txt")
    assert info.size == 1 and info.type == FileType.FILE


def test_make_dir_rename_remove(sandbox):
    assert sandbox.files.make_dir("/home/user/newdir") is True
    assert sandbox.files.make_dir("/home/user/newdir") is False
    sandbox.files.write("/home/user/newdir/a", "a")
    sandbox.files.rename("/home/user/newdir/a", "/home/user/newdir/b")
    assert sandbox.files.exists("/home/user/newdir/b")
    sandbox.files.remove("/home/user/newdir")
    assert not sandbox.files.exists("/home/user/newdir")


def test_watch_dir(sandbox):
    sandbox.files.make_dir("/home/user/watched")
    handle = sandbox.files.watch_dir("/home/user/watched")
    sandbox.files.write("/home/user/watched/new.txt", "x")
    time.sleep(1)
    events = handle.get_new_events()
    handle.stop()
    assert any(e.name == "new.txt" and e.type in (FilesystemEventType.CREATE, FilesystemEventType.WRITE) for e in events)


def test_signed_download_and_upload_urls(sandbox):
    sandbox.files.write("/home/user/signed.txt", "via url")
    url = sandbox.download_url("/home/user/signed.txt", use_signature_expiration=60)
    headers = {}
    if os.environ.get("E2B_SANDBOX_URL"):
        headers = {"E2b-Sandbox-Id": sandbox.sandbox_id, "E2b-Sandbox-Port": "49983"}
    with http_client() as client:
        r = client.get(url, headers=headers)
        assert r.status_code == 200 and r.text == "via url"
        up = sandbox.upload_url("/home/user/uploaded.txt", use_signature_expiration=60)
        r = client.post(up, headers=headers, files={"file": ("uploaded.txt", b"uploaded")})
    assert r.status_code == 200
    assert sandbox.files.read("/home/user/uploaded.txt") == "uploaded"
