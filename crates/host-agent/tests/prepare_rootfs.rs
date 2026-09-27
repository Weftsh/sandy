//! The `prepare-rootfs` helper must keep every write inside the root
//! filesystem, whatever symlinks the image contains. Needs root (chroot);
//! skipped otherwise.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::Command;

fn run_helper(root: &Path, guest: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_weft-host-agent"))
        .arg("prepare-rootfs")
        .arg(root)
        .arg(guest)
        .output()
        .expect("run helper")
}

fn guest_dir() -> tempfile::TempDir {
    let guest = tempfile::tempdir().unwrap();
    fs::write(guest.path().join("envd"), b"envd").unwrap();
    fs::write(guest.path().join("weft-guest-init"), b"init").unwrap();
    guest
}

fn is_root() -> bool {
    nix::unistd::geteuid().is_root()
}

#[test]
fn symlinks_in_the_image_cannot_redirect_writes_to_the_host() {
    if !is_root() {
        eprintln!("skipped: needs root");
        return;
    }
    let outside = tempfile::tempdir().unwrap();
    fs::write(
        outside.path().join("passwd"),
        "hostroot:x:0:0::/root:/bin/sh\n",
    )
    .unwrap();
    fs::create_dir_all(outside.path().join("sudoers.d")).unwrap();
    let guest = guest_dir();

    for link_target in [
        outside.path().to_path_buf(),
        Path::new("../../..").join(outside.path().strip_prefix("/").unwrap()),
    ] {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("bin")).unwrap();
        fs::write(root.path().join("bin/sh"), b"").unwrap();
        fs::create_dir_all(root.path().join("usr/bin")).unwrap();
        fs::write(root.path().join("usr/bin/sudo"), b"").unwrap();
        symlink(&link_target, root.path().join("etc")).unwrap();
        let _ = run_helper(root.path(), guest.path());
        assert_eq!(
            fs::read_to_string(outside.path().join("passwd")).unwrap(),
            "hostroot:x:0:0::/root:/bin/sh\n",
            "the helper wrote through etc -> {}",
            link_target.display()
        );
        assert!(fs::read_dir(outside.path().join("sudoers.d"))
            .unwrap()
            .next()
            .is_none());
    }
}

#[test]
fn prepares_a_normal_image() {
    if !is_root() {
        eprintln!("skipped: needs root");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join("bin")).unwrap();
    fs::write(root.path().join("bin/sh"), b"").unwrap();
    let out = run_helper(root.path(), guest_dir().path());
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(fs::read_to_string(root.path().join("etc/passwd"))
        .unwrap()
        .contains("user:x:"));
    assert_eq!(fs::read(root.path().join("usr/bin/envd")).unwrap(), b"envd");
    // Slim images without ca-certificates still get a bundle envd can append to.
    assert!(root
        .path()
        .join("etc/ssl/certs/ca-certificates.crt")
        .is_file());
}
