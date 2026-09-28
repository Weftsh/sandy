//! Filesystems, device nodes, hostname and resolver.

use std::fs;
use std::io;
use std::path::Path;

use nix::mount::{mount, MsFlags};
use nix::sys::stat::{makedev, mknod, Mode as FileMode, SFlag};
use nix::unistd::sethostname;

use crate::config::{Config, Mode};

pub fn prepare(cfg: &Config) -> io::Result<()> {
    if !cfg.skip_mounts {
        match cfg.mode {
            Mode::Vm => mount_vm()?,
            Mode::Namespace => mount_namespace()?,
        }
    }
    if let Err(err) = sethostname(&cfg.hostname) {
        eprintln!("weft-guest-init: sethostname: {err}");
    }
    if let Some(dns) = &cfg.dns {
        write_if_possible(
            "/etc/resolv.conf",
            &format!("nameserver {dns}\noptions edns0\n"),
        );
    }
    ensure_hosts(&cfg.hostname);
    Ok(())
}

fn mount_vm() -> io::Result<()> {
    let nosuid_nodev_noexec = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;
    mount_fs("proc", "/proc", "proc", nosuid_nodev_noexec, None)?;
    mount_fs("sysfs", "/sys", "sysfs", nosuid_nodev_noexec, None)?;
    // A kernel built with CONFIG_DEVTMPFS_MOUNT (Firecracker's guest
    // configuration is) mounts devtmpfs on /dev before init runs, and
    // mounting it there again fails with EBUSY.
    let mounts = fs::read_to_string("/proc/self/mounts").unwrap_or_default();
    if !is_mounted(&mounts, "/dev", "devtmpfs") {
        mount_fs(
            "devtmpfs",
            "/dev",
            "devtmpfs",
            MsFlags::MS_NOSUID,
            Some("mode=0755"),
        )?;
    }
    mount_common()?;
    mount_fs(
        "cgroup2",
        "/sys/fs/cgroup",
        "cgroup2",
        nosuid_nodev_noexec,
        None,
    )
}

/// In the development runtime there is no devtmpfs: build a minimal /dev.
fn mount_namespace() -> io::Result<()> {
    let nosuid_nodev_noexec = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;
    mount_fs("proc", "/proc", "proc", nosuid_nodev_noexec, None)?;
    // sysfs is read-only and optional: some hosts refuse it in a child namespace.
    if let Err(err) = mount_fs(
        "sysfs",
        "/sys",
        "sysfs",
        nosuid_nodev_noexec | MsFlags::MS_RDONLY,
        None,
    ) {
        eprintln!("weft-guest-init: mounting /sys: {err}");
    }
    mount_fs(
        "tmpfs",
        "/dev",
        "tmpfs",
        MsFlags::MS_NOSUID,
        Some("mode=0755,size=65536k"),
    )?;
    let rw = FileMode::from_bits_truncate(0o666);
    for (name, major, minor) in [
        ("null", 1, 3),
        ("zero", 1, 5),
        ("full", 1, 7),
        ("random", 1, 8),
        ("urandom", 1, 9),
        ("tty", 5, 0),
    ] {
        let path = format!("/dev/{name}");
        mknod(path.as_str(), SFlag::S_IFCHR, rw, makedev(major, minor)).map_err(io::Error::from)?;
        // mknod honours the umask; make the mode exact.
        fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o666))?;
    }
    for (link, target) in [
        ("/dev/fd", "/proc/self/fd"),
        ("/dev/stdin", "/proc/self/fd/0"),
        ("/dev/stdout", "/proc/self/fd/1"),
        ("/dev/stderr", "/proc/self/fd/2"),
    ] {
        std::os::unix::fs::symlink(target, link)?;
    }
    mount_common()
}

fn mount_common() -> io::Result<()> {
    mount_fs(
        "devpts",
        "/dev/pts",
        "devpts",
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("newinstance,ptmxmode=0666,mode=0620,gid=5"),
    )?;
    let ptmx = Path::new("/dev/ptmx");
    if ptmx.symlink_metadata().is_err() {
        std::os::unix::fs::symlink("pts/ptmx", ptmx)?;
    }
    mount_fs(
        "tmpfs",
        "/dev/shm",
        "tmpfs",
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("mode=1777"),
    )?;
    mount_fs(
        "tmpfs",
        "/run",
        "tmpfs",
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("mode=0755"),
    )?;
    Ok(())
}

fn mount_fs(
    source: &str,
    target: &str,
    fstype: &str,
    flags: MsFlags,
    data: Option<&str>,
) -> io::Result<()> {
    fs::create_dir_all(target)?;
    mount(Some(source), target, Some(fstype), flags, data)
        .map_err(|err| io::Error::other(format!("mount {fstype} on {target}: {err}")))
}

/// Whether `mounts` (the format of /proc/self/mounts) has a `fstype`
/// filesystem mounted on `target`.
fn is_mounted(mounts: &str, target: &str, fstype: &str) -> bool {
    mounts.lines().any(|line| {
        let mut fields = line.split_whitespace().skip(1);
        fields.next() == Some(target) && fields.next() == Some(fstype)
    })
}

fn write_if_possible(path: &str, contents: &str) {
    // /etc/resolv.conf is often a dangling symlink into /run in container
    // images. Replace it with a regular file.
    if fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        let _ = fs::remove_file(path);
    }
    if let Err(err) = fs::write(path, contents) {
        eprintln!("weft-guest-init: writing {path}: {err}");
    }
}

fn ensure_hosts(hostname: &str) {
    let existing = fs::read_to_string("/etc/hosts").unwrap_or_default();
    let mut out = String::new();
    if !existing
        .lines()
        .any(|l| l.split_whitespace().skip(1).any(|h| h == "localhost"))
    {
        out.push_str("127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n");
    }
    if !existing
        .lines()
        .any(|l| l.split_whitespace().skip(1).any(|h| h == hostname))
    {
        out.push_str(&format!("127.0.1.1\t{hostname}\n"));
    }
    if !out.is_empty() {
        write_if_possible("/etc/hosts", &(existing + &out));
    }
}

#[cfg(test)]
mod tests {
    use super::is_mounted;

    #[test]
    fn finds_the_kernels_devtmpfs() {
        let mounts = "/dev/root / ext4 rw,relatime 0 0\n\
                      devtmpfs /dev devtmpfs rw,size=250000k,mode=755 0 0\n\
                      proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n";
        assert!(is_mounted(mounts, "/dev", "devtmpfs"));
        assert!(!is_mounted(mounts, "/dev/pts", "devpts"));
        assert!(!is_mounted(mounts, "/dev", "tmpfs"));
        assert!(!is_mounted("", "/dev", "devtmpfs"));
    }
}
