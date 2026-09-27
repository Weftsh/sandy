//! Root filesystem images and the files placed into and taken out of jails.
//!
//! Every sandbox writes to its own copy of the template's `rootfs.ext4`.
//! Production hosts format the data volume (which holds templates, the jail
//! chroots and pause snapshots) as XFS with reflink support
//! (`mkfs.xfs -m reflink=1`, the default in current xfsprogs), so that copy
//! is a constant-time clone that shares extents until the guest writes. On
//! filesystems without reflink the copy falls back to a sparse full copy,
//! which works but costs time and space proportional to the image.
//!
//! Snapshot memory and state files are read-only for the VMM and are hard
//! linked into the chroot, so all sandboxes of a template share one copy in
//! the page cache.

use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use nix::fcntl::OFlag;

use crate::cmd::{Cmd, CmdError, Runner, SystemRunner};

/// `mkfs.ext4` populating the image from a directory (e2fsprogs 1.43+).
/// The image file must already exist with its final size.
pub fn mkfs_cmd(rootfs_dir: &Path, image: &Path) -> Cmd {
    Cmd::new(
        "mkfs.ext4",
        [
            "-F".to_owned(),
            "-q".to_owned(),
            "-d".to_owned(),
            rootfs_dir.display().to_string(),
            "-L".to_owned(),
            "rootfs".to_owned(),
            "-E".to_owned(),
            "root_owner=0:0".to_owned(),
            image.display().to_string(),
        ],
    )
}

/// A clone sharing the source's extents. GNU cp refuses `--sparse=always`
/// together with `--reflink=always`; a clone keeps holes anyway.
pub fn reflink_cmd(src: &Path, dst: &Path) -> Cmd {
    Cmd::new(
        "cp",
        [
            "--reflink=always".to_owned(),
            src.display().to_string(),
            dst.display().to_string(),
        ],
    )
}

/// A full copy that leaves runs of zeros as holes.
pub fn sparse_copy_cmd(src: &Path, dst: &Path) -> Cmd {
    Cmd::new(
        "cp",
        [
            "--sparse=always".to_owned(),
            src.display().to_string(),
            dst.display().to_string(),
        ],
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyKind {
    Reflink,
    Sparse,
}

/// Copies `src` to a new file `dst`, cloning extents when the filesystem can.
pub async fn cow_copy(src: &Path, dst: &Path) -> Result<CopyKind, CmdError> {
    if SystemRunner.run(&reflink_cmd(src, dst)).await.is_ok() {
        return Ok(CopyKind::Reflink);
    }
    let _ = tokio::fs::remove_file(dst).await;
    SystemRunner.run(&sparse_copy_cmd(src, dst)).await?;
    Ok(CopyKind::Sparse)
}

/// Creates a sparse file of `bytes`, replacing any existing file.
pub async fn create_sparse(path: &Path, bytes: u64) -> io::Result<()> {
    let _ = tokio::fs::remove_file(path).await;
    let f = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .await?;
    f.set_len(bytes).await
}

/// Hard-links `src` to `dst`; copies when they are on different filesystems.
pub async fn link_or_copy(src: &Path, dst: &Path) -> io::Result<()> {
    match tokio::fs::hard_link(src, dst).await {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(nix::libc::EXDEV) => {
            tracing::warn!(
                src = %src.display(),
                "file is on another filesystem than the jails; copying instead of hard-linking"
            );
            cow_copy(src, dst).await.map(drop).map_err(io::Error::other)
        }
        Err(e) => Err(e),
    }
}

/// Changes a file's owner and mode without following symlinks.
pub fn set_owner_and_mode(path: &Path, uid: u32, gid: u32, mode: u32) -> io::Result<()> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(OFlag::O_NOFOLLOW.bits())
        .open(path)?;
    nix::unistd::fchown(&f, Some(uid.into()), Some(gid.into())).map_err(io::Error::from)?;
    f.set_permissions(std::fs::Permissions::from_mode(mode))
}

/// Makes a shared, read-only snapshot input readable by every jail user
/// (they never own it). Only adds read bits; never loosens anything else.
pub fn ensure_world_readable(path: &Path) -> io::Result<()> {
    let meta = std::fs::metadata(path)?;
    let mode = meta.permissions().mode() & 0o7777;
    if mode & 0o444 != 0o444 {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode | 0o444))?;
    }
    Ok(())
}

/// Moves a file a VMM wrote out of its chroot. The VMM must be dead: the
/// check that the entry is a regular file (not a symlink planted to make the
/// agent read or upload a host file) is only meaningful when nothing can
/// swap it afterwards.
pub async fn move_out_of_jail(src: &Path, dst: &Path) -> io::Result<u64> {
    let meta = tokio::fs::symlink_metadata(src).await?;
    if !meta.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not a regular file", src.display()),
        ));
    }
    let _ = tokio::fs::remove_file(dst).await;
    match tokio::fs::rename(src, dst).await {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(nix::libc::EXDEV) => {
            cow_copy(src, dst).await.map_err(io::Error::other)?;
            tokio::fs::remove_file(src).await?;
        }
        Err(e) => return Err(e),
    }
    Ok(meta.len())
}

/// Whether two paths are on the same filesystem (hard links work between them).
pub fn same_filesystem(a: &Path, b: &Path) -> io::Result<bool> {
    Ok(std::fs::metadata(a)?.dev() == std::fs::metadata(b)?.dev())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn mkfs_command() {
        let cmd = mkfs_cmd(
            Path::new("/data/builds/b1/rootfs"),
            Path::new("/data/jail/firecracker/b1/root/rootfs.ext4"),
        );
        assert_eq!(
            cmd.to_string(),
            "mkfs.ext4 -F -q -d /data/builds/b1/rootfs -L rootfs -E root_owner=0:0 /data/jail/firecracker/b1/root/rootfs.ext4"
        );
        assert!(!cmd.allow_failure);
    }

    #[test]
    fn copy_commands() {
        let (a, b) = (
            Path::new("/t/rootfs.ext4"),
            Path::new("/j/root/rootfs.ext4"),
        );
        assert_eq!(
            reflink_cmd(a, b).to_string(),
            "cp --reflink=always /t/rootfs.ext4 /j/root/rootfs.ext4"
        );
        assert_eq!(
            sparse_copy_cmd(a, b).to_string(),
            "cp --sparse=always /t/rootfs.ext4 /j/root/rootfs.ext4"
        );
    }

    #[tokio::test]
    async fn builds_a_real_ext4_image() {
        if std::process::Command::new("mkfs.ext4")
            .arg("-V")
            .output()
            .is_err()
        {
            eprintln!("mkfs.ext4 not installed; skipping");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("rootfs");
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/hostname"), "sandbox\n").unwrap();
        let image = tmp.path().join("rootfs.ext4");
        create_sparse(&image, 32 << 20).await.unwrap();
        SystemRunner.run(&mkfs_cmd(&root, &image)).await.unwrap();
        let sb = std::fs::read(&image).unwrap();
        assert_eq!(
            &sb[1024 + 0x38..1024 + 0x3a],
            &[0x53, 0xef],
            "ext4 superblock magic"
        );
        assert_eq!(&sb[1024 + 0x78..1024 + 0x78 + 6], b"rootfs", "volume label");
        let meta = std::fs::metadata(&image).unwrap();
        assert_eq!(meta.len(), 32 << 20);
        assert!(meta.blocks() * 512 < meta.len(), "image stays sparse");
    }

    #[tokio::test]
    async fn copies_sparse_files_whatever_the_filesystem() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src.img");
        create_sparse(&src, 64 << 20).await.unwrap();
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut f = std::fs::OpenOptions::new().write(true).open(&src).unwrap();
            f.seek(SeekFrom::Start(40 << 20)).unwrap();
            f.write_all(b"data in the middle").unwrap();
        }
        let dst = tmp.path().join("dst.img");
        let kind = cow_copy(&src, &dst).await.unwrap();
        let (a, b) = (std::fs::read(&src).unwrap(), std::fs::read(&dst).unwrap());
        assert!(a == b, "copy differs ({kind:?})");
        assert!(
            std::fs::metadata(&dst).unwrap().blocks() * 512 < (8 << 20),
            "copy is sparse ({kind:?})"
        );
    }

    #[tokio::test]
    async fn links_and_moves_regular_files_only() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("memory");
        std::fs::write(&src, b"mem").unwrap();
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o600)).unwrap();
        let jail = tmp.path().join("root");
        std::fs::create_dir(&jail).unwrap();
        link_or_copy(&src, &jail.join("memory")).await.unwrap();
        assert_eq!(std::fs::metadata(&src).unwrap().nlink(), 2);
        ensure_world_readable(&jail.join("memory")).unwrap();
        assert_eq!(
            std::fs::metadata(&src).unwrap().permissions().mode() & 0o777,
            0o644
        );

        // A symlink left in the jail is never followed out of it.
        let secret = tmp.path().join("secret");
        std::fs::write(&secret, b"host file").unwrap();
        std::os::unix::fs::symlink(&secret, jail.join("memory.new")).unwrap();
        let out = tmp.path().join("out");
        let err = move_out_of_jail(&jail.join("memory.new"), &out)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(!out.exists());

        std::fs::write(jail.join("vmstate.new"), b"state").unwrap();
        assert_eq!(
            move_out_of_jail(&jail.join("vmstate.new"), &out)
                .await
                .unwrap(),
            5
        );
        assert_eq!(std::fs::read(&out).unwrap(), b"state");
        assert!(!jail.join("vmstate.new").exists());
        assert!(same_filesystem(&src, &out).unwrap());
    }

    #[test]
    fn sets_owner_without_following_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("rootfs.ext4");
        std::fs::write(&f, b"").unwrap();
        let (uid, gid) = (
            nix::unistd::getuid().as_raw(),
            nix::unistd::getgid().as_raw(),
        );
        set_owner_and_mode(&f, uid, gid, 0o600).unwrap();
        assert_eq!(
            std::fs::metadata(&f).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&f, &link).unwrap();
        assert!(set_owner_and_mode(&link, uid, gid, 0o644).is_err());
        assert_eq!(
            std::fs::metadata(&f).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
