//! Turns pulled image layers into a sandbox root filesystem.
//!
//! Layers are untrusted input processed as root, so each layer is extracted
//! by a helper process (`weft-host-agent unpack-layer`) that first
//! `chroot`s into the target directory: absolute symlinks and `..` then
//! resolve inside the root filesystem, whatever the archive contains. The
//! extractor additionally refuses entries that would write through a
//! symlink, never creates device nodes or FIFOs, and applies OCI whiteouts.
//! Installing envd, the init binary and the sandbox user happens in a second
//! chrooted helper (`weft-host-agent prepare-rootfs`) for the same reason:
//! an image with `etc -> /etc` must not make the agent edit the host's files.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

/// Where the guest binaries are installed inside every root filesystem.
pub const GUEST_ENVD_PATH: &str = "usr/bin/envd";
pub const GUEST_INIT_PATH: &str = "usr/local/bin/weft-guest-init";

/// The account the E2B SDKs run commands as by default.
pub const SANDBOX_USER: &str = "user";

#[derive(Debug, thiserror::Error)]
pub enum RootfsError {
    #[error("i/o: {0}")]
    Io(#[from] io::Error),
    #[error("unsafe archive entry {0:?}: {1}")]
    Unsafe(String, &'static str),
    #[error("image is missing {0}; sandbox templates need a POSIX shell")]
    MissingShell(&'static str),
    #[error("{0}")]
    Other(String),
}

/// Normalizes an archive path to a relative path with no `.`/`..`/root
/// components, or rejects it. The root itself (`./`) normalizes to an empty
/// path.
pub fn safe_relative(raw: &Path) -> Result<PathBuf, &'static str> {
    let mut out = PathBuf::new();
    for c in raw.components() {
        match c {
            Component::Normal(p) => out.push(p),
            Component::CurDir | Component::RootDir => {}
            Component::ParentDir => return Err("path contains `..`"),
            Component::Prefix(_) => return Err("path has a prefix"),
        }
    }
    Ok(out)
}

/// True if any existing ancestor of `rel` under `root` is a symlink.
fn has_symlink_ancestor(root: &Path, rel: &Path) -> io::Result<bool> {
    let mut cur = root.to_path_buf();
    let mut comps: Vec<_> = rel.components().collect();
    comps.pop();
    for c in comps {
        cur.push(c);
        match fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        }
    }
    Ok(false)
}

/// Extracts one layer tar stream into `root`, applying OCI whiteouts.
///
/// Called inside the chrooted helper with `root == "/"`, and directly by
/// tests with a temporary directory.
pub fn extract_layer<R: Read>(reader: R, root: &Path) -> Result<(), RootfsError> {
    let mut archive = tar::Archive::new(reader);
    archive.set_preserve_permissions(true);
    archive.set_preserve_ownerships(true);
    archive.set_unpack_xattrs(false);
    archive.set_overwrite(true);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let raw = entry.path()?.into_owned();
        let display = raw.display().to_string();
        let rel = safe_relative(&raw).map_err(|why| RootfsError::Unsafe(display.clone(), why))?;
        if rel.as_os_str().is_empty() {
            // The layer's entry for the root directory itself.
            continue;
        }
        if has_symlink_ancestor(root, &rel)? {
            return Err(RootfsError::Unsafe(display, "writes through a symlink"));
        }
        let name = rel
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_owned();
        let parent = rel.parent().map(Path::to_path_buf).unwrap_or_default();

        // Whiteouts: `.wh..wh..opq` empties the directory; `.wh.name` deletes `name`.
        if name == ".wh..wh..opq" {
            let dir = root.join(&parent);
            if let Ok(read) = fs::read_dir(&dir) {
                for child in read {
                    remove_any(&child?.path())?;
                }
            }
            continue;
        }
        if let Some(target) = name.strip_prefix(".wh.") {
            remove_any(&root.join(&parent).join(target))?;
            continue;
        }

        let dest = root.join(&rel);
        let kind = entry.header().entry_type();
        // Device nodes would give later writes (or a sandbox) a path to host
        // devices; FIFOs would hang readers. Images have no business with either.
        if kind.is_character_special() || kind.is_block_special() || kind.is_fifo() {
            continue;
        }
        // Never write through an existing symlink or into a type mismatch.
        if let Ok(meta) = fs::symlink_metadata(&dest) {
            let keep_dir = meta.is_dir() && kind.is_dir();
            if !keep_dir {
                remove_any(&dest)?;
            }
        }
        if kind.is_hard_link() {
            let link = entry
                .link_name()?
                .ok_or_else(|| RootfsError::Unsafe(display.clone(), "hard link without target"))?;
            let link_rel =
                safe_relative(&link).map_err(|why| RootfsError::Unsafe(display.clone(), why))?;
            if link_rel.as_os_str().is_empty() {
                return Err(RootfsError::Unsafe(
                    display,
                    "hard link to the root directory",
                ));
            }
            if has_symlink_ancestor(root, &link_rel)? {
                return Err(RootfsError::Unsafe(display, "hard link through a symlink"));
            }
            let src = root.join(&link_rel);
            if fs::symlink_metadata(&src)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
            {
                return Err(RootfsError::Unsafe(display, "hard link to a symlink"));
            }
        }
        if let Some(p) = dest.parent() {
            fs::create_dir_all(p)?;
        }
        entry
            .unpack(&dest)
            .map_err(|e| RootfsError::Other(format!("extracting {display}: {e}")))?;
    }
    Ok(())
}

fn remove_any(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Opens a layer file with the decompressor its media type calls for.
pub fn open_layer(path: &Path, media_type: &str) -> io::Result<Box<dyn Read>> {
    let file = io::BufReader::new(fs::File::open(path)?);
    if media_type.ends_with("+zstd") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "zstd layers are not supported yet; push a gzip image",
        ));
    }
    if media_type.ends_with("gzip") {
        return Ok(Box::new(flate2::read::MultiGzDecoder::new(file)));
    }
    Ok(Box::new(file))
}

/// Entry point of the `unpack-layer` helper: chroot into `root`, extract.
pub fn unpack_layer_in_chroot(
    root: &Path,
    layer: &Path,
    media_type: &str,
) -> Result<(), RootfsError> {
    // Open the layer before the chroot hides it.
    let reader = open_layer(layer, media_type)?;
    nix::unistd::chroot(root)
        .map_err(|e| RootfsError::Other(format!("chroot {}: {e}", root.display())))?;
    std::env::set_current_dir("/")?;
    extract_layer(reader, Path::new("/"))
}

/// The guest binaries every root filesystem gets.
pub struct GuestFiles {
    pub envd: Vec<u8>,
    pub init: Vec<u8>,
}

impl GuestFiles {
    pub fn read(guest_dir: &Path) -> Result<Self, RootfsError> {
        let read = |name: &str| {
            fs::read(guest_dir.join(name)).map_err(|e| {
                RootfsError::Other(format!("reading {}: {e}", guest_dir.join(name).display()))
            })
        };
        Ok(Self {
            envd: read("envd")?,
            init: read("weft-guest-init")?,
        })
    }
}

/// Entry point of the `prepare-rootfs` helper: reads the guest binaries,
/// `chroot`s into `root` and prepares it there, so every path the image
/// controls (symlinks included) resolves inside the root filesystem. Runs in
/// a process of its own because the chroot cannot be undone.
pub fn prepare_in_chroot(root: &Path, guest_dir: &Path) -> Result<(), RootfsError> {
    let files = GuestFiles::read(guest_dir)?;
    nix::unistd::chroot(root)
        .map_err(|e| RootfsError::Other(format!("chroot {}: {e}", root.display())))?;
    std::env::set_current_dir("/")?;
    prepare(Path::new("/"), &files)
}

/// Installs envd, the init binary and the sandbox user into an unpacked
/// root filesystem. Only safe inside the chroot [`prepare_in_chroot`] sets
/// up: on the host, a symlink in the image would redirect these writes.
fn prepare(root: &Path, files: &GuestFiles) -> Result<(), RootfsError> {
    let shell = root.join("bin/sh");
    if fs::symlink_metadata(&shell).is_err() {
        return Err(RootfsError::MissingShell("/bin/sh"));
    }
    for dir in [
        "proc",
        "sys",
        "dev",
        "run",
        "tmp",
        "usr/bin",
        "usr/local/bin",
        "etc",
        "etc/ssl/certs",
        "home",
    ] {
        let p = root.join(dir);
        if fs::symlink_metadata(&p)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            continue; // e.g. /bin -> usr/bin on merged-usr images
        }
        fs::create_dir_all(&p)?;
    }
    fs::set_permissions(root.join("tmp"), fs::Permissions::from_mode(0o1777))?;
    install_file(&files.envd, &root.join(GUEST_ENVD_PATH), 0o755)?;
    install_file(&files.init, &root.join(GUEST_INIT_PATH), 0o755)?;
    ensure_user(root)?;
    ensure_ca_bundle(root)?;
    Ok(())
}

/// envd appends the egress CA to this file when a sandbox's policy has
/// credential rules, and fails if it is missing (slim images often lack the
/// `ca-certificates` package). An empty bundle is better than no sandbox.
fn ensure_ca_bundle(root: &Path) -> Result<(), RootfsError> {
    let bundle = root.join("etc/ssl/certs/ca-certificates.crt");
    if !regular_or_missing(&bundle)? {
        fs::write(&bundle, b"")?;
        fs::set_permissions(&bundle, fs::Permissions::from_mode(0o644))?;
    }
    Ok(())
}

/// True if `path` is a regular file, false if it does not exist; an error for
/// anything else (a device, FIFO or directory) that a write must not touch.
fn regular_or_missing(path: &Path) -> Result<bool, RootfsError> {
    match fs::metadata(path) {
        Ok(m) if m.is_file() => Ok(true),
        Ok(_) => Err(RootfsError::Other(format!(
            "{} is not a regular file",
            path.display()
        ))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn install_file(contents: &[u8], dst: &Path, mode: u32) -> Result<(), RootfsError> {
    if fs::symlink_metadata(dst).is_ok() {
        remove_any(dst)?;
    }
    fs::write(dst, contents)
        .map_err(|e| RootfsError::Other(format!("installing {}: {e}", dst.display())))?;
    fs::set_permissions(dst, fs::Permissions::from_mode(mode))?;
    Ok(())
}

/// Creates the `user` account (with a home directory and, when sudo is
/// installed, passwordless sudo) unless the image already has one.
fn ensure_user(root: &Path) -> Result<(), RootfsError> {
    let passwd_path = root.join("etc/passwd");
    let group_path = root.join("etc/group");
    let shadow = root.join("etc/shadow");
    for f in [&passwd_path, &group_path, &shadow] {
        regular_or_missing(f)?;
    }
    let passwd = fs::read_to_string(&passwd_path).unwrap_or_default();
    let group = fs::read_to_string(&group_path).unwrap_or_default();
    let users = parse_ids(&passwd, 2);
    let groups = parse_ids(&group, 2);

    let (uid, gid) = if let Some(uid) = users.get(SANDBOX_USER) {
        let gid = passwd
            .lines()
            .find(|l| l.split(':').next() == Some(SANDBOX_USER))
            .and_then(|l| l.split(':').nth(3))
            .and_then(|g| g.parse().ok())
            .unwrap_or(*uid);
        (*uid, gid)
    } else {
        let taken: Vec<u32> = users
            .values()
            .copied()
            .chain(groups.values().copied())
            .collect();
        let id = (1000..60000)
            .find(|i| !taken.contains(i))
            .ok_or_else(|| RootfsError::Other("no free uid".into()))?;
        let shell = if root.join("bin/bash").exists() {
            "/bin/bash"
        } else {
            "/bin/sh"
        };
        append_line(
            &passwd_path,
            &format!("{SANDBOX_USER}:x:{id}:{id}::/home/{SANDBOX_USER}:{shell}"),
        )?;
        if !groups.contains_key(SANDBOX_USER) {
            append_line(&group_path, &format!("{SANDBOX_USER}:x:{id}:"))?;
        }
        if shadow.exists() {
            append_line(&shadow, &format!("{SANDBOX_USER}:!:19000:0:99999:7:::"))?;
        }
        (id, id)
    };

    let home = root.join("home").join(SANDBOX_USER);
    if fs::symlink_metadata(&home).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(RootfsError::Other(format!(
            "/home/{SANDBOX_USER} must be a directory, not a symlink"
        )));
    }
    fs::create_dir_all(&home)?;
    let meta = fs::metadata(&home)?;
    if meta.uid() != uid {
        nix::unistd::chown(&home, Some(uid.into()), Some(gid.into()))
            .map_err(|e| RootfsError::Other(format!("chown home: {e}")))?;
    }
    let sudoers = root.join("etc/sudoers.d");
    if root.join("usr/bin/sudo").exists() && sudoers.is_dir() {
        let f = sudoers.join("weft-sandbox-user");
        regular_or_missing(&f)?;
        fs::write(&f, format!("{SANDBOX_USER} ALL=(ALL:ALL) NOPASSWD: ALL\n"))?;
        fs::set_permissions(&f, fs::Permissions::from_mode(0o440))?;
    }
    Ok(())
}

fn parse_ids(file: &str, field: usize) -> BTreeMap<String, u32> {
    file.lines()
        .filter_map(|l| {
            let mut parts = l.split(':');
            let name = parts.next()?.to_owned();
            let id = parts.nth(field - 1)?.parse().ok()?;
            Some((name, id))
        })
        .collect()
}

fn append_line(path: &Path, line: &str) -> io::Result<()> {
    let mut existing = fs::read_to_string(path).unwrap_or_default();
    if !existing.is_empty() && !existing.ends_with('\n') {
        existing.push('\n');
    }
    existing.push_str(line);
    existing.push('\n');
    fs::write(path, existing)
}

/// Parses `KEY=value` image environment entries.
pub fn parse_env(entries: &[String]) -> BTreeMap<String, String> {
    entries
        .iter()
        .filter_map(|e| e.split_once('=').map(|(k, v)| (k.to_owned(), v.to_owned())))
        .filter(|(k, _)| !k.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn tar_with(entries: &[(&str, tar::EntryType, &[u8], Option<&str>)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (path, kind, data, link) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(*kind);
            h.set_mode(if kind.is_dir() { 0o755 } else { 0o644 });
            h.set_size(data.len() as u64);
            h.set_uid(0);
            h.set_gid(0);
            h.set_mtime(0);
            if let Some(l) = link {
                h.set_link_name(l).unwrap();
            }
            // Bypass the builder's own path sanitizing to model hostile archives.
            let name = h.as_old_mut().name.as_mut();
            name[..path.len()].copy_from_slice(path.as_bytes());
            h.set_cksum();
            b.append(&h, *data).unwrap();
        }
        b.into_inner().unwrap()
    }

    #[test]
    fn extracts_files_and_applies_whiteouts() {
        let dir = tempfile::tempdir().unwrap();
        let layer1 = tar_with(&[
            ("./", tar::EntryType::Directory, b"", None),
            ("etc/", tar::EntryType::Directory, b"", None),
            ("etc/keep", tar::EntryType::Regular, b"1", None),
            ("etc/gone", tar::EntryType::Regular, b"2", None),
            ("opt/", tar::EntryType::Directory, b"", None),
            ("opt/old", tar::EntryType::Regular, b"3", None),
        ]);
        extract_layer(Cursor::new(layer1), dir.path()).unwrap();
        let layer2 = tar_with(&[
            ("etc/.wh.gone", tar::EntryType::Regular, b"", None),
            ("opt/.wh..wh..opq", tar::EntryType::Regular, b"", None),
            ("opt/new", tar::EntryType::Regular, b"4", None),
        ]);
        extract_layer(Cursor::new(layer2), dir.path()).unwrap();
        assert!(dir.path().join("etc/keep").exists());
        assert!(!dir.path().join("etc/gone").exists());
        assert!(!dir.path().join("opt/old").exists());
        assert_eq!(fs::read(dir.path().join("opt/new")).unwrap(), b"4");
    }

    #[test]
    fn never_creates_device_nodes_or_fifos() {
        let root = tempfile::tempdir().unwrap();
        let tar = tar_with(&[
            ("etc/passwd", tar::EntryType::Block, b"", None),
            ("dev/mem", tar::EntryType::Char, b"", None),
            ("tmp/pipe", tar::EntryType::Fifo, b"", None),
            ("etc/hostname", tar::EntryType::Regular, b"box", None),
        ]);
        extract_layer(&tar[..], root.path()).unwrap();
        for p in ["etc/passwd", "dev/mem", "tmp/pipe"] {
            assert!(
                fs::symlink_metadata(root.path().join(p)).is_err(),
                "{p} was created"
            );
        }
        assert_eq!(fs::read(root.path().join("etc/hostname")).unwrap(), b"box");
    }

    #[test]
    fn refuses_parent_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let evil = tar_with(&[("../escape", tar::EntryType::Regular, b"x", None)]);
        assert!(matches!(
            extract_layer(Cursor::new(evil), dir.path()),
            Err(RootfsError::Unsafe(..))
        ));
        assert!(!dir.path().parent().unwrap().join("escape").exists());
    }

    #[test]
    fn refuses_to_write_through_symlinks() {
        let outside = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let target = outside.path().to_str().unwrap().to_owned();
        let evil = tar_with(&[
            ("link", tar::EntryType::Symlink, b"", Some(&target)),
            ("link/pwned", tar::EntryType::Regular, b"x", None),
        ]);
        assert!(matches!(
            extract_layer(Cursor::new(evil), dir.path()),
            Err(RootfsError::Unsafe(..))
        ));
        assert!(!outside.path().join("pwned").exists());
    }

    #[test]
    fn replaces_a_symlink_instead_of_following_it() {
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("victim"), b"original").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let victim = outside.path().join("victim").to_str().unwrap().to_owned();
        let layer1 = tar_with(&[("file", tar::EntryType::Symlink, b"", Some(&victim))]);
        extract_layer(Cursor::new(layer1), dir.path()).unwrap();
        let layer2 = tar_with(&[("file", tar::EntryType::Regular, b"new", None)]);
        extract_layer(Cursor::new(layer2), dir.path()).unwrap();
        assert_eq!(
            fs::read(outside.path().join("victim")).unwrap(),
            b"original"
        );
        assert_eq!(fs::read(dir.path().join("file")).unwrap(), b"new");
    }

    #[test]
    fn refuses_hard_links_through_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let evil = tar_with(&[
            ("etc", tar::EntryType::Symlink, b"", Some("/etc")),
            ("stolen", tar::EntryType::Link, b"", Some("etc/shadow")),
        ]);
        assert!(matches!(
            extract_layer(Cursor::new(evil), dir.path()),
            Err(RootfsError::Unsafe(..))
        ));
    }

    #[test]
    fn prepares_user_and_binaries() {
        let root = tempfile::tempdir().unwrap();
        let guest = GuestFiles {
            envd: b"envd".to_vec(),
            init: b"init".to_vec(),
        };
        assert!(matches!(
            prepare(root.path(), &guest),
            Err(RootfsError::MissingShell(_))
        ));

        fs::create_dir_all(root.path().join("bin")).unwrap();
        fs::write(root.path().join("bin/sh"), b"").unwrap();
        fs::create_dir_all(root.path().join("etc")).unwrap();
        fs::write(
            root.path().join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/sh\nubuntu:x:1000:1000::/home/ubuntu:/bin/sh\n",
        )
        .unwrap();
        fs::write(root.path().join("etc/group"), "root:x:0:\nubuntu:x:1000:\n").unwrap();
        prepare(root.path(), &guest).unwrap();
        let passwd = fs::read_to_string(root.path().join("etc/passwd")).unwrap();
        assert!(
            passwd.contains("user:x:1001:1001::/home/user:/bin/sh"),
            "{passwd}"
        );
        assert!(fs::read_to_string(root.path().join("etc/group"))
            .unwrap()
            .contains("user:x:1001:"));
        assert_eq!(
            fs::read(root.path().join(GUEST_ENVD_PATH)).unwrap(),
            b"envd"
        );
        assert!(root.path().join("home/user").is_dir());
        // Idempotent.
        prepare(root.path(), &guest).unwrap();
        assert_eq!(
            fs::read_to_string(root.path().join("etc/passwd"))
                .unwrap()
                .matches("user:x:")
                .count(),
            1
        );
    }

    #[test]
    fn parses_image_env() {
        let env = parse_env(&[
            "PATH=/usr/bin:/bin".into(),
            "EMPTY=".into(),
            "BAD".into(),
            "=x".into(),
        ]);
        assert_eq!(env.get("PATH").unwrap(), "/usr/bin:/bin");
        assert_eq!(env.get("EMPTY").unwrap(), "");
        assert_eq!(env.len(), 2);
    }
}
