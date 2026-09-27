# Guest kernel

`build.sh` builds the Linux kernel every Weft sandbox runs: an uncompressed
x86_64 `vmlinux` that the host agent's Firecracker runtime boots once per
template and then restores from snapshots.

```sh
guest/kernel/build.sh              # -> dist/guest/vmlinux, dist/guest/vmlinux.config
guest/kernel/build.sh /some/dir    # -> /some/dir/vmlinux
```

Build dependencies (Debian/Ubuntu): `build-essential bc bison flex libelf-dev
libssl-dev curl xz-utils`. A build takes about 15 to 20 minutes on 3 to 4
cores and produces a vmlinux of about 27 MB; set `JOBS` to control
parallelism, `KERNEL_TARBALL` to use an already downloaded tarball and
`KERNEL_WORK_DIR` to keep the build tree.

## Pinned versions

| What | Version | Where it is pinned |
| --- | --- | --- |
| Linux | 6.18.54 (longterm) | `VERSION`: `LINUX_VERSION`, `LINUX_SHA256` |
| Firecracker | v1.17.0 | `VERSION`: `FIRECRACKER_VERSION`; `FIRECRACKER_VERSION` in `crates/host-agent/src/runtime/firecracker/mod.rs` |
| Guest configuration | Firecracker v1.17.0 `resources/guest_configs/microvm-kernel-ci-x86_64-6.18.config` | vendored here, `FC_CONFIG_SHA256` |

The tarball hash is the one kernel.org publishes in the signed
`sha256sums.asc`. `build.sh` refuses a tarball or a vendored configuration
that does not match its pinned hash.

## Why this kernel

* **Linux 6.18** is the newest longterm release and one of the guest kernel
  lines Firecracker v1.17 officially supports (with 5.10 and 6.1). Firecracker
  publishes the microVM configuration it tests for exactly this line.
* **Firecracker's configuration as the base**: it is what Firecracker's CI
  boots, snapshots and restores, and it already carries the virtio-mmio,
  ACPI, serial and paravirtual clock support a microVM needs, with nothing for
  hardware a microVM never has.
* **`weft.config` on top**, small and verified: after `make olddefconfig`
  the build fails if any line of the fragment is missing from the final
  configuration (Kconfig silently drops options whose dependencies are not
  met).

## What `weft.config` adds and why

| Setting | Why |
| --- | --- |
| `CONFIG_MODULES=n` | Root filesystems come from arbitrary OCI images and never contain modules for this kernel, so everything is built in. |
| `CONFIG_IP_PNP=y`, DHCP/BOOTP/RARP off | The host passes the guest's fixed address on the command line (`ip=169.254.0.21::169.254.0.22:255.255.255.252::eth0:off`); `eth0` is up before init runs. |
| `CONFIG_VMGENID=y`, `CONFIG_ACPI=y` | Fresh randomness after restore; see below. |
| `CONFIG_HW_RANDOM_VIRTIO=y` | Firecracker's entropy device, attached to every VM. |
| devtmpfs, tmpfs, cgroup v2 controllers (memory, pids, cpu, cpuset, freezer) | `weft-guest-init` mounts devtmpfs, `/dev/pts`, `/dev/shm`, `/run` and a cgroup v2 hierarchy; envd creates cgroups for the processes it starts. |
| `CONFIG_UNIX98_PTYS`, `CONFIG_INOTIFY_USER`, epoll/eventfd/signalfd/timerfd | envd's terminals (PTYs), filesystem watches (inotify) and the Go runtime. |
| `CONFIG_OVERLAY_FS=y` | Container tooling people run inside sandboxes. |
| `CONFIG_LOCALVERSION="-weft"` | `uname -r` reports `6.18.54-weft`. |

## Randomness in restored sandboxes

Every sandbox of a template resumes from the same memory snapshot, so all of
them start with the same kernel CRNG state. Following Firecracker's
`docs/snapshotting/random-for-clones.md`:

* Firecracker always exposes a **VMGenID** device and writes a new
  cryptographically random generation ID on every restore, raising a
  notification before the vCPUs resume. Linux 5.18+ with `CONFIG_VMGENID`
  (found through ACPI on x86_64) mixes the new ID into its entropy pool and
  forces a CRNG reseed, so `getrandom()` and `/dev/urandom` diverge between
  clones as soon as the kernel handles the notification.
* The **virtio-rng** entropy device keeps feeding host randomness.
* User code only reaches a restored sandbox after the host agent's `/init`
  call, which follows the restore; the kernel normally handles the VMGenID
  notification long before. Firecracker's document notes a window between
  resume and reseed; closing it completely would take an explicit
  `RNDADDENTROPY`/`RNDRESEEDCRNG` in the guest before envd serves `/init`,
  which Weft does not do yet.

State outside the kernel is not refreshed: userspace PRNGs seeded by
processes the template's start command launched, and
`/proc/sys/kernel/random/boot_id`, are identical across clones of a template.

## Kernel command line

The runtime boots template VMs with:

```text
console=ttyS0 reboot=k panic=1 pci=off
ip=169.254.0.21::169.254.0.22:255.255.255.252::eth0:off
init=/usr/local/bin/weft-guest-init weft.dns=169.254.0.22 weft.envd=/usr/bin/envd
weft.envd_args=-isnotfc,-port,49983
```

Firecracker appends `root=/dev/vda rw` and a virtio-mmio device list; this
configuration ignores the list (`CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES` is off,
as in Firecracker's) and finds the same devices through ACPI. `panic=1` with
`reboot=k` turns a guest panic into a VMM exit, which the host agent reports
with the end of the console output.

## Updating

1. Pick the new longterm release and copy its `linux-<version>.tar.xz` hash
   from `https://cdn.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc` (verify
   the file's signature against the kernel.org checksum autosigner key).
2. When moving to a new Firecracker release, fetch the matching
   `resources/guest_configs/microvm-kernel-ci-x86_64-<line>.config` at the
   release tag from
   `https://raw.githubusercontent.com/firecracker-microvm/firecracker/<tag>/...`,
   replace the vendored file unchanged and update `FC_CONFIG_SHA256`, and move
   `FIRECRACKER_VERSION` in the host agent at the same time.
3. Rebuild and rebuild every template: snapshots record the kernel's memory,
   so a new kernel only reaches sandboxes through new templates.

## Licensing

The scripts and `weft.config` in this directory are Apache-2.0 (see the
repository's `LICENSE.md`). The vendored Firecracker configuration is
Apache-2.0, see `NOTICE`. The kernel built from them is Linux, GPL-2.0; its
exact source is the pinned kernel.org release plus the final configuration
written next to it (`vmlinux.config`).
