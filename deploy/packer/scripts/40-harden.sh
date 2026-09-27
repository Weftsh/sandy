#!/usr/bin/env bash
# Host hardening: kernel settings from Firecracker's production host setup
# guide (docs/prod-host-setup.md) plus general hardening, KVM permissions,
# no SSH keys from cloud-init, bounded logs, no core dumps.
set -euo pipefail
export LC_ALL=C

: "${UPLOAD_DIR:?}"
files="$UPLOAD_DIR/files/config"

log() { printf '==> 40-harden: %s\n' "$*"; }

log "kernel parameters"
install -m 0644 "$files/sysctl-90-weft-host.conf" /etc/sysctl.d/90-weft-host.conf
install -m 0644 "$files/modprobe-weft.conf" /etc/modprobe.d/weft.conf
install -m 0644 "$files/modules-load-weft.conf" /etc/modules-load.d/weft.conf
install -m 0644 "$files/udev-65-weft-kvm.rules" /etc/udev/rules.d/65-weft-kvm.rules

# prod-host-setup.md: limit kernel logging to the serial console, which a
# guest-triggered message flood could otherwise slow the host down with.
grubby --update-kernel=ALL --args="quiet loglevel=1"

# Kernel modules the host agent relies on must exist for the kernel that
# boots, not only the one running this build.
kernel="$(grubby --default-kernel | sed 's|^/boot/vmlinuz-||')"
for m in kvm kvm_intel kvm_amd tun veth xt_REDIRECT xt_conntrack nf_nat; do
  modinfo -k "$kernel" "$m" >/dev/null || { echo "kernel $kernel lacks module $m" >&2; exit 1; }
done

log "cloud-init, journald, core dumps"
install -m 0644 "$files/cloud-99-weft.cfg" /etc/cloud/cloud.cfg.d/99-weft.cfg
install -d -m 0755 /etc/systemd/journald.conf.d /etc/systemd/coredump.conf.d
install -m 0644 "$files/journald-weft.conf" /etc/systemd/journald.conf.d/weft.conf
install -m 0644 "$files/coredump-weft.conf" /etc/systemd/coredump.conf.d/weft.conf
install -m 0644 "$files/limits-weft.conf" /etc/security/limits.d/90-weft.conf

log "accounts"
passwd -l root >/dev/null
# SELinux stays in the Amazon Linux 2023 default (permissive); Firecracker's
# jailer provides the per-VM isolation (chroot, namespaces, seccomp, cgroups,
# unprivileged UID per VM).
