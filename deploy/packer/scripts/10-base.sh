#!/usr/bin/env bash
# Base operating system: current security fixes, the packages the host agent
# needs, no swap, SSM agent on.
set -euo pipefail
export LC_ALL=C

log() { printf '==> 10-base: %s\n' "$*"; }

# Move to the newest Amazon Linux 2023 release for current fixes, then lock
# dnf to it so later package operations on a host stay on the same release.
log "applying updates"
dnf -y -q upgrade --releasever=latest
release="$(rpm -q --qf '%{VERSION}\n' system-release | head -n1)"
printf '%s\n' "$release" > /etc/dnf/vars/releasever
log "Amazon Linux release $release"

# iproute: ip, ip netns (per-sandbox network namespaces)
# iptables-nft: iptables, iptables-restore, ip6tables-restore (host agent rules)
# e2fsprogs: mkfs.ext4 -d (template root filesystems; needs >= 1.43)
# xfsprogs: the reflink data volume
# util-linux: mount, blkid, lsblk; nvme-cli and mdadm: instance store
# amazon-cloudwatch-agent: ships host logs; logrotate: rotates them
log "installing packages"
dnf -y -q install \
  iproute \
  iptables-nft \
  e2fsprogs \
  xfsprogs \
  util-linux \
  nvme-cli \
  mdadm \
  jq \
  tar \
  gzip \
  logrotate \
  amazon-cloudwatch-agent \
  amazon-ssm-agent

e2fs_version="$(mkfs.ext4 -V 2>&1 | head -n1 | sed -E 's/^mke2fs ([0-9.]+).*/\1/')"
if [[ "$(printf '%s\n1.43\n' "$e2fs_version" | sort -V | head -n1)" != "1.43" ]]; then
  echo "e2fsprogs $e2fs_version is older than 1.43 (mkfs.ext4 -d is required)" >&2
  exit 1
fi
command -v iptables-restore >/dev/null && command -v ip6tables-restore >/dev/null
ip netns list >/dev/null

# No swap anywhere (Firecracker production host setup: guest memory must not
# reach disk). Amazon Linux 2023 ships none; make sure nothing adds it.
log "disabling swap"
swapoff -a
sed -i -E '/\sswap\s/d' /etc/fstab
dnf -y -q remove 'zram-generator*' >/dev/null 2>&1 || true
systemctl mask swap.target

systemctl enable amazon-ssm-agent.service
