#!/usr/bin/env bash
# Final step: no SSH on the image (hosts are reached with SSM Session
# Manager), and nothing instance-specific left behind. The SSH session running
# this script survives the removal of sshd until the script ends; Packer then
# stops the instance through the EC2 API.
set -euo pipefail
export LC_ALL=C

: "${UPLOAD_DIR:?}"

log() { printf '==> 90-finalize: %s\n' "$*"; }

rm -rf "$UPLOAD_DIR"

log "removing sshd and EC2 Instance Connect"
dnf -y -q remove openssh-server 'ec2-instance-connect*'
systemctl mask sshd.service sshd.socket sshd-keygen.target >/dev/null 2>&1 || true
rm -f /etc/ssh/ssh_host_*
rm -f /root/.ssh/authorized_keys /home/ec2-user/.ssh/authorized_keys

log "cleaning up"
dnf -q clean all
rm -rf /var/cache/dnf
cloud-init clean --logs
# A fresh machine ID on every instance.
truncate -s 0 /etc/machine-id
rm -f /var/lib/systemd/random-seed
find /var/log -type f \( -name '*.log' -o -name '*.gz' \) -delete
rm -rf /var/log/journal/*
rm -f /root/.bash_history /home/ec2-user/.bash_history
sync
log "done"
