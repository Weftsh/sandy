#!/usr/bin/env bash
# Installs the Weft binaries, guest artifacts, helper scripts and systemd
# units. Every uploaded binary must match the SHA-256 the release workflow
# computed when it built it.
set -euo pipefail
export LC_ALL=C

: "${UPLOAD_DIR:?}" "${WEFT_VERSION:?}"
: "${HOST_AGENT_SHA256:?}" "${GUEST_INIT_SHA256:?}" "${ENVD_SHA256:?}" "${VMLINUX_SHA256:?}"

log() { printf '==> 30-weft: %s\n' "$*"; }

verify() {
  local file="$1" expected="$2"
  echo "${expected}  ${file}" | sha256sum --quiet -c - || {
    echo "checksum mismatch for ${file}" >&2
    exit 1
  }
}

log "verifying build inputs"
verify "$UPLOAD_DIR/bin/weft-host-agent" "$HOST_AGENT_SHA256"
verify "$UPLOAD_DIR/guest/weft-guest-init" "$GUEST_INIT_SHA256"
verify "$UPLOAD_DIR/guest/envd" "$ENVD_SHA256"
verify "$UPLOAD_DIR/guest/vmlinux" "$VMLINUX_SHA256"

files="$UPLOAD_DIR/files"

log "installing binaries"
install -m 0755 -o root -g root "$UPLOAD_DIR/bin/weft-host-agent" /usr/local/bin/weft-host-agent
install -d -m 0755 -o root -g root /opt/weft /opt/weft/guest
install -m 0644 -o root -g root "$UPLOAD_DIR/guest/vmlinux" /opt/weft/guest/vmlinux
install -m 0755 -o root -g root "$UPLOAD_DIR/guest/envd" /opt/weft/guest/envd
install -m 0755 -o root -g root "$UPLOAD_DIR/guest/weft-guest-init" /opt/weft/guest/weft-guest-init

/usr/local/bin/weft-host-agent --version
/usr/local/bin/weft-host-agent run --help >/dev/null

log "installing licenses and notices"
install -d -m 0755 /usr/local/share/doc/weft-sandboxes
install -m 0644 "$files/licenses/"* /usr/local/share/doc/weft-sandboxes/

log "installing helper scripts and units"
install -m 0755 -o root -g root "$files/bin/weft-host-bootstrap" /usr/local/sbin/weft-host-bootstrap
install -m 0755 -o root -g root "$files/bin/weft-data-volume" /usr/local/sbin/weft-data-volume
install -m 0755 -o root -g root "$files/bin/weft-host-tuning" /usr/local/sbin/weft-host-tuning
for unit in weft-data-volume.service weft-host-tuning.service weft-host-agent.service; do
  install -m 0644 -o root -g root "$files/systemd/$unit" "/etc/systemd/system/$unit"
done
install -m 0644 -o root -g root "$files/config/logrotate-weft" /etc/logrotate.d/weft

install -d -m 0755 -o root -g root /etc/weft /var/lib/weft
install -d -m 0750 -o root -g root /var/log/weft

systemctl daemon-reload
# weft-host-agent.service is skipped (ConditionPathExists) until
# weft-host-bootstrap writes /etc/weft/host-agent.env from user data.
systemctl enable weft-data-volume.service weft-host-tuning.service weft-host-agent.service

cat > /opt/weft/MANIFEST <<EOF
weft_version=${WEFT_VERSION}
git_commit=${WEFT_GIT_COMMIT:-unknown}
firecracker_version=${FIRECRACKER_VERSION:-unknown}
weft-host-agent sha256=${HOST_AGENT_SHA256}
weft-guest-init sha256=${GUEST_INIT_SHA256}
envd sha256=${ENVD_SHA256}
vmlinux sha256=${VMLINUX_SHA256}
EOF
chmod 0644 /opt/weft/MANIFEST
