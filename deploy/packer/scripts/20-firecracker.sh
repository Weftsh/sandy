#!/usr/bin/env bash
# Installs the pinned Firecracker and jailer release, verifying the archive
# and both binaries against hashes pinned in firecracker.auto.pkrvars.hcl.
set -euo pipefail
export LC_ALL=C

: "${FIRECRACKER_VERSION:?}" "${FIRECRACKER_TGZ_SHA256:?}" "${FIRECRACKER_SHA256:?}" "${JAILER_SHA256:?}"

log() { printf '==> 20-firecracker: %s\n' "$*"; }

version="$FIRECRACKER_VERSION"
arch=x86_64
archive="firecracker-v${version}-${arch}.tgz"
url="https://github.com/firecracker-microvm/firecracker/releases/download/v${version}/${archive}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

log "downloading Firecracker v${version}"
curl --proto '=https' --tlsv1.2 -fsSL --retry 5 --retry-delay 3 -o "$work/$archive" "$url"
echo "${FIRECRACKER_TGZ_SHA256}  $work/$archive" | sha256sum --quiet -c -

tar -xzf "$work/$archive" -C "$work" --no-same-owner
release_dir="$work/release-v${version}-${arch}"
fc="$release_dir/firecracker-v${version}-${arch}"
jailer="$release_dir/jailer-v${version}-${arch}"
echo "${FIRECRACKER_SHA256}  $fc" | sha256sum --quiet -c -
echo "${JAILER_SHA256}  $jailer" | sha256sum --quiet -c -
# The release's own checksum list must agree as well.
(cd "$release_dir" && sha256sum --quiet -c SHA256SUMS)

install -m 0755 -o root -g root "$fc" /usr/local/bin/firecracker
install -m 0755 -o root -g root "$jailer" /usr/local/bin/jailer
install -d -m 0755 /usr/local/share/doc/firecracker
install -m 0644 "$release_dir/LICENSE" "$release_dir/NOTICE" "$release_dir/THIRD-PARTY" /usr/local/share/doc/firecracker/

/usr/local/bin/firecracker --version | grep -qx "Firecracker v${version}"
/usr/local/bin/jailer --version | grep -qx "Jailer v${version}"
log "installed Firecracker and jailer v${version}"
