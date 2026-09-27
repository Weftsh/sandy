#!/usr/bin/env bash
# Builds the Weft guest kernel: an uncompressed x86_64 vmlinux for Firecracker.
#
# Usage: guest/kernel/build.sh [OUT_DIR]      (default: dist/guest)
#
# 1. Downloads the pinned Linux longterm release from kernel.org (or takes
#    $KERNEL_TARBALL) and checks it against the SHA-256 pinned in VERSION.
# 2. Starts from Firecracker's x86_64 microVM guest configuration (vendored
#    in this directory, hash-checked) and merges weft.config over it.
# 3. Runs `make olddefconfig`, fails if any line of weft.config did not
#    survive it, and builds vmlinux.
#
# Outputs OUT_DIR/vmlinux and OUT_DIR/vmlinux.config (the final .config).
#
# Environment:
#   KERNEL_TARBALL   local linux-<version>.tar.xz to use instead of downloading
#                    (still checked against the pinned hash)
#   KERNEL_WORK_DIR  build here and keep the tree (default: a temporary directory)
#   JOBS             parallel make jobs (default: nproc)
#   CROSS_COMPILE    toolchain prefix when the build host is not x86_64
#
# Build dependencies on Debian/Ubuntu:
#   build-essential bc bison flex libelf-dev libssl-dev curl xz-utils
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
source <(grep -E '^[A-Z0-9_]+=' "$HERE/VERSION")
OUT_DIR="${1:-$ROOT/dist/guest}"
JOBS="${JOBS:-$(nproc)}"

die() {
  echo "guest/kernel/build.sh: $*" >&2
  exit 1
}

for tool in curl tar xz make gcc bc bison flex sha256sum od; do
  command -v "$tool" >/dev/null || die "missing build dependency: $tool"
done
if [[ "$(uname -m)" != "x86_64" && -z "${CROSS_COMPILE:-}" ]]; then
  die "the guest kernel is x86_64; set CROSS_COMPILE to build on $(uname -m)"
fi

echo "$FC_CONFIG_SHA256  $HERE/$FC_CONFIG" | sha256sum --check --quiet - ||
  die "$FC_CONFIG does not match FC_CONFIG_SHA256 in VERSION"

if [[ -n "${KERNEL_WORK_DIR:-}" ]]; then
  WORK="$KERNEL_WORK_DIR"
  mkdir -p "$WORK"
else
  WORK="$(mktemp -d)"
  trap 'rm -rf "$WORK"' EXIT
fi

TARBALL="$WORK/linux-$LINUX_VERSION.tar.xz"
if [[ -n "${KERNEL_TARBALL:-}" ]]; then
  cp "$KERNEL_TARBALL" "$TARBALL"
elif [[ ! -f "$TARBALL" ]]; then
  curl -fsSL --proto '=https' --tlsv1.2 -o "$TARBALL.part" \
    "https://cdn.kernel.org/pub/linux/kernel/v${LINUX_VERSION%%.*}.x/linux-$LINUX_VERSION.tar.xz"
  mv "$TARBALL.part" "$TARBALL"
fi
echo "$LINUX_SHA256  $TARBALL" | sha256sum --check --quiet - ||
  die "linux-$LINUX_VERSION.tar.xz does not match LINUX_SHA256 in VERSION"

SRC="$WORK/linux-$LINUX_VERSION"
rm -rf "$SRC"
tar -xJf "$TARBALL" -C "$WORK"

# Fixed build identity so rebuilds of the same source differ as little as
# possible. The timestamp is the release's own (the tarball's file times).
MAKE=(make -C "$SRC" ARCH=x86_64
  KBUILD_BUILD_USER=weft KBUILD_BUILD_HOST=weft KBUILD_BUILD_VERSION=1
  KBUILD_BUILD_TIMESTAMP="$(date -u -d "@$(stat -c %Y "$SRC/Makefile")" '+%Y-%m-%d %H:%M:%S UTC')")
if [[ -n "${CROSS_COMPILE:-}" ]]; then
  MAKE+=(CROSS_COMPILE="$CROSS_COMPILE")
fi

cp "$HERE/$FC_CONFIG" "$SRC/.config"
(cd "$SRC" && ./scripts/kconfig/merge_config.sh -m -O "$SRC" "$SRC/.config" "$HERE/weft.config") >/dev/null
"${MAKE[@]}" -s olddefconfig

# olddefconfig silently drops settings whose dependencies are not met.
# Everything weft.config asks for must have made it into the final config.
rejected=0
while IFS= read -r line; do
  case "$line" in
    CONFIG_*=*)
      if ! grep -qxF -- "$line" "$SRC/.config"; then
        echo "not in the final config: $line (got: $(grep -E "^(# )?${line%%=*}[= ]" "$SRC/.config" || echo unset))" >&2
        rejected=1
      fi
      ;;
    "# CONFIG_"*" is not set")
      symbol="${line#\# }"
      symbol="${symbol%% *}"
      if grep -q "^$symbol=" "$SRC/.config"; then
        echo "still enabled in the final config: $(grep "^$symbol=" "$SRC/.config")" >&2
        rejected=1
      fi
      ;;
  esac
done <"$HERE/weft.config"
[[ "$rejected" == 0 ]] || die "make olddefconfig rejected parts of weft.config (see above)"

"${MAKE[@]}" -j"$JOBS" vmlinux

magic="$(head -c 4 "$SRC/vmlinux" | od -An -tx1 | tr -d ' \n')"
[[ "$magic" == "7f454c46" ]] || die "vmlinux is not an ELF image"

mkdir -p "$OUT_DIR"
install -m 0644 "$SRC/vmlinux" "$OUT_DIR/vmlinux"
install -m 0644 "$SRC/.config" "$OUT_DIR/vmlinux.config"
release="$("${MAKE[@]}" -s kernelrelease)"
echo "Linux $release ($(sha256sum "$OUT_DIR/vmlinux" | cut -d' ' -f1)) -> $OUT_DIR/vmlinux"
