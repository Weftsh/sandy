#!/usr/bin/env bash
# Runs the whole Weft Sandboxes stack on one Linux machine for development
# and CI: control plane, egress gateway and host agent.
#
#   scripts/dev-stack.sh build [--firecracker]                  # as yourself
#   sudo env "PATH=$PATH" scripts/dev-stack.sh up --no-build [--https] [--firecracker]
#   sudo scripts/dev-stack.sh down
#   scripts/dev-stack.sh env          # print the E2B_* variables for SDKs
#
# Starting needs root (network namespaces, iptables); building does not, and
# should run as you so your toolchains are used and nothing in the checkout
# ends up owned by root. When already root (CI containers), `up` builds too.
#
# By default sandboxes use the namespace runtime, which does NOT isolate them
# from the host. Use it only on machines you are happy to run untrusted code
# on as root.
#
# --firecracker runs each sandbox as a Firecracker microVM through the jailer,
# as production hosts do. It needs /dev/kvm and cgroup v2. `build
# --firecracker` also builds the guest kernel (about 20 minutes, once) and
# downloads the Firecracker release pinned for host AMIs into
# .weft/firecracker. VM data and jails live in $WEFT_DEV_FC_DIR (default
# /var/lib/weft-dev), which keeps jail socket paths short.
#
# --https serves the edge proxy over TLS on https://<port>-<id>.127-0-0-1.sslip.io:3443
# (a public wildcard name for 127.0.0.1) with a throwaway CA, so the SDKs use
# production-style host routing instead of E2B_SANDBOX_URL.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATE="${WEFT_DEV_STATE:-$ROOT/.weft/dev}"
BASE_IMAGE="${WEFT_DEV_BASE_IMAGE:-mirror.gcr.io/library/python:3.12-slim}"
API_PORT=3000
EDGE_PORT=3001
HTTPS_EDGE_PORT=3443
ECHO_PORT=18443
FC_BIN_DIR="$ROOT/.weft/firecracker"
FC_DIR="${WEFT_DEV_FC_DIR:-/var/lib/weft-dev}"

log() { printf '\033[1m[dev-stack]\033[0m %s\n' "$*" >&2; }

# Under sudo, hands files the developer uses (the environment file, test
# certificates, the dev license key) back to the invoking user.
give_to_user() {
  [[ -n "${SUDO_UID:-}" ]] || return 0
  local f
  for f in "$@"; do
    [[ -e "$f" ]] && chown "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$f"
  done
  return 0
}
die() { log "error: $*"; exit 1; }

remove_host_rules() {
  # The host agent's host-level chains match only sandbox interfaces (wv+),
  # so they are inert once it stops; remove them so `down` leaves no rules.
  while iptables -w -t nat -D PREROUTING -i wv+ -j WEFT-PRE 2>/dev/null; do :; done
  while iptables -w -D INPUT -i wv+ -j WEFT-IN 2>/dev/null; do :; done
  while iptables -w -D FORWARD -o wv+ -j WEFT-FWD 2>/dev/null; do :; done
  while iptables -w -D FORWARD -i wv+ -j WEFT-FWD 2>/dev/null; do :; done
  for chain in WEFT-IN WEFT-FWD; do
    iptables -w -F "$chain" 2>/dev/null && iptables -w -X "$chain" 2>/dev/null
  done
  iptables -w -t nat -F WEFT-PRE 2>/dev/null && iptables -w -t nat -X WEFT-PRE 2>/dev/null
  return 0
}

# Kills microVMs a stopped host agent left running (processes whose root is
# a jail), then removes their cgroups and jails.
remove_firecracker_leftovers() {
  [[ -d "$FC_DIR/jail" ]] || return 0
  local p root cg
  for p in /proc/[0-9]*; do
    root="$(readlink "$p/root" 2>/dev/null)" || continue
    if [[ "$root" == "$FC_DIR/jail/"* ]]; then kill -9 "${p#/proc/}" 2>/dev/null || true; fi
  done
  sleep 0.5
  for cg in /sys/fs/cgroup/firecracker/*/; do
    [[ -d "$cg" ]] && rmdir "$cg" 2>/dev/null
  done
  rm -rf "$FC_DIR/jail"
  return 0
}

stop_all() {
  # The host agent first, so it can stop its sandboxes while the control
  # plane is still up; wait for each process to exit before going on.
  for name in host-agent egress-gateway control-plane; do
    [[ -f "$STATE/$name.pid" ]] || continue
    local pid
    pid="$(cat "$STATE/$name.pid")"
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 60); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.5
    done
    kill -9 "$pid" 2>/dev/null || true
    rm -f "$STATE/$name.pid"
  done
}

pinned() { # name: a value from the host AMI's Firecracker pins
  sed -n "s/^$1 *= *\"\(.*\)\"$/\1/p" "$ROOT/deploy/packer/firecracker.auto.pkrvars.hcl"
}

# Downloads the Firecracker and jailer release that host AMIs install,
# checked against the same pinned hashes (deploy/packer/scripts/20-firecracker.sh).
fetch_firecracker() {
  local version archive work rel
  version="$(pinned firecracker_version)"
  if [[ -x "$FC_BIN_DIR/firecracker" && -x "$FC_BIN_DIR/jailer" ]] &&
    [[ "$("$FC_BIN_DIR/firecracker" --version 2>/dev/null | head -n 1)" == "Firecracker v$version" ]]; then
    return 0
  fi
  log "downloading Firecracker v$version"
  archive="firecracker-v${version}-x86_64.tgz"
  work="$(mktemp -d)"
  curl --proto '=https' --tlsv1.2 -fsSL --retry 5 --retry-delay 3 -o "$work/$archive" \
    "https://github.com/firecracker-microvm/firecracker/releases/download/v${version}/${archive}"
  echo "$(pinned firecracker_tgz_sha256)  $work/$archive" | sha256sum --quiet -c -
  tar -xzf "$work/$archive" -C "$work" --no-same-owner
  rel="$work/release-v${version}-x86_64"
  echo "$(pinned firecracker_sha256)  $rel/firecracker-v${version}-x86_64" | sha256sum --quiet -c -
  echo "$(pinned jailer_sha256)  $rel/jailer-v${version}-x86_64" | sha256sum --quiet -c -
  mkdir -p "$FC_BIN_DIR"
  install -m 0755 "$rel/firecracker-v${version}-x86_64" "$FC_BIN_DIR/firecracker"
  install -m 0755 "$rel/jailer-v${version}-x86_64" "$FC_BIN_DIR/jailer"
  rm -rf "$work"
}

build() {
  local firecracker=0 arg
  for arg in "$@"; do
    case "$arg" in
      --firecracker) firecracker=1 ;;
      *) die "unknown flag $arg" ;;
    esac
  done
  log "building"
  if [[ ! -x "$ROOT/dist/guest/envd" ]]; then
    "$ROOT/guest/envd/build.sh" "$ROOT/dist/guest"
  fi
  rustup target add x86_64-unknown-linux-musl >/dev/null 2>&1 || true
  (cd "$ROOT" && cargo build --release -p weft-guest-init --target x86_64-unknown-linux-musl)
  cp "$ROOT/target/x86_64-unknown-linux-musl/release/weft-guest-init" "$ROOT/dist/guest/"
  (cd "$ROOT" && cargo build --release -p weft-host-agent -p weft-egress-gateway)
  (cd "$ROOT" && pnpm install --frozen-lockfile && pnpm -r build)
  if [[ $firecracker -eq 1 ]]; then
    # Delete dist/guest/vmlinux to rebuild after changing guest/kernel/.
    [[ -f "$ROOT/dist/guest/vmlinux" ]] || "$ROOT/guest/kernel/build.sh" "$ROOT/dist/guest"
    fetch_firecracker
  fi
}

gen_ca() { # dir name cn
  openssl ecparam -name prime256v1 -genkey -noout -out "$1/$2.key.pem" 2>/dev/null
  openssl req -x509 -new -key "$1/$2.key.pem" -sha256 -days 30 -subj "/CN=$3" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$1/$2.pem" 2>/dev/null
}

wait_http() { # url tries
  for _ in $(seq 1 "$2"); do
    curl -sf --noproxy '*' -o /dev/null "$1" && return 0
    sleep 1
  done
  return 1
}

show_logs() {
  local f
  for f in "$STATE"/control-plane.log "$STATE"/egress-gateway.log "$STATE"/host-agent.log; do
    [[ -f "$f" ]] || continue
    printf '\n==> %s <==\n' "$f" >&2
    tail -n 40 "$f" >&2
  done
}

api() { # method path [body]
  curl -sf --noproxy '*' -X "$1" -H "X-API-Key: $WEFT_BOOTSTRAP_ADMIN_KEY" -H 'content-type: application/json' \
    ${3:+-d "$3"} "http://127.0.0.1:$API_PORT$2"
}

up() {
  local https=0 do_build=1 firecracker=0 build_flags=()
  for arg in "$@"; do
    case "$arg" in
      --https) https=1 ;;
      --no-build) do_build=0 ;;
      --firecracker) firecracker=1 build_flags=(--firecracker) ;;
      *) die "unknown flag $arg" ;;
    esac
  done
  [[ $EUID -eq 0 ]] || die "run as root: the host agent creates namespaces and iptables rules"
  if [[ $do_build -eq 1 && -n "${SUDO_USER:-}" ]]; then
    die "build as yourself first, then start without building:
    scripts/dev-stack.sh build ${build_flags[*]}
    sudo env \"PATH=\$PATH\" scripts/dev-stack.sh up --no-build ${build_flags[*]}"
  fi
  command -v ip >/dev/null || die "iproute2 is required"
  command -v iptables >/dev/null || die "iptables is required"
  command -v openssl >/dev/null || die "openssl is required"

  mkdir -p "$STATE" && chmod 700 "$STATE"
  stop_all
  remove_firecracker_leftovers
  [[ $do_build -eq 1 ]] && build "${build_flags[@]}"
  if [[ $firecracker -eq 1 ]]; then
    [[ -c /dev/kvm ]] || die "--firecracker needs /dev/kvm"
    [[ -f /sys/fs/cgroup/cgroup.controllers ]] || die "--firecracker needs cgroup v2"
    command -v mkfs.ext4 >/dev/null || die "--firecracker needs mkfs.ext4 (e2fsprogs)"
    [[ -x "$FC_BIN_DIR/firecracker" && -x "$FC_BIN_DIR/jailer" ]] ||
      die "Firecracker is missing; run: scripts/dev-stack.sh build --firecracker"
    [[ -f "$ROOT/dist/guest/vmlinux" ]] ||
      die "the guest kernel is missing; run: scripts/dev-stack.sh build --firecracker"
  fi

  # Throwaway development secrets, regenerated on every start.
  export WEFT_DEV_MODE=1
  WEFT_DEV_TOKEN="dev-$(openssl rand -hex 24)"
  WEFT_BOOTSTRAP_ADMIN_KEY="weft_sk_dev_$(openssl rand -hex 24)"
  export WEFT_DEV_TOKEN WEFT_BOOTSTRAP_ADMIN_KEY
  export WEFT_BOOTSTRAP_TEMPLATES="base=$BASE_IMAGE"
  export WEFT_API_LISTEN="127.0.0.1:$API_PORT"
  gen_ca "$STATE" egress-ca "Weft Sandboxes development egress CA"
  export WEFT_EGRESS_CA_CERT_FILE="$STATE/egress-ca.pem"
  # A license signing key the development control plane trusts as kid
  # "dev-1", so license keys can be issued and installed locally with
  # `weft-license issue --private-key $STATE/license/license-signing.key.pem`.
  rm -rf "$STATE/license"
  node "$ROOT/packages/license/dist/cli.js" keygen --out "$STATE/license" >/dev/null
  WEFT_DEV_LICENSE_PUBLIC_KEYS="$(python3 -c 'import json,sys; print(json.dumps({"dev-1": open(sys.argv[1]).read()}))' "$STATE/license/license-signing.pub.pem")"
  export WEFT_DEV_LICENSE_PUBLIC_KEYS
  # Nothing answers license checks locally; keep them off the network.
  export WEFT_LICENSE_ENDPOINT="http://127.0.0.1:9/v1/check"

  # A local HTTPS upstream (echo.weft.test) the egress and credential-proxy
  # tests reach through the gateway, plus a secret for the gateway to inject.
  gen_ca "$STATE" upstream-ca "Weft Sandboxes development upstream CA"
  openssl ecparam -name prime256v1 -genkey -noout -out "$STATE/echo.key.pem" 2>/dev/null
  openssl req -new -key "$STATE/echo.key.pem" -subj "/CN=echo.weft.test" -out "$STATE/echo.csr" 2>/dev/null
  printf 'subjectAltName=DNS:echo.weft.test\nextendedKeyUsage=serverAuth\n' > "$STATE/echo.ext"
  openssl x509 -req -in "$STATE/echo.csr" -CA "$STATE/upstream-ca.pem" -CAkey "$STATE/upstream-ca.key.pem" -CAcreateserial \
    -days 30 -sha256 -extfile "$STATE/echo.ext" -out "$STATE/echo.pem" 2>/dev/null
  local echo_secret
  echo_secret="echo-secret-$(openssl rand -hex 16)"
  printf '{"weft-dev-echo-secret": "%s"}\n' "$echo_secret" > "$STATE/dev-secrets.json"
  chmod 600 "$STATE/dev-secrets.json" "$STATE"/*.key.pem

  local domain="weft.test"
  if [[ $https -eq 1 ]]; then
    domain="127-0-0-1.sslip.io:$HTTPS_EDGE_PORT"
    gen_ca "$STATE" edge-ca "Weft Sandboxes development edge CA"
    openssl ecparam -name prime256v1 -genkey -noout -out "$STATE/edge.key.pem" 2>/dev/null
    openssl req -new -key "$STATE/edge.key.pem" -subj "/CN=*.127-0-0-1.sslip.io" -out "$STATE/edge.csr" 2>/dev/null
    printf 'subjectAltName=DNS:*.127-0-0-1.sslip.io,DNS:127-0-0-1.sslip.io\nextendedKeyUsage=serverAuth\n' > "$STATE/edge.ext"
    openssl x509 -req -in "$STATE/edge.csr" -CA "$STATE/edge-ca.pem" -CAkey "$STATE/edge-ca.key.pem" -CAcreateserial \
      -days 30 -sha256 -extfile "$STATE/edge.ext" -out "$STATE/edge.pem" 2>/dev/null
    export WEFT_EDGE_LISTEN="127.0.0.1:$HTTPS_EDGE_PORT"
    export WEFT_EDGE_TLS_CERT_FILE="$STATE/edge.pem" WEFT_EDGE_TLS_KEY_FILE="$STATE/edge.key.pem"
  else
    export WEFT_EDGE_LISTEN="127.0.0.1:$EDGE_PORT"
  fi
  export WEFT_DOMAIN="$domain"

  log "starting control plane (api :$API_PORT, edge ${WEFT_EDGE_LISTEN##*:})"
  # `exec` keeps the recorded PID equal to the process's PID.
  (cd "$ROOT" && exec nohup node packages/control-plane/dist/main.js </dev/null >"$STATE/control-plane.log" 2>&1) &
  echo $! >"$STATE/control-plane.pid"
  wait_http "http://127.0.0.1:$API_PORT/health" 30 || die "control plane did not start; see $STATE/control-plane.log"

  log "starting egress gateway (:15000)"
  (cd "$ROOT" && exec nohup ./target/release/weft-egress-gateway --dev \
    --listen 127.0.0.1:15000 --health-listen 127.0.0.1:15080 \
    --control-plane-url "http://127.0.0.1:$API_PORT" --dev-token "$WEFT_DEV_TOKEN" \
    --ca-cert-file "$STATE/egress-ca.pem" --ca-key-file "$STATE/egress-ca.key.pem" \
    --dev-secrets-file "$STATE/dev-secrets.json" \
    --dev-resolve "echo.weft.test=127.0.0.1:$ECHO_PORT" --dev-upstream-ca-file "$STATE/upstream-ca.pem" \
    </dev/null >"$STATE/egress-gateway.log" 2>&1) &
  echo $! >"$STATE/egress-gateway.pid"

  local data_dir runtime_args
  if [[ $firecracker -eq 1 ]]; then
    log "starting host agent (Firecracker microVMs)"
    data_dir="$FC_DIR/host"
    mkdir -p "$FC_DIR/jail"
    runtime_args=(--runtime firecracker --kernel "$ROOT/dist/guest/vmlinux" --chroot-base "$FC_DIR/jail"
      --firecracker-bin "$FC_BIN_DIR/firecracker" --jailer-bin "$FC_BIN_DIR/jailer")
  else
    log "starting host agent (namespace runtime: NOT isolated)"
    data_dir="$STATE/host"
    runtime_args=(--runtime namespace --insecure-namespace-runtime)
  fi
  mkdir -p "$data_dir"
  (cd "$ROOT" && exec nohup ./target/release/weft-host-agent run \
    --host-id dev-host-1 --private-ip 127.0.0.1 \
    --control-plane-url "http://127.0.0.1:$API_PORT" --auth dev-token --dev-token "$WEFT_DEV_TOKEN" \
    "${runtime_args[@]}" \
    --data-dir "$data_dir" --guest-dir "$ROOT/dist/guest" \
    --egress-gateway 127.0.0.1:15000 --api-listen 127.0.0.1:5007 --tunnel-listen 127.0.0.1:5008 \
    --max-sandboxes "${WEFT_DEV_MAX_SANDBOXES:-32}" \
    </dev/null >"$STATE/host-agent.log" 2>&1) &
  echo $! >"$STATE/host-agent.pid"

  log "waiting for the base template ($BASE_IMAGE)"
  local status="" name
  for _ in $(seq 1 180); do
    status="$(api GET /weft/v1/templates | python3 -c 'import json,sys; t=[x for x in json.load(sys.stdin) if "base" in x["names"]]; print(t[0]["status"] if t else "")' 2>/dev/null || true)"
    [[ "$status" == "ready" || "$status" == "failed" ]] && break
    for name in control-plane egress-gateway host-agent; do
      kill -0 "$(cat "$STATE/$name.pid")" 2>/dev/null || { show_logs; die "the $name exited; see $STATE/$name.log"; }
    done
    sleep 2
  done
  [[ "$status" == "ready" ]] || { show_logs; die "base template is '${status:-missing}'; see $STATE/*.log"; }

  log "creating team and API key"
  local team key
  team="$(api POST /weft/v1/teams '{"name":"dev"}')"
  key="$(printf '%s' "$team" | python3 -c 'import json,sys; print(json.load(sys.stdin)["apiKey"]["key"])')"
  local team_id
  team_id="$(printf '%s' "$team" | python3 -c 'import json,sys; print(json.load(sys.stdin)["team"]["teamId"])')"
  {
    echo "export E2B_API_URL=http://127.0.0.1:$API_PORT"
    echo "export E2B_DOMAIN=$domain"
    echo "export E2B_API_KEY=$key"
    echo "export WEFT_ADMIN_KEY=$WEFT_BOOTSTRAP_ADMIN_KEY"
    # The weft-sandbox CLI reads these, so it works without a login.
    echo "export WEFT_API_URL=http://127.0.0.1:$API_PORT"
    echo "export WEFT_API_KEY=$WEFT_BOOTSTRAP_ADMIN_KEY"
    echo "export WEFT_DOMAIN=$domain"
    echo "export WEFT_DEV_TEAM_ID=$team_id"
    echo "export WEFT_DEV_ECHO_PORT=$ECHO_PORT"
    echo "export WEFT_DEV_ECHO_CERT=$STATE/echo.pem"
    echo "export WEFT_DEV_ECHO_KEY=$STATE/echo.key.pem"
    echo "export WEFT_DEV_UPSTREAM_CA=$STATE/upstream-ca.pem"
    echo "export WEFT_DEV_ECHO_SECRET=$echo_secret"
    echo "export WEFT_DEV_IMAGE=$BASE_IMAGE"
    echo "export WEFT_DEV_LICENSE_KEY=$STATE/license/license-signing.key.pem"
    # The escape suite adds its microVM boundary checks.
    [[ $firecracker -eq 1 ]] && echo "export WEFT_ESCAPE_RUNTIME=firecracker"
    if [[ $https -eq 1 ]]; then
      cat /etc/ssl/certs/ca-certificates.crt "$STATE/edge-ca.pem" > "$STATE/ca-bundle.pem"
      echo "export SSL_CERT_FILE=$STATE/ca-bundle.pem"
      echo "export NODE_EXTRA_CA_CERTS=$STATE/edge-ca.pem"
      echo "export NO_PROXY=\${NO_PROXY:+\$NO_PROXY,}.sslip.io,127.0.0.1,localhost"
      echo "unset E2B_SANDBOX_URL"
    else
      echo "export E2B_SANDBOX_URL=http://127.0.0.1:$EDGE_PORT"
      echo "export NO_PROXY=\${NO_PROXY:+\$NO_PROXY,}127.0.0.1,localhost"
    fi
  } > "$STATE/e2b.env"
  chmod 600 "$STATE/e2b.env"
  give_to_user "$ROOT/.weft" "$STATE" "$STATE/e2b.env" "$STATE/echo.pem" "$STATE/echo.key.pem" \
    "$STATE/upstream-ca.pem" "$STATE/edge-ca.pem" "$STATE/ca-bundle.pem" \
    "$STATE/license" "$STATE/license/license-signing.key.pem" "$STATE/license/license-signing.pub.pem"
  log "ready. Load the SDK settings with:  source $STATE/e2b.env"
}

case "${1:-}" in
  build) shift; build "$@" ;;
  up) shift; up "$@" ;;
  down) stop_all; remove_firecracker_leftovers; remove_host_rules; log "stopped" ;;
  env) cat "$STATE/e2b.env" ;;
  *) echo "usage: $0 build [--firecracker] | up [--https] [--no-build] [--firecracker] | down | env" >&2; exit 2 ;;
esac
