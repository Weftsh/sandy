#!/usr/bin/env bash
# Host-side isolation checks for a Firecracker host with running sandboxes.
# Every VMM must run under the jailer with its own UID, seccomp filtering,
# private network, mount and PID namespaces, inside its jail, and never as
# root.
#
# WEFT_JAIL_BASE is the host agent's chroot base (default /var/lib/weft/jail,
# as on host AMIs; the development stack uses /var/lib/weft-dev/jail).
set -euo pipefail
jail_base="${WEFT_JAIL_BASE:-/var/lib/weft/jail}"
fail=0
pids="$(pgrep -x firecracker || true)"
[[ -n "$pids" ]] || { echo "no firecracker processes; start some sandboxes first"; exit 1; }
# The jailer pivots into the jail inside a new mount namespace, so from the
# host /proc/<pid>/root reads "/"; compare the directory itself instead.
declare -A jails
for dir in "$jail_base"/firecracker/*/root; do
  [[ -d "$dir" ]] && jails[$(stat -c '%d:%i' "$dir")]=$dir
done
declare -A uids
for pid in $pids; do
  uid="$(awk '/^Uid:/ {print $2}' /proc/"$pid"/status)"
  seccomp="$(awk '/^Seccomp:/ {print $2}' /proc/"$pid"/status)"
  root_id="$(stat -Lc '%d:%i' /proc/"$pid"/root/)"
  [[ "$uid" != "0" ]] || { echo "pid $pid runs as root"; fail=1; }
  [[ "$seccomp" == "2" ]] || { echo "pid $pid has seccomp mode $seccomp"; fail=1; }
  for ns in net mnt pid; do
    [[ "$(readlink /proc/"$pid"/ns/$ns)" != "$(readlink /proc/1/ns/$ns)" ]] ||
      { echo "pid $pid shares the host $ns namespace"; fail=1; }
  done
  [[ -n "${jails[$root_id]:-}" ]] || { echo "pid $pid is not confined to a jail under $jail_base"; fail=1; }
  if [[ -n "${uids[$uid]:-}" ]]; then echo "pid $pid shares UID $uid with pid ${uids[$uid]}"; fail=1; fi
  uids[$uid]=$pid
done
iptables -t nat -S WEFT-PRE >/dev/null || { echo "WEFT-PRE chain missing"; fail=1; }
iptables -S WEFT-IN | grep -q -- "-j DROP" || { echo "WEFT-IN does not end in DROP"; fail=1; }
curl -s -m 2 -o /dev/null -w '%{http_code}' -H "X-aws-ec2-metadata-token-ttl-seconds: 60" -X PUT http://169.254.169.254/latest/api/token >/dev/null || true
[[ $fail -eq 0 ]] && echo "host checks passed for $(wc -w <<<"$pids") VMMs"
exit $fail
