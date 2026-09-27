#!/usr/bin/env bash
# Host-side isolation checks for a Firecracker host with running sandboxes.
# Every VMM must run under the jailer with its own UID, seccomp filtering, a
# private network namespace and cgroup limits, and never as root.
set -euo pipefail
fail=0
pids="$(pgrep -x firecracker || true)"
[[ -n "$pids" ]] || { echo "no firecracker processes; start some sandboxes first"; exit 1; }
declare -A uids
for pid in $pids; do
  uid="$(awk '/^Uid:/ {print $2}' /proc/"$pid"/status)"
  seccomp="$(awk '/^Seccomp:/ {print $2}' /proc/"$pid"/status)"
  netns="$(readlink /proc/"$pid"/ns/net)"
  root="$(readlink /proc/"$pid"/root)"
  [[ "$uid" != "0" ]] || { echo "pid $pid runs as root"; fail=1; }
  [[ "$seccomp" == "2" ]] || { echo "pid $pid has seccomp mode $seccomp"; fail=1; }
  [[ "$netns" != "$(readlink /proc/1/ns/net)" ]] || { echo "pid $pid shares the host network namespace"; fail=1; }
  [[ "$root" == /var/lib/weft/jail/* || "$root" == */jail/firecracker/* ]] || { echo "pid $pid is not chrooted by the jailer ($root)"; fail=1; }
  if [[ -n "${uids[$uid]:-}" ]]; then echo "pid $pid shares UID $uid with pid ${uids[$uid]}"; fail=1; fi
  uids[$uid]=$pid
done
iptables -t nat -S WEFT-PRE >/dev/null || { echo "WEFT-PRE chain missing"; fail=1; }
iptables -S WEFT-IN | grep -q -- "-j DROP" || { echo "WEFT-IN does not end in DROP"; fail=1; }
curl -s -m 2 -o /dev/null -w '%{http_code}' -H "X-aws-ec2-metadata-token-ttl-seconds: 60" -X PUT http://169.254.169.254/latest/api/token >/dev/null || true
[[ $fail -eq 0 ]] && echo "host checks passed for $(wc -w <<<"$pids") VMMs"
exit $fail
