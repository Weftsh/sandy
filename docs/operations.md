# Operations

Day-to-day running of a stack. The stack's resources, parameters and IAM are
described in [deploy/README.md](../deploy/README.md).

## Health

| Check | How |
| --- | --- |
| API | `GET https://api.<domain>/health` returns `{"status":"ok","version":...}` |
| Hosts | `weft-sandbox hosts`: every host with its last heartbeat, runtime, version, capacity and sandbox count |
| Sandboxes | `weft-sandbox sandboxes`: every sandbox across teams |
| License | `weft-sandbox license status` |
| Load balancer | Target group health in the EC2 console, or CloudWatch `HealthyHostCount` |

Hosts send a heartbeat every few seconds. A host silent for 30 seconds gets no
new sandboxes; after two minutes its sandboxes are dropped from the API.

## Logs

All logs go to CloudWatch Logs, encrypted with the stack's KMS key, kept for
`LogRetentionDays` (default 365):

| Log group | Contents |
| --- | --- |
| `/weft/<stack>/control-plane` | Streams `api/`, `edge/`, `worker/`: JSON lines with sandbox, template and host events |
| `/weft/<stack>/egress-gateway` | Gateway events and the egress audit log ([egress.md](egress.md#audit-log)) |
| `/weft/<stack>/hosts` | `<instance-id>/host-agent`, `<instance-id>/bootstrap` |
| `/weft/<stack>/functions/*` | Custom-resource Lambdas (install, upgrade, uninstall) |
| `/weft/<stack>/vpc-flow-logs` | With `EnableVpcFlowLogs=true` |

Guest console output from a microVM that fails to boot or restore is included
in the host agent's error message.

## Metrics and scaling

The worker publishes `SlotUtilization` to the CloudWatch namespace named after
the stack. For each host it takes the tighter of two limits, sandbox slots
(`MaxSandboxesPerHost`) and guest memory, and averages them across the fleet.
The host Auto Scaling group tracks the metric against
`HostTargetSlotUtilization` (default 70%), adding hosts above the target and
removing them below it. The namespace also has `RunningSandboxes` and
`LiveHosts`.

Each host commits at most its memory minus 2 GiB (for the OS, the agent and
page cache) to sandboxes. Each sandbox is charged its template's memory plus
128 MiB for the VMM. A start that would exceed that budget goes to another
host. With the default `c8i.2xlarge` (16 GiB) and 512 MiB templates, that is
about 21 sandboxes per host, below the default slot cap of 32; larger
templates fit fewer. The budget comes from two host agent settings, which the
stack leaves at their defaults: `WEFT_MEMORY_RESERVE_MIB` (2048) and
`WEFT_MEMORY_OVERCOMMIT` (1.0; above 1 commits more guest memory than the host
has, which is safe only while guests leave much of their memory untouched).

**Scale-in and Spot interruptions stop the sandboxes on that host.** There is
no live migration. Keep `HostMinSize` and `HostOnDemandBaseCapacity` at your
steady-state need, and use Spot (`HostOnDemandPercentageAboveBase` below 100)
only for capacity whose sandboxes can be recreated.

When every host is full, `Sandbox.create` fails with `503` until the fleet
grows. New hosts take a few minutes to join.

## Upgrades

1. Read the release notes on the GitHub release page.
2. Update the stack with the new release's template URL. Keep your parameter
   values.
3. The release is verified again. ECS services roll with deployment circuit
   breakers that roll back a failed deployment.
4. A new host AMI changes the launch template only. Existing hosts keep their
   sandboxes. Replace them in a maintenance window:

   ```sh
   aws autoscaling start-instance-refresh \
     --auto-scaling-group-name <HostAutoScalingGroupName output> \
     --preferences MinHealthyPercentage=90,InstanceWarmup=300
   ```

   Replacing a host stops its running sandboxes. Paused sandboxes are in S3 and
   are not affected.
5. If the release changes the Firecracker version, rebuild your templates
   (`weft-sandbox templates rebuild <template-id>`). The release notes say when
   this is needed.

Security fixes for Firecracker, KVM or the guest kernel ship as new AMIs; see
[SECURITY.md](../SECURITY.md#patch-commitment).

## Keys and secrets

| What | Rotate by |
| --- | --- |
| Team API keys | `weft-sandbox keys create <team-id>`, move clients, then `weft-sandbox keys revoke <team-id> <key-id>`. Revocation takes effect within seconds |
| Named admin keys | `weft-sandbox keys create team_admin --name <who>` creates an additional admin key; revoke it like a team key. Prefer these over sharing the bootstrap key |
| Bootstrap admin key | Put a new random value (at least 32 characters) in the `AdminKeySecretArn` secret, then force a new deployment of the api and worker ECS services. The previous bootstrap key stops working when the new tasks start |
| Credentials for the credential proxy | Update the secret's value. The gateway reads it again within five minutes; set a new version and wait before revoking the old credential upstream |
| Egress CA | Not rotated in place in this release. It is created with the stack and valid for 10 years; its private key never leaves Secrets Manager |

## Backups and data

- **DynamoDB** tables have point-in-time recovery. They hold teams, key
  hashes, templates, sandbox records, host state and license state.
- **S3** holds template snapshots and paused sandboxes. Paused sandboxes are
  deleted after 30 days.
- Nothing else needs backing up: hosts hold only caches and running sandboxes.

## Troubleshooting

| Symptom | Look at |
| --- | --- |
| `Sandbox.create` returns 503 | `weft-sandbox hosts`: are hosts registered and not full? Auto Scaling activity for launch failures (capacity, quotas) |
| `Sandbox.create` says a template is still building or failed | `weft-sandbox templates get <id>` shows the build log |
| Code in a sandbox cannot resolve a name (`Name or service not known`) | The name is not in the team's policy (`weft-sandbox egress get`); the host log has an `event: dns` line for it |
| Code in a sandbox cannot reach a host | The team's policy, then the gateway audit log for that sandbox: `reason` says why ([egress.md](egress.md#what-a-denial-looks-like-inside-the-sandbox)) |
| A host agent restarted | Its running sandboxes are gone and disappear from the API at the host's next heartbeat; paused sandboxes are not affected |
| TLS errors inside the sandbox for a credential host | The client must trust the system store or `SSL_CERT_FILE`; see [egress.md](egress.md#credential-rules) |
| Hosts do not register | `/weft/<stack>/hosts/<instance-id>/bootstrap`; the host needs to reach `api.<domain>` through the internal load balancer |
| Clients cannot resolve the domain | The domain resolves only inside the VPC; see [install.md](install.md#reach-the-stack) |

To look at a host, start a Session Manager session
(`aws ssm start-session --target <instance-id>`) and check
`systemctl status weft-host-agent` and `journalctl -u weft-host-agent`.
