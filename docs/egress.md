# Egress

Sandboxes have **no outbound network access** until an admin allows it. Every
TCP connection a sandbox opens is redirected on its host to the egress
gateway, which checks it against the sandbox's policy, connects to the
destination for it and logs the outcome. DNS answers only names the policy
allows. UDP (other than DNS), ICMP and connections to link-local, loopback or
host addresses never leave the sandbox's network namespace.

## Team policies

A policy is a JSON document per team. A new team starts with the empty,
deny-all policy.

```json
{
  "allow": [
    { "host": "pypi.org" },
    { "host": "*.pythonhosted.org" },
    { "host": "api.github.com" },
    { "host": "10.20.0.0/16", "ports": [5432] }
  ],
  "credentials": [
    {
      "host": "api.openai.com",
      "header": "Authorization",
      "secretId": "arn:aws:secretsmanager:us-east-1:123456789012:secret:openai-key-AbCdEf",
      "format": "Bearer {{secret}}"
    }
  ]
}
```

```sh
weft-sandbox egress set <team-id> policy.json
weft-sandbox egress get <team-id>
```

The API validates the whole document and rejects it with a message naming the
first problem, so an invalid policy never reaches a gateway. A change applies
to the team's existing sandboxes as well as new ones: their hosts' DNS
resolvers update immediately and the gateways within 30 seconds (their policy
cache lifetime). Connections that are already open stay open until they
close.

### Allow rules

| `host` | Matches |
| --- | --- |
| `api.github.com` | That exact name |
| `*.example.com` | Every subdomain of `example.com`, at any depth; **not** `example.com` itself |
| `*` | Any public destination: fully qualified names and public IP addresses. Never private, link-local or loopback addresses |
| `203.0.113.7`, `10.20.0.0/16`, `2001:db8::/32` | Those addresses. The only way to reach private addresses, such as databases in your VPC |

`ports` defaults to `[80, 443]`. A policy has at most 256 rules.

How the gateway identifies the destination:

- **TLS** (HTTPS and anything else over TLS): the server name (SNI) the
  sandbox sends.
- **Plain HTTP**: the `Host` header of every request on the connection, each
  checked separately.
- **Anything else** (SSH, database protocols, raw TCP): only the destination
  IP address, so hostname rules do not apply. Use an IP or CIDR rule, or `*`
  with the port listed (for example `{"host": "*", "ports": [22]}` for SSH to
  public hosts).

A name that is allowed but resolves to a private address is refused unless a
CIDR rule also allows that address. This stops DNS rebinding from turning a
public allowlist entry into access to your VPC.

Wildcards are checked only for not being a top-level domain: `*.com` is
rejected, but a public suffix such as `*.co.uk` is accepted. Write wildcards
for domains you control or trust.

### Credential rules

A credential rule makes the gateway add a secret to HTTPS requests to one
host. The sandbox makes the request without the secret and never sees it.

| Field | Meaning |
| --- | --- |
| `host` | Exact hostname (no wildcards). Implies an allow rule for that host on port 443 |
| `header` | Header to set, such as `Authorization` or `x-api-key`. Replaces any value the sandbox sent |
| `secretId` | Secrets Manager secret name or ARN in the stack's account and Region |
| `secretKey` | Optional: for a JSON secret, the key holding the value |
| `format` | Optional: template containing `{{secret}}`, such as `Bearer {{secret}}` |

The gateway can read only secrets tagged `weft-sandbox-access=true` (and never
the stack's own admin and license secrets):

```sh
aws secretsmanager create-secret --name openai-key --secret-string "$OPENAI_API_KEY" \
  --tags Key=weft-sandbox-access,Value=true
```

Secrets encrypted with a customer managed KMS key need a key policy that lets
the gateway task role decrypt through Secrets Manager.

To add the header, the gateway terminates TLS for credential hosts only, with
a certificate from the stack's egress CA. Sandboxes whose policy has
credential rules get that CA in their system trust store, and
`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` and `NODE_EXTRA_CA_CERTS` point at the
store. The gateway then opens its own TLS connection to the real host and
verifies its certificate. Connections to every other host pass through
untouched: the gateway reads the server name and never decrypts them.

Limits of the credential proxy:

- It handles HTTP/1.1 inside TLS. Clients that insist on HTTP/2 without
  falling back, and non-HTTP protocols, do not get the credential.
- It does not scrub response bodies. An upstream that echoes the credential
  back (some error pages do) reveals it to the sandbox.
- The egress CA's certificate is public (the `EgressCaCertificateParameter`
  output). Its private key stays in Secrets Manager, readable only by the
  gateway.

## SDK options

The E2B SDKs have their own network options. On Weft Sandboxes they can only
**narrow** the team's policy, never widen it:

| SDK option | Effect |
| --- | --- |
| none (the default, `allow_internet_access=True`) | The team's policy |
| `allow_internet_access=False` | Deny all |
| `network={"deny_out": ["0.0.0.0/0"]}` | Deny all |
| `network={"deny_out": ["0.0.0.0/0"], "allow_out": [...]}` | Only the listed entries. Each must already be allowed by the team policy, or the request fails with 403 |
| `network={"allow_public_traffic": False}` | Inbound: requests to sandbox ports need the sandbox's traffic token |
| `network.rules`, `egress_proxy`, `mask_request_host`, other `deny_out` entries | Rejected with 400 |

A narrowed sandbox keeps only the credential rules whose hosts its `allow_out`
list still covers. If the team policy later stops allowing an `allow_out`
entry, that sandbox loses all egress rather than keeping the entry.

## DNS

Each host runs a resolver for its sandboxes. It answers names the policy
allows, from the host's upstream resolver, and returns `NXDOMAIN` for
everything else. So a sandbox cannot use DNS queries to send data to a domain
it has not been allowed.

## Audit log

The gateway writes one JSON line per connection and one per proxied HTTP
request to `/weft/<stack>/egress-gateway` in CloudWatch Logs (target `audit`).
Records never contain credential values, URL paths, query strings or bodies.

| Field | Meaning |
| --- | --- |
| `event` | `connection` or `request` |
| `sandboxId` | The sandbox |
| `dst`, `dstHost`, `host` | Destination address and name |
| `protocol` | `tls`, `http`, `https` (intercepted), `opaque` |
| `decision`, `reason` | `allow` or `deny`, and why: `not_allowed`, `forbidden_address`, `private_address_for_name`, `host_mismatch` and others |
| `intercepted`, `credentialInjected` | Whether TLS was terminated and a credential added |
| `method`, `status` | For requests |
| `bytesUp`, `bytesDown`, `durationMs`, `requests` | Volume and timing |

Denied connections from one sandbox over the last day, with CloudWatch Logs
Insights:

```
fields @timestamp, dstHost, dst, reason
| filter event = "connection" and decision = "deny" and sandboxId = "<sandbox-id>"
| sort @timestamp desc
```

Refused DNS names are logged by the host agent instead, in
`/weft/<stack>/hosts` (`event` `dns`, with `sandboxId` and `name`), once per
sandbox and name and at most 50 names per sandbox:

```
fields @timestamp, sandboxId, name
| filter event = "dns" and decision = "deny"
| sort @timestamp desc
```

### What a denial looks like inside the sandbox

| Attempt | What the code sees |
| --- | --- |
| A name outside the policy | DNS lookup fails: `Name or service not known`, `ENOTFOUND`, `Could not resolve host` |
| Plain HTTP to a disallowed host | `403` with the header `x-weft-egress-reason` (for example `not_allowed`) |
| TLS to a disallowed host or IP address | The connection closes during the handshake: `unexpected EOF`, `connection reset` |
| Metadata service, host or other link-local addresses | `Connection refused` |
| UDP other than DNS, ICMP | No answer (timeouts) |
