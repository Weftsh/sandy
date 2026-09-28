# Licensing

A Weft Sandboxes stack needs a license to receive releases and security
patches. **A license never stops sandboxes.** A missing, expired, over-cap or
unverifiable license produces warnings, never a refusal.

This page covers the commercial license key. The source code license (FSL and
Apache-2.0) is described in [LICENSE.md](../LICENSE.md).

## License modes

| Mode | Set with | Contacts Weft | For |
| --- | --- | --- | --- |
| **Online key** | `LicenseKey` parameter, `LicenseMode=key` | Once a day, four fields (below) | Most installs |
| **Offline key** | Same; the key itself says `offline` | Never | Air-gapped installs, with an annual true-up |
| **AWS Marketplace** | `LicenseMode=marketplace`, `MarketplaceProductSku` | Never. Checks out an entitlement from AWS License Manager in your own account | Buying through AWS |

## License keys

A key looks like `weft_lic_v1.<payload>.<signature>`. The payload is a JSON
document, and the signature is Ed25519 over it. The stack checks the signature
locally against public keys compiled into the release; verification makes no
network call.

The payload contains:

| Field | Meaning |
| --- | --- |
| `lid` | License ID |
| `entity` | Legal entity the license is issued to |
| `tier` | `community`, `team`, `business` or `enterprise` |
| `accounts` | AWS account IDs the license covers; empty means any |
| `maxConcurrent` | Concurrent sandboxes covered; `null` means unlimited |
| `mode` | `online` or `offline` |
| `iat`, `exp` | Issued and expiry dates |
| `trial` | Present and `true` on a trial key |

A license covers the legal entity it is issued to: every AWS account that
entity owns, so the keys Weft sells carry an empty `accounts` list. A 15-day
trial key is marked `trial` and expires when the trial ends; the full key is
emailed when the first payment clears. Release AMIs are public, like the rest
of a release: the license is what entitles an organization to run the stack
and to receive releases and security patches.

Install or replace a key without updating the stack:

```sh
weft-sandbox license install 'weft_lic_v1....'
weft-sandbox license status
```

The `LicenseKey` stack parameter is stored in Secrets Manager and applied
when the control plane first starts with that value. A key installed with
`license install` stays in effect until the parameter changes, so renewals
work either way: install the new key, or update the stack with it.

## What the daily check sends

Online keys make one HTTPS request a day to `https://license.weft.sh/v1/check`
(user agent `weft-sandboxes/<version>`) with exactly this body:

```json
{ "keyId": "lic_...", "version": "0.1.0", "region": "eu-west-1", "peakConcurrent": 12 }
```

| Field | Value |
| --- | --- |
| `keyId` | The license ID from the key |
| `version` | The stack's release version |
| `region` | The AWS Region the stack runs in |
| `peakConcurrent` | Highest number of running sandboxes since the last successful check |

Nothing else is sent: no account ID, sandbox IDs, template names, user data,
code or logs. The field list is fixed in
[packages/license/src/check.ts](../packages/license/src/check.ts) and a test
asserts it. The response can carry a status (`active`, `lapsed`, `revoked`)
and a notice, such as a renewal reminder, shown in `license status`.

A failed check is retried twice with backoff and then left until the next
day. Sandboxes are never affected.

## License states

`weft-sandbox license status` (or `GET /weft/v1/license` with the admin key)
reports:

| Field | Meaning |
| --- | --- |
| `state` | `unlicensed`, `invalid` (bad signature, or account not covered), `active`, `expiring` (within 30 days), `lapsed` |
| `trial` | The installed key is a trial key. A trial reads `expiring` from its first day, and its warnings say when the trial ends and to install the full key |
| `releaseAccess` | Whether the account is entitled to new releases and security patches. Stays true for 30 days after expiry |
| `overCap` | More sandboxes running than `maxConcurrent`. Sandboxes keep launching |
| `checkOverdue` | Online keys: no successful check for more than 7 days |
| `peakThisMonth`, `monthlyPeaks` | Peak concurrent sandboxes per UTC month, last 13 months |
| `warnings` | Plain-language explanations of anything above |

Warnings are also written to the control plane log.

## Offline true-up

Offline keys never contact Weft. Once a year, send Weft the `monthlyPeaks`
from `weft-sandbox license status`. The stack keeps 13 months of history.

## Issuing keys (vendor side)

The `weft-license` tool in [packages/license](../packages/license) creates
signing keys and issues keys:

```sh
weft-license keygen --out ./keys                      # local Ed25519 key pair (testing)
weft-license issue --payload payload.json --kms-key-id <ED25519 KMS key>
weft-license verify <license-key> --public-key <kid>=<public.pem>
```

Production keys are signed with an AWS KMS key of spec
`ECC_NIST_EDWARDS25519` (algorithm `ED25519_SHA_512`, which is pure Ed25519),
so the private key never leaves KMS. The matching public keys are listed in
[packages/license/src/trusted-keys.ts](../packages/license/src/trusted-keys.ts).
The release workflow refuses to build a release while that list is empty.
