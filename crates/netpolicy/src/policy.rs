//! Egress policy: which names a sandbox may resolve, which destinations it may
//! connect to, and which outbound requests get a credential injected.

use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::ip::{classify_ip, IpClass};

/// Ports allowed when a rule does not list any.
pub const DEFAULT_PORTS: [u16; 2] = [80, 443];

/// Most rules a single policy may carry. Keeps evaluation cheap and bounds the
/// size of the policy document the gateway fetches per sandbox.
pub const MAX_RULES: usize = 256;

/// Wire form of a sandbox egress policy, as stored by the control plane and
/// served to the host agent and egress gateway.
///
/// An empty policy denies everything.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EgressPolicy {
    #[serde(default)]
    pub allow: Vec<AllowRule>,
    #[serde(default)]
    pub credentials: Vec<CredentialRule>,
}

/// Allows traffic to a hostname, a wildcard domain or a CIDR block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AllowRule {
    /// `api.github.com`, `*.github.com` (subdomains only), `*` (any public
    /// host) or a CIDR block such as `203.0.113.0/24`.
    pub host: String,
    /// Destination ports. Defaults to 80 and 443.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
}

/// Injects a secret into HTTPS requests to one host. The secret is fetched by
/// the egress gateway and never enters the sandbox.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialRule {
    /// Exact hostname, e.g. `api.openai.com`. Wildcards are not accepted.
    pub host: String,
    /// Header to set, e.g. `authorization` or `x-api-key`.
    pub header: String,
    /// AWS Secrets Manager secret ARN or name.
    pub secret_id: String,
    /// When the secret is a JSON object, the key whose value to use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_key: Option<String>,
    /// Header value template. `{{secret}}` is replaced by the secret value.
    /// Defaults to `{{secret}}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
}

impl CredentialRule {
    /// Renders the header value for a secret.
    pub fn render(&self, secret: &str) -> String {
        self.format
            .as_deref()
            .unwrap_or("{{secret}}")
            .replace("{{secret}}", secret)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("rule {index}: invalid host pattern {pattern:?}: {reason}")]
    InvalidHost {
        index: usize,
        pattern: String,
        reason: &'static str,
    },
    #[error("rule {index}: port 0 is not a valid destination port")]
    InvalidPort { index: usize },
    #[error("credential {index}: {reason}")]
    InvalidCredential { index: usize, reason: &'static str },
    #[error("policy has {count} rules; the limit is {MAX_RULES}")]
    TooManyRules { count: usize },
}

/// A parsed host pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostPattern {
    /// Matches exactly this lowercase hostname.
    Exact(String),
    /// Matches any strict subdomain of this lowercase domain.
    Subdomains(String),
    /// Matches any public hostname and any public IP address.
    AnyPublic,
    /// Matches IP addresses inside this block, including private ones.
    Cidr(IpNet),
}

impl HostPattern {
    pub fn parse(pattern: &str) -> Result<Self, &'static str> {
        let p = pattern.trim();
        if p == "*" {
            return Ok(Self::AnyPublic);
        }
        if let Ok(net) = p.parse::<IpNet>() {
            return Ok(Self::Cidr(net.trunc()));
        }
        if let Ok(ip) = p.parse::<IpAddr>() {
            return Ok(Self::Cidr(IpNet::from(ip)));
        }
        if let Some(domain) = p.strip_prefix("*.") {
            let domain = normalize_hostname(domain).ok_or("not a valid domain name")?;
            if !domain.contains('.') {
                return Err("wildcards must cover a registrable domain, not a top-level domain");
            }
            return Ok(Self::Subdomains(domain));
        }
        if p.contains('*') {
            return Err("only a leading `*.` wildcard is supported");
        }
        normalize_hostname(p)
            .map(Self::Exact)
            .ok_or("not a valid hostname")
    }

    fn matches_name(&self, name: &str) -> bool {
        match self {
            Self::Exact(h) => h == name,
            Self::Subdomains(d) => name.len() > d.len() + 1
                && name.ends_with(d.as_str())
                && name.as_bytes()[name.len() - d.len() - 1] == b'.',
            Self::AnyPublic => true,
            Self::Cidr(_) => false,
        }
    }
}

/// Lowercases a hostname, strips one trailing dot and checks RFC 1123 syntax.
/// Returns `None` for anything that is not a plausible DNS name, including IP
/// address literals.
pub fn normalize_hostname(name: &str) -> Option<String> {
    let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    if name.is_empty() || name.len() > 253 || name.parse::<IpAddr>().is_ok() {
        return None;
    }
    let valid = name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    valid.then_some(name)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CompiledRule {
    pattern: HostPattern,
    ports: Vec<u16>,
}

impl CompiledRule {
    fn allows_port(&self, port: u16) -> bool {
        if self.ports.is_empty() {
            DEFAULT_PORTS.contains(&port)
        } else {
            self.ports.contains(&port)
        }
    }
}

/// Why a destination was refused. Logged by the gateway for audit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyReason {
    /// No rule allows this destination.
    NotAllowed,
    /// The address is in a range that can never be reached.
    ForbiddenAddress,
    /// A hostname rule matched but the name resolved to a private address.
    PrivateAddressForName,
}

impl DenyReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotAllowed => "not_allowed",
            Self::ForbiddenAddress => "forbidden_address",
            Self::PrivateAddressForName => "private_address_for_name",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(DenyReason),
}

impl Decision {
    pub fn is_allowed(self) -> bool {
        self == Decision::Allow
    }
}

/// A validated policy, ready to evaluate.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompiledPolicy {
    rules: Vec<CompiledRule>,
    credentials: Vec<CredentialRule>,
}

impl CompiledPolicy {
    /// The policy that allows nothing.
    pub fn deny_all() -> Self {
        Self::default()
    }

    pub fn compile(policy: &EgressPolicy) -> Result<Self, PolicyError> {
        let count = policy.allow.len() + policy.credentials.len();
        if count > MAX_RULES {
            return Err(PolicyError::TooManyRules { count });
        }
        let mut rules = Vec::with_capacity(policy.allow.len() + policy.credentials.len());
        for (index, rule) in policy.allow.iter().enumerate() {
            let pattern =
                HostPattern::parse(&rule.host).map_err(|reason| PolicyError::InvalidHost {
                    index,
                    pattern: rule.host.clone(),
                    reason,
                })?;
            if rule.ports.contains(&0) {
                return Err(PolicyError::InvalidPort { index });
            }
            rules.push(CompiledRule {
                pattern,
                ports: rule.ports.clone(),
            });
        }
        let mut credentials = Vec::with_capacity(policy.credentials.len());
        for (index, cred) in policy.credentials.iter().enumerate() {
            let host = normalize_hostname(&cred.host).ok_or(PolicyError::InvalidCredential {
                index,
                reason: "host must be an exact hostname",
            })?;
            if !is_valid_header_name(&cred.header) {
                return Err(PolicyError::InvalidCredential {
                    index,
                    reason: "header is not a valid HTTP header name",
                });
            }
            if is_hop_by_hop_or_framing(&cred.header) {
                return Err(PolicyError::InvalidCredential {
                    index,
                    reason: "header controls HTTP framing and cannot carry a credential",
                });
            }
            if cred.secret_id.trim().is_empty() {
                return Err(PolicyError::InvalidCredential {
                    index,
                    reason: "secretId is required",
                });
            }
            if let Some(format) = &cred.format {
                if !format.contains("{{secret}}") {
                    return Err(PolicyError::InvalidCredential {
                        index,
                        reason: "format must contain {{secret}}",
                    });
                }
                if format.contains(['\r', '\n']) {
                    return Err(PolicyError::InvalidCredential {
                        index,
                        reason: "format must not contain line breaks",
                    });
                }
            }
            // A credential implies HTTPS access to its host.
            rules.push(CompiledRule {
                pattern: HostPattern::Exact(host.clone()),
                ports: vec![443],
            });
            credentials.push(CredentialRule {
                host,
                header: cred.header.to_ascii_lowercase(),
                ..cred.clone()
            });
        }
        Ok(Self { rules, credentials })
    }

    /// Whether the guest resolver may answer a query for `name`. CIDR rules
    /// never make a name resolvable.
    pub fn may_resolve(&self, name: &str) -> bool {
        let Some(name) = normalize_hostname(name) else {
            return false;
        };
        self.rules.iter().any(|r| r.pattern.matches_name(&name))
    }

    /// Whether a connection to `name:port` is allowed, before resolution.
    pub fn check_name(&self, name: &str, port: u16) -> Decision {
        let Some(name) = normalize_hostname(name) else {
            return Decision::Deny(DenyReason::NotAllowed);
        };
        let allowed = self
            .rules
            .iter()
            .any(|r| r.allows_port(port) && r.pattern.matches_name(&name));
        if allowed {
            Decision::Allow
        } else {
            Decision::Deny(DenyReason::NotAllowed)
        }
    }

    /// Whether the gateway may connect to `ip:port` after resolving an allowed
    /// name. Public addresses pass; private ones need an explicit CIDR rule;
    /// forbidden ones never pass.
    pub fn check_resolved(&self, ip: IpAddr, port: u16) -> Decision {
        match classify_ip(ip) {
            IpClass::Forbidden => Decision::Deny(DenyReason::ForbiddenAddress),
            IpClass::Public => Decision::Allow,
            IpClass::Private => {
                if self.cidr_allows(ip, port) {
                    Decision::Allow
                } else {
                    Decision::Deny(DenyReason::PrivateAddressForName)
                }
            }
        }
    }

    /// Whether a connection to a bare IP address, with no hostname available
    /// from SNI or an HTTP Host header, is allowed.
    pub fn check_ip(&self, ip: IpAddr, port: u16) -> Decision {
        match classify_ip(ip) {
            IpClass::Forbidden => Decision::Deny(DenyReason::ForbiddenAddress),
            IpClass::Private => {
                if self.cidr_allows(ip, port) {
                    Decision::Allow
                } else {
                    Decision::Deny(DenyReason::NotAllowed)
                }
            }
            IpClass::Public => {
                let any_public = self.rules.iter().any(|r| {
                    r.allows_port(port) && matches!(r.pattern, HostPattern::AnyPublic)
                });
                if any_public || self.cidr_allows(ip, port) {
                    Decision::Allow
                } else {
                    Decision::Deny(DenyReason::NotAllowed)
                }
            }
        }
    }

    fn cidr_allows(&self, ip: IpAddr, port: u16) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            v4 => v4,
        };
        self.rules.iter().any(|r| {
            r.allows_port(port) && matches!(&r.pattern, HostPattern::Cidr(net) if net.contains(&ip))
        })
    }

    /// The credential to inject for requests to `host`, if any.
    pub fn credential_for(&self, host: &str) -> Option<&CredentialRule> {
        let host = normalize_hostname(host)?;
        self.credentials.iter().find(|c| c.host == host)
    }

    /// Whether any credential rule exists. The gateway only intercepts TLS for
    /// hosts that carry a credential.
    pub fn has_credentials(&self) -> bool {
        !self.credentials.is_empty()
    }
}

fn is_valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
        })
}

fn is_hop_by_hop_or_framing(name: &str) -> bool {
    const BLOCKED: [&str; 10] = [
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "upgrade",
        "te",
        "trailer",
        "proxy-authorization",
        "proxy-connection",
    ];
    BLOCKED.contains(&name.to_ascii_lowercase().as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(json: &str) -> CompiledPolicy {
        let p: EgressPolicy = serde_json::from_str(json).unwrap();
        CompiledPolicy::compile(&p).unwrap()
    }

    #[test]
    fn empty_policy_denies_everything() {
        let p = CompiledPolicy::deny_all();
        assert!(!p.may_resolve("example.com"));
        assert!(!p.check_name("example.com", 443).is_allowed());
        assert!(!p.check_ip("1.1.1.1".parse().unwrap(), 443).is_allowed());
        assert!(p.credential_for("example.com").is_none());
    }

    #[test]
    fn exact_and_wildcard_rules() {
        let p = policy(r#"{"allow":[{"host":"api.github.com"},{"host":"*.pypi.org"}]}"#);
        assert!(p.may_resolve("api.github.com"));
        assert!(p.may_resolve("API.GitHub.com."));
        assert!(!p.may_resolve("github.com"));
        assert!(!p.may_resolve("evilapi.github.com"));
        assert!(p.may_resolve("files.pypi.org"));
        assert!(p.may_resolve("a.b.pypi.org"));
        assert!(!p.may_resolve("pypi.org"), "wildcard matches subdomains only");
        assert!(!p.may_resolve("notpypi.org"));
        assert!(!p.may_resolve("pypi.org.evil.com"));
        assert!(p.check_name("api.github.com", 443).is_allowed());
        assert!(p.check_name("api.github.com", 80).is_allowed());
        assert!(!p.check_name("api.github.com", 22).is_allowed());
    }

    #[test]
    fn explicit_ports_replace_defaults() {
        let p = policy(r#"{"allow":[{"host":"git.example.com","ports":[22]}]}"#);
        assert!(p.check_name("git.example.com", 22).is_allowed());
        assert!(!p.check_name("git.example.com", 443).is_allowed());
    }

    #[test]
    fn hostname_rules_never_reach_private_or_forbidden_addresses() {
        let p = policy(r#"{"allow":[{"host":"internal.example.com"}]}"#);
        assert_eq!(
            p.check_resolved("10.0.0.8".parse().unwrap(), 443),
            Decision::Deny(DenyReason::PrivateAddressForName)
        );
        assert_eq!(
            p.check_resolved("169.254.169.254".parse().unwrap(), 80),
            Decision::Deny(DenyReason::ForbiddenAddress)
        );
        assert!(p.check_resolved("93.184.215.14".parse().unwrap(), 443).is_allowed());
    }

    #[test]
    fn cidr_rules_open_private_ranges_but_never_forbidden_ones() {
        let p = policy(r#"{"allow":[{"host":"10.20.0.0/16","ports":[5432]},{"host":"169.254.0.0/16"}]}"#);
        assert!(p.check_ip("10.20.1.2".parse().unwrap(), 5432).is_allowed());
        assert!(!p.check_ip("10.20.1.2".parse().unwrap(), 443).is_allowed());
        assert!(!p.check_ip("10.21.1.2".parse().unwrap(), 5432).is_allowed());
        assert_eq!(
            p.check_ip("169.254.169.254".parse().unwrap(), 80),
            Decision::Deny(DenyReason::ForbiddenAddress)
        );
        assert!(!p.may_resolve("10.20.1.2"));
    }

    #[test]
    fn any_public_allows_public_only() {
        let p = policy(r#"{"allow":[{"host":"*"}]}"#);
        assert!(p.may_resolve("anything.example"));
        assert!(p.check_ip("1.1.1.1".parse().unwrap(), 443).is_allowed());
        assert!(!p.check_ip("10.0.0.1".parse().unwrap(), 443).is_allowed());
        assert!(!p.check_ip("127.0.0.1".parse().unwrap(), 443).is_allowed());
        assert!(!p.check_resolved("192.168.0.1".parse().unwrap(), 443).is_allowed());
    }

    #[test]
    fn credentials_imply_https_access_to_their_host() {
        let p = policy(
            r#"{"credentials":[{"host":"api.openai.com","header":"Authorization","secretId":"arn:aws:secretsmanager:us-east-1:111122223333:secret:openai","format":"Bearer {{secret}}"}]}"#,
        );
        assert!(p.may_resolve("api.openai.com"));
        assert!(p.check_name("api.openai.com", 443).is_allowed());
        assert!(!p.check_name("api.openai.com", 80).is_allowed());
        let c = p.credential_for("API.OPENAI.COM").unwrap();
        assert_eq!(c.header, "authorization");
        assert_eq!(c.render("sk-test"), "Bearer sk-test");
    }

    #[test]
    fn rejects_bad_patterns_and_credentials() {
        let bad_hosts = ["*.com", "api.*.com", "", "exa mple.com", "-bad.com", "**"];
        for host in bad_hosts {
            let p = EgressPolicy {
                allow: vec![AllowRule { host: host.to_string(), ports: vec![] }],
                credentials: vec![],
            };
            assert!(CompiledPolicy::compile(&p).is_err(), "{host:?} should be rejected");
        }
        let cred = |header: &str, format: Option<&str>, host: &str| EgressPolicy {
            allow: vec![],
            credentials: vec![CredentialRule {
                host: host.into(),
                header: header.into(),
                secret_id: "s".into(),
                secret_key: None,
                format: format.map(Into::into),
            }],
        };
        assert!(CompiledPolicy::compile(&cred("Host", None, "a.com")).is_err());
        assert!(CompiledPolicy::compile(&cred("Transfer-Encoding", None, "a.com")).is_err());
        assert!(CompiledPolicy::compile(&cred("bad header", None, "a.com")).is_err());
        assert!(CompiledPolicy::compile(&cred("x-key", Some("no placeholder"), "a.com")).is_err());
        assert!(CompiledPolicy::compile(&cred("x-key", Some("{{secret}}\r\nx: y"), "a.com")).is_err());
        assert!(CompiledPolicy::compile(&cred("x-key", None, "*.a.com")).is_err());
        assert!(CompiledPolicy::compile(&cred("x-key", None, "a.com")).is_ok());
    }

    #[test]
    fn rejects_unknown_fields_and_port_zero() {
        assert!(serde_json::from_str::<EgressPolicy>(r#"{"allow":[],"deny":[]}"#).is_err());
        let p: EgressPolicy =
            serde_json::from_str(r#"{"allow":[{"host":"a.com","ports":[0]}]}"#).unwrap();
        assert_eq!(
            CompiledPolicy::compile(&p),
            Err(PolicyError::InvalidPort { index: 0 })
        );
    }

    #[test]
    fn caps_rule_count() {
        let p = EgressPolicy {
            allow: (0..=MAX_RULES)
                .map(|i| AllowRule { host: format!("h{i}.example.com"), ports: vec![] })
                .collect(),
            credentials: vec![],
        };
        assert!(matches!(
            CompiledPolicy::compile(&p),
            Err(PolicyError::TooManyRules { .. })
        ));
    }
}
