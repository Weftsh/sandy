//! Egress policy model and PROXY protocol v2 framing shared by the Weft host
//! agent and the egress gateway.
//!
//! Sandboxes are deny-by-default: an empty [`EgressPolicy`] allows no DNS
//! names, no connections and no credentials. Both the host agent (for guest
//! DNS) and the egress gateway (for connections) evaluate the same compiled
//! policy, so the two enforcement points cannot drift apart.

pub mod ip;
pub mod policy;
pub mod proxy_protocol;

pub use ip::{classify_ip, IpClass};
pub use policy::{
    AllowRule, CompiledPolicy, CredentialRule, Decision, DenyReason, EgressPolicy, HostPattern,
    PolicyError,
};
pub use proxy_protocol::{ProxyHeader, ProxyProtocolError, TLV_SANDBOX_ID};
