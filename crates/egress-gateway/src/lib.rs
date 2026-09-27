//! The Weft egress gateway.
//!
//! Every TCP connection a sandbox opens is intercepted by its host agent and
//! handed to the gateway with a PROXY v2 header naming the sandbox and the
//! original destination. The gateway fetches the sandbox's egress policy from
//! the control plane, checks that the connection really comes from the host
//! running that sandbox, and then, depending on what the sandbox speaks:
//!
//! * TLS with SNI: checks the name, resolves it itself and splices bytes, or,
//!   for hosts with a credential rule, terminates TLS with a leaf from the
//!   install's interception CA and injects the credential into each request;
//! * plain HTTP/1.x: proxies request by request, checking every Host;
//! * anything else: checks the original destination IP and splices.
//!
//! Sandboxes are deny-by-default and every decision is written to an audit
//! log, one JSON line per connection plus one per proxied HTTP request.

pub mod audit;
pub mod ca;
pub mod cache;
pub mod classify;
pub mod config;
mod conn;
pub mod control_plane;
pub mod health;
pub mod http_head;
pub mod io;
pub mod limits;
mod proxy;
pub mod secrets;
pub mod server;
pub mod sni;
pub mod upstream;

pub use config::{Args, Config};
pub use server::Gateway;
