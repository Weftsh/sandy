//! Per-sandbox networking.
//!
//! Every sandbox gets a *slot*: a network namespace that acts as its router,
//! connected to the host by a veth pair with a unique /30. The guest itself
//! always sees the same addresses (169.254.0.21, gateway 169.254.0.22), which
//! is what lets every microVM restore from the same template snapshot.
//!
//! ```text
//!  guest eth0 169.254.0.21 ── tap0 169.254.0.22 [slot netns] veth0 10.200.x.2 ── wvN 10.200.x.1 [host]
//! ```
//!
//! Rules, in order of defence:
//! 1. The slot namespace forwards only TCP and DNS from the guest, and only
//!    to the host side of its veth. Everything else (UDP, ICMP, IPv6) drops.
//! 2. On the host, every TCP connection arriving from a slot is redirected to
//!    the egress forwarder and every DNS query to the guest resolver. Nothing
//!    from a slot is routed by the host, and nothing else on the host accepts
//!    connections from a slot. The host agent's API, the instance metadata
//!    service and other guests are therefore unreachable.
//! 3. The egress forwarder hands each connection to the egress gateway, which
//!    applies the sandbox's allowlist.
//!
//! In the Firecracker runtime `tap0` is a real tap device. In the
//! development namespace runtime it is one end of a veth pair whose other
//! end, `eth0`, sits in a second "guest" namespace, so the address plan and
//! the rules are identical.

use std::net::Ipv4Addr;

use ipnet_lite::Ipv4Block;

use crate::cmd::Cmd;

/// Address the guest uses on its only interface.
pub const GUEST_IP: Ipv4Addr = Ipv4Addr::new(169, 254, 0, 21);
/// Gateway and resolver address the guest sees.
pub const GUEST_GATEWAY: Ipv4Addr = Ipv4Addr::new(169, 254, 0, 22);
pub const GUEST_PREFIX: u8 = 30;

/// Host-wide networking settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetConfig {
    /// Pool the per-slot /30 links are carved from. Must not overlap the VPC.
    pub pool: Ipv4Block,
    /// Port the host's guest resolver listens on.
    pub dns_port: u16,
    /// Port the host's egress forwarder listens on.
    pub egress_port: u16,
}

impl NetConfig {
    pub fn max_slots(&self) -> u32 {
        self.pool.size() / 4
    }
}

/// How the guest is attached to its slot namespace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuestLink {
    /// A tap device owned by the jailed Firecracker user.
    Tap { uid: u32, gid: u32 },
    /// A veth pair into a separate guest namespace (development runtime).
    Veth { guest_netns: String },
}

/// Addresses and names for one slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Slot {
    pub index: u32,
    /// Host end of the veth pair.
    pub host_ip: Ipv4Addr,
    /// Slot-namespace end of the veth pair. Connections from the guest reach
    /// the host with this source address, which identifies the sandbox.
    pub ns_ip: Ipv4Addr,
    pub host_if: String,
    pub netns: String,
}

impl Slot {
    pub fn new(cfg: &NetConfig, index: u32) -> Option<Self> {
        if index >= cfg.max_slots() {
            return None;
        }
        let base = u32::from(cfg.pool.network()) + index * 4;
        Some(Self {
            index,
            host_ip: Ipv4Addr::from(base + 1),
            ns_ip: Ipv4Addr::from(base + 2),
            host_if: format!("wv{index}"),
            netns: format!("weft-s{index}"),
        })
    }

    /// Finds the slot whose namespace address is `ip`.
    pub fn index_for_ns_ip(cfg: &NetConfig, ip: Ipv4Addr) -> Option<u32> {
        let ip = u32::from(ip);
        let net = u32::from(cfg.pool.network());
        if !cfg.pool.contains(Ipv4Addr::from(ip)) || (ip - net) % 4 != 2 {
            return None;
        }
        Some((ip - net) / 4)
    }
}

fn ip(args: &[&str]) -> Cmd {
    Cmd::new("ip", args.iter().copied())
}

fn in_ns(ns: &str, program: &str, args: &[&str]) -> Cmd {
    let mut full = vec!["netns", "exec", ns, program];
    full.extend_from_slice(args);
    Cmd::new("ip", full)
}

/// Commands that create a slot. Run [`teardown_plan`] first to clear leftovers.
pub fn setup_plan(cfg: &NetConfig, slot: &Slot, link: &GuestLink) -> Vec<Cmd> {
    let ns = slot.netns.as_str();
    let host_cidr = format!("{}/30", slot.host_ip);
    let ns_cidr = format!("{}/30", slot.ns_ip);
    let gw_cidr = format!("{GUEST_GATEWAY}/{GUEST_PREFIX}");
    let host_ip = slot.host_ip.to_string();
    debug_assert!(cfg.pool.contains(slot.ns_ip), "slot outside the configured pool");

    let mut plan = vec![
        ip(&["netns", "add", ns]),
        // Fails only on kernels built without IPv6, where it is off anyway.
        in_ns(ns, "sysctl", &["-q", "-w", "net.ipv6.conf.all.disable_ipv6=1"]).allow_failure(),
        in_ns(ns, "sysctl", &["-q", "-w", "net.ipv6.conf.default.disable_ipv6=1"]).allow_failure(),
        in_ns(ns, "sysctl", &["-q", "-w", "net.ipv4.ip_forward=1"]),
        ip(&["link", "add", &slot.host_if, "type", "veth", "peer", "name", "veth0", "netns", ns]),
        ip(&["addr", "add", &host_cidr, "dev", &slot.host_if]),
        ip(&["link", "set", &slot.host_if, "up"]),
        ip(&["-n", ns, "link", "set", "lo", "up"]),
        ip(&["-n", ns, "addr", "add", &ns_cidr, "dev", "veth0"]),
        ip(&["-n", ns, "link", "set", "veth0", "up"]),
        ip(&["-n", ns, "route", "add", "default", "via", &host_ip]),
    ];

    match link {
        GuestLink::Tap { uid, gid } => {
            let (uid, gid) = (uid.to_string(), gid.to_string());
            plan.extend([
                ip(&["-n", ns, "tuntap", "add", "dev", "tap0", "mode", "tap", "user", &uid, "group", &gid]),
                ip(&["-n", ns, "addr", "add", &gw_cidr, "dev", "tap0"]),
                ip(&["-n", ns, "link", "set", "tap0", "up"]),
            ]);
        }
        GuestLink::Veth { guest_netns } => {
            let g = guest_netns.as_str();
            let guest_cidr = format!("{GUEST_IP}/{GUEST_PREFIX}");
            let gw = GUEST_GATEWAY.to_string();
            plan.extend([
                ip(&["netns", "add", g]),
                in_ns(g, "sysctl", &["-q", "-w", "net.ipv6.conf.all.disable_ipv6=1"]).allow_failure(),
                in_ns(g, "sysctl", &["-q", "-w", "net.ipv6.conf.default.disable_ipv6=1"]).allow_failure(),
                ip(&["-n", ns, "link", "add", "tap0", "type", "veth", "peer", "name", "eth0", "netns", g]),
                ip(&["-n", ns, "addr", "add", &gw_cidr, "dev", "tap0"]),
                ip(&["-n", ns, "link", "set", "tap0", "up"]),
                ip(&["-n", g, "link", "set", "lo", "up"]),
                ip(&["-n", g, "addr", "add", &guest_cidr, "dev", "eth0"]),
                ip(&["-n", g, "link", "set", "eth0", "up"]),
                ip(&["-n", g, "route", "add", "default", "via", &gw]),
            ]);
        }
    }

    plan.push(in_ns(ns, "iptables-restore", &[]).stdin(slot_ruleset(slot)));
    plan.push(in_ns(ns, "ip6tables-restore", &[]).stdin(DROP_ALL_V6.to_owned()).allow_failure());
    plan
}

/// Commands that remove a slot. Every step tolerates the resource being gone.
pub fn teardown_plan(slot: &Slot, link: &GuestLink) -> Vec<Cmd> {
    let mut plan = vec![
        ip(&["link", "del", &slot.host_if]).allow_failure(),
        ip(&["netns", "del", &slot.netns]).allow_failure(),
    ];
    if let GuestLink::Veth { guest_netns } = link {
        plan.push(ip(&["netns", "del", guest_netns]).allow_failure());
    }
    plan
}

const DROP_ALL_V6: &str = "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT DROP [0:0]\nCOMMIT\n";

/// The slot namespace's iptables ruleset, applied atomically.
pub fn slot_ruleset(slot: &Slot) -> String {
    let host = slot.host_ip;
    let ns = slot.ns_ip;
    let guest = GUEST_IP;
    format!(
        "*nat\n\
         :PREROUTING ACCEPT [0:0]\n\
         :INPUT ACCEPT [0:0]\n\
         :OUTPUT ACCEPT [0:0]\n\
         :POSTROUTING ACCEPT [0:0]\n\
         -A PREROUTING -i tap0 -p udp --dport 53 -j DNAT --to-destination {host}:53\n\
         -A PREROUTING -i tap0 -p tcp --dport 53 -j DNAT --to-destination {host}:53\n\
         -A PREROUTING -i veth0 -s {host} -p tcp -j DNAT --to-destination {guest}\n\
         -A POSTROUTING -o veth0 -j SNAT --to-source {ns}\n\
         COMMIT\n\
         *filter\n\
         :INPUT DROP [0:0]\n\
         :FORWARD DROP [0:0]\n\
         :OUTPUT ACCEPT [0:0]\n\
         -A INPUT -i lo -j ACCEPT\n\
         -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n\
         -A FORWARD -m conntrack --ctstate INVALID -j DROP\n\
         -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n\
         -A FORWARD -i tap0 -o veth0 -s {guest} -p tcp -m conntrack --ctstate NEW -j ACCEPT\n\
         -A FORWARD -i tap0 -o veth0 -s {guest} -d {host} -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT\n\
         -A FORWARD -i veth0 -o tap0 -s {host} -d {guest} -p tcp -m conntrack --ctstate NEW -j ACCEPT\n\
         COMMIT\n"
    )
}

/// Host-wide chains. Installed once at agent start; idempotent.
pub fn host_plan(cfg: &NetConfig) -> Vec<Cmd> {
    let dns = cfg.dns_port.to_string();
    let egress = cfg.egress_port.to_string();
    let ipt = |args: &[&str]| Cmd::new("iptables", args.iter().copied());
    let mut plan = vec![
        // Chains may already exist from a previous run.
        ipt(&["-w", "-t", "nat", "-N", "WEFT-PRE"]).allow_failure(),
        ipt(&["-w", "-t", "nat", "-F", "WEFT-PRE"]),
        ipt(&["-w", "-t", "nat", "-A", "WEFT-PRE", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", &dns]),
        ipt(&["-w", "-t", "nat", "-A", "WEFT-PRE", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", &dns]),
        ipt(&["-w", "-t", "nat", "-A", "WEFT-PRE", "-p", "tcp", "-j", "REDIRECT", "--to-ports", &egress]),
        ipt(&["-w", "-N", "WEFT-IN"]).allow_failure(),
        ipt(&["-w", "-F", "WEFT-IN"]),
        ipt(&["-w", "-A", "WEFT-IN", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]),
        ipt(&["-w", "-A", "WEFT-IN", "-p", "udp", "--dport", &dns, "-j", "ACCEPT"]),
        ipt(&["-w", "-A", "WEFT-IN", "-p", "tcp", "--dport", &dns, "-j", "ACCEPT"]),
        ipt(&["-w", "-A", "WEFT-IN", "-p", "tcp", "--dport", &egress, "-j", "ACCEPT"]),
        ipt(&["-w", "-A", "WEFT-IN", "-j", "DROP"]),
        ipt(&["-w", "-N", "WEFT-FWD"]).allow_failure(),
        ipt(&["-w", "-F", "WEFT-FWD"]),
        ipt(&["-w", "-A", "WEFT-FWD", "-j", "DROP"]),
    ];
    // Jump rules: check first, insert at the top only if missing.
    for (table, chain, dir, target) in [
        ("nat", "PREROUTING", "-i", "WEFT-PRE"),
        ("filter", "INPUT", "-i", "WEFT-IN"),
        ("filter", "FORWARD", "-i", "WEFT-FWD"),
        ("filter", "FORWARD", "-o", "WEFT-FWD"),
    ] {
        plan.push(ensure_rule(table, chain, &[dir, "wv+", "-j", target]));
    }
    plan
}

/// Inserts a jump rule at the top of a built-in chain unless it is already
/// there. `iptables` has no "insert if missing", so this probes with `-C`.
/// Every argument is a fixed identifier, so the shell sees no untrusted input.
fn ensure_rule(table: &str, chain: &str, rule: &[&str]) -> Cmd {
    let spec = rule.join(" ");
    Cmd::new(
        "sh",
        [
            "-c".to_owned(),
            format!(
                "iptables -w -t {table} -C {chain} {spec} 2>/dev/null || iptables -w -t {table} -I {chain} 1 {spec}"
            ),
        ],
    )
}

/// A tiny IPv4 block type so the address plan does not depend on parsing
/// libraries' formatting rules.
pub mod ipnet_lite {
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Ipv4Block {
        network: Ipv4Addr,
        prefix: u8,
    }

    impl Ipv4Block {
        pub fn new(network: Ipv4Addr, prefix: u8) -> Result<Self, String> {
            if !(8..=30).contains(&prefix) {
                return Err(format!("prefix /{prefix} must be between /8 and /30"));
            }
            let mask = u32::MAX << (32 - prefix);
            if u32::from(network) & !mask != 0 {
                return Err(format!("{network}/{prefix} has host bits set"));
            }
            Ok(Self { network, prefix })
        }
        pub fn network(&self) -> Ipv4Addr {
            self.network
        }
        pub fn size(&self) -> u32 {
            1u32 << (32 - self.prefix)
        }
        pub fn contains(&self, ip: Ipv4Addr) -> bool {
            let mask = u32::MAX << (32 - self.prefix);
            u32::from(ip) & mask == u32::from(self.network)
        }
    }

    impl FromStr for Ipv4Block {
        type Err = String;
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let (ip, prefix) = s.split_once('/').ok_or("expected a.b.c.d/n")?;
            let ip: Ipv4Addr = ip.parse().map_err(|_| format!("bad address {ip:?}"))?;
            let prefix: u8 = prefix.parse().map_err(|_| format!("bad prefix {prefix:?}"))?;
            Self::new(ip, prefix)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> NetConfig {
        NetConfig {
            pool: "10.200.0.0/16".parse().unwrap(),
            dns_port: 15053,
            egress_port: 15001,
        }
    }

    #[test]
    fn slots_get_unique_non_overlapping_links() {
        let c = cfg();
        assert_eq!(c.max_slots(), 16384);
        let s0 = Slot::new(&c, 0).unwrap();
        let s1 = Slot::new(&c, 1).unwrap();
        let last = Slot::new(&c, 16383).unwrap();
        assert_eq!((s0.host_ip, s0.ns_ip), ("10.200.0.1".parse().unwrap(), "10.200.0.2".parse().unwrap()));
        assert_eq!((s1.host_ip, s1.ns_ip), ("10.200.0.5".parse().unwrap(), "10.200.0.6".parse().unwrap()));
        assert_eq!(last.ns_ip, "10.200.255.254".parse::<Ipv4Addr>().unwrap());
        assert!(Slot::new(&c, 16384).is_none());
        assert_eq!(s1.host_if, "wv1");
        assert!(last.host_if.len() <= 15, "interface names are limited to 15 bytes");
    }

    #[test]
    fn maps_namespace_addresses_back_to_slots() {
        let c = cfg();
        assert_eq!(Slot::index_for_ns_ip(&c, "10.200.0.6".parse().unwrap()), Some(1));
        assert_eq!(Slot::index_for_ns_ip(&c, "10.200.0.5".parse().unwrap()), None, "host side is not a sandbox");
        assert_eq!(Slot::index_for_ns_ip(&c, "10.201.0.6".parse().unwrap()), None);
    }

    #[test]
    fn slot_rules_only_forward_tcp_and_dns_to_the_host_side() {
        let s = Slot::new(&cfg(), 3).unwrap();
        let rules = slot_ruleset(&s);
        assert!(rules.contains(":FORWARD DROP"));
        assert!(rules.contains(":INPUT DROP"));
        assert!(rules.contains("-A PREROUTING -i tap0 -p udp --dport 53 -j DNAT --to-destination 10.200.0.13:53"));
        assert!(rules.contains("-A POSTROUTING -o veth0 -j SNAT --to-source 10.200.0.14"));
        assert!(rules.contains("-A PREROUTING -i veth0 -s 10.200.0.13 -p tcp -j DNAT --to-destination 169.254.0.21"));
        // No rule accepts UDP other than DNS, ICMP, or anything to other destinations.
        for line in rules.lines().filter(|l| l.starts_with("-A FORWARD") && l.contains("ACCEPT")) {
            assert!(
                line.contains("ESTABLISHED") || line.contains("-p tcp") || line.contains("--dport 53"),
                "unexpected accept: {line}"
            );
        }
        assert!(!rules.contains("icmp"));
    }

    #[test]
    fn setup_plan_for_firecracker_uses_a_tap_owned_by_the_jail_user() {
        let c = cfg();
        let s = Slot::new(&c, 7).unwrap();
        let plan = setup_plan(&c, &s, &GuestLink::Tap { uid: 200_007, gid: 200_007 });
        let text: Vec<String> = plan.iter().map(|c| c.to_string()).collect();
        assert!(text.contains(&"ip -n weft-s7 tuntap add dev tap0 mode tap user 200007 group 200007".to_string()));
        assert!(text.iter().any(|t| t == "ip netns exec weft-s7 iptables-restore"));
        assert!(text.iter().any(|t| t.ends_with("net.ipv6.conf.all.disable_ipv6=1")));
    }

    #[test]
    fn setup_plan_for_namespaces_builds_a_guest_namespace() {
        let c = cfg();
        let s = Slot::new(&c, 2).unwrap();
        let plan = setup_plan(&c, &s, &GuestLink::Veth { guest_netns: "weft-g2".into() });
        let text: Vec<String> = plan.iter().map(|c| c.to_string()).collect();
        assert!(text.contains(&"ip -n weft-g2 addr add 169.254.0.21/30 dev eth0".to_string()));
        assert!(text.contains(&"ip -n weft-g2 route add default via 169.254.0.22".to_string()));
        let teardown = teardown_plan(&s, &GuestLink::Veth { guest_netns: "weft-g2".into() });
        assert!(teardown.iter().all(|c| c.allow_failure));
        assert_eq!(teardown.len(), 3);
    }

    #[test]
    fn host_plan_redirects_all_slot_tcp_and_dns_and_accepts_nothing_else() {
        let plan = host_plan(&cfg());
        let text: Vec<String> = plan.iter().map(|c| c.to_string()).collect();
        assert!(text.iter().any(|t| t.contains("WEFT-PRE -p tcp -j REDIRECT --to-ports 15001")));
        assert!(text.iter().any(|t| t.contains("WEFT-PRE -p udp --dport 53 -j REDIRECT --to-ports 15053")));
        let dns_pos = text.iter().position(|t| t.contains("-p tcp --dport 53 -j REDIRECT")).unwrap();
        let tcp_pos = text.iter().position(|t| t.contains("-p tcp -j REDIRECT")).unwrap();
        assert!(dns_pos < tcp_pos, "DNS over TCP must match before the catch-all TCP redirect");
        assert!(text.iter().any(|t| t.ends_with("WEFT-IN -j DROP")));
        assert!(text.iter().any(|t| t.ends_with("WEFT-FWD -j DROP")));
    }

    #[test]
    fn rejects_bad_pools() {
        assert!("10.200.0.1/16".parse::<ipnet_lite::Ipv4Block>().is_err());
        assert!("10.200.0.0/31".parse::<ipnet_lite::Ipv4Block>().is_err());
        assert!("nonsense".parse::<ipnet_lite::Ipv4Block>().is_err());
    }
}
