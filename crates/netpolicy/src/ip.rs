//! Classification of destination IP addresses.
//!
//! Some ranges can never be reached from a sandbox, whatever the policy says:
//! the instance metadata service, loopback and link-local addresses. Private
//! ranges are reachable only when an explicit CIDR rule names them.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// How the gateway treats a destination address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpClass {
    /// Publicly routable. Reachable when a hostname or CIDR rule allows it.
    Public,
    /// RFC 1918, CGNAT, ULA and similar ranges. Reachable only through an
    /// explicit CIDR rule, never through a hostname rule, so a public name
    /// that resolves to an internal address cannot be used to reach the VPC.
    Private,
    /// Never reachable: metadata service, loopback, link-local, multicast,
    /// unspecified, broadcast, documentation and reserved ranges.
    Forbidden,
}

/// Classifies an address. IPv4-mapped and IPv4-compatible IPv6 addresses are
/// classified as the IPv4 address they embed.
pub fn classify_ip(ip: IpAddr) -> IpClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return classify_v4(v4);
            }
            classify_v6(v6)
        }
    }
}

fn classify_v4(ip: Ipv4Addr) -> IpClass {
    let o = ip.octets();
    let forbidden = ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_link_local() // 169.254.0.0/16, includes IMDS 169.254.169.254
        || ip.is_multicast()
        || ip.is_broadcast()
        || o[0] == 0 // 0.0.0.0/8
        || o[0] >= 240 // 240.0.0.0/4 reserved
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 IETF protocol assignments
        || (o[0] == 192 && o[1] == 0 && o[2] == 2) // TEST-NET-1
        || (o[0] == 198 && o[1] == 51 && o[2] == 100) // TEST-NET-2
        || (o[0] == 203 && o[1] == 0 && o[2] == 113) // TEST-NET-3
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19)); // benchmarking
    if forbidden {
        return IpClass::Forbidden;
    }
    let private = ip.is_private() // 10/8, 172.16/12, 192.168/16
        || (o[0] == 100 && (64..=127).contains(&o[1])); // 100.64.0.0/10 CGNAT
    if private {
        IpClass::Private
    } else {
        IpClass::Public
    }
}

fn classify_v6(ip: Ipv6Addr) -> IpClass {
    let s = ip.segments();
    let forbidden = ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
        || (s[0] == 0xfd00 && s[1] == 0x0ec2) // fd00:ec2::/32 EC2 IMDS, DNS and NTP
        || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
        || (s[0] == 0x0064 && s[1] == 0xff9b) // NAT64 prefixes (well-known and local-use) embed IPv4
        || s[0] == 0x2002 // 6to4 embeds an IPv4 address
        || (s[0] == 0x2001 && s[1] == 0) // Teredo embeds an IPv4 address
        || s[0] == 0; // ::/16 reserved, includes IPv4-compatible addresses
    if forbidden {
        return IpClass::Forbidden;
    }
    if (s[0] & 0xfe00) == 0xfc00 {
        // fc00::/7 unique local
        return IpClass::Private;
    }
    IpClass::Public
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class(s: &str) -> IpClass {
        classify_ip(s.parse().unwrap())
    }

    #[test]
    fn metadata_service_is_forbidden_in_every_form() {
        assert_eq!(class("169.254.169.254"), IpClass::Forbidden);
        assert_eq!(class("::ffff:169.254.169.254"), IpClass::Forbidden);
        assert_eq!(class("fd00:ec2::254"), IpClass::Forbidden);
        assert_eq!(class("64:ff9b:1::a9fe:a9fe"), IpClass::Forbidden);
        assert_eq!(class("2002:a9fe:a9fe::1"), IpClass::Forbidden);
        assert_eq!(class("2001:0:4136:e378::1"), IpClass::Forbidden);
        assert_eq!(class("169.254.170.2"), IpClass::Forbidden); // ECS task metadata
    }

    #[test]
    fn loopback_and_unspecified_are_forbidden() {
        assert_eq!(class("127.0.0.1"), IpClass::Forbidden);
        assert_eq!(class("127.1.2.3"), IpClass::Forbidden);
        assert_eq!(class("0.0.0.0"), IpClass::Forbidden);
        assert_eq!(class("::1"), IpClass::Forbidden);
        assert_eq!(class("::"), IpClass::Forbidden);
        assert_eq!(class("::ffff:127.0.0.1"), IpClass::Forbidden);
    }

    #[test]
    fn private_ranges_are_private() {
        for ip in ["10.0.0.5", "172.16.3.4", "172.31.255.255", "192.168.1.1", "100.64.0.1", "fd12::1"] {
            assert_eq!(class(ip), IpClass::Private, "{ip}");
        }
    }

    #[test]
    fn public_addresses_are_public() {
        for ip in ["1.1.1.1", "140.82.112.3", "172.32.0.1", "2606:4700::1111"] {
            assert_eq!(class(ip), IpClass::Public, "{ip}");
        }
    }
}
