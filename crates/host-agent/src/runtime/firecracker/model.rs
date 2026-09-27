//! Firecracker API request bodies and rate-limiter settings.
//!
//! Field names follow the OpenAPI definition shipped with the targeted
//! release (`src/firecracker/swagger/firecracker.yaml`). Firecracker rejects
//! unknown fields, so the tests pin every body to the swagger's property
//! names.

use serde::{Deserialize, Serialize};

/// A token bucket (`TokenBucket`). The refill rate is `size / refill_time`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenBucket {
    /// Capacity: bytes for bandwidth buckets, operations for ops buckets.
    pub size: u64,
    /// Extra tokens available once, before the bucket starts refilling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub one_time_burst: Option<u64>,
    /// Milliseconds it takes to refill an empty bucket.
    pub refill_time: u64,
}

impl TokenBucket {
    /// Firecracker treats a bucket with zero size or refill time as "no
    /// limit", which is how a live update turns a bucket off.
    pub const DISABLED: TokenBucket = TokenBucket {
        size: 0,
        one_time_burst: None,
        refill_time: 0,
    };
}

/// A device rate limiter (`RateLimiter`): independent bandwidth and
/// operations buckets; an absent bucket does not limit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimiter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bandwidth: Option<TokenBucket>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ops: Option<TokenBucket>,
}

impl RateLimiter {
    /// Body for a live update that leaves the device limited exactly as
    /// `limiter` says, whatever the snapshot it was restored from carried:
    /// buckets that are not configured are turned off explicitly.
    pub fn live_update(limiter: Option<&RateLimiter>) -> RateLimiter {
        let l = limiter.copied().unwrap_or_default();
        RateLimiter {
            bandwidth: Some(l.bandwidth.unwrap_or(TokenBucket::DISABLED)),
            ops: Some(l.ops.unwrap_or(TokenBucket::DISABLED)),
        }
    }
}

/// Per-VM I/O limits. `None` disables a limiter; [`RateLimits::default`]
/// holds conservative values for a shared host.
///
/// Network and disk limits are applied when a template VM boots and again
/// right after every restore, so changing them takes effect for existing
/// templates and snapshots. The entropy limiter is fixed when the template is
/// built (Firecracker cannot update it later). The serial limiter is not part
/// of snapshots and is set on every boot and restore.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct RateLimits {
    /// Guest-bound network traffic.
    pub net_rx: Option<RateLimiter>,
    /// Traffic the guest sends.
    pub net_tx: Option<RateLimiter>,
    /// The root filesystem's virtio-block device.
    pub disk: Option<RateLimiter>,
    /// The virtio-rng device.
    pub entropy: Option<RateLimiter>,
    /// Serial console output; bytes beyond the rate are dropped by Firecracker.
    pub serial: Option<TokenBucket>,
}

impl Default for RateLimits {
    fn default() -> Self {
        // 1 Gbit/s each way, refilled in 100 ms steps so bursts stay short.
        let net = RateLimiter {
            bandwidth: Some(TokenBucket {
                size: 12_500_000,
                one_time_burst: None,
                refill_time: 100,
            }),
            ops: None,
        };
        Self {
            net_rx: Some(net),
            net_tx: Some(net),
            // 200 MiB/s and 10,000 operations per second.
            disk: Some(RateLimiter {
                bandwidth: Some(TokenBucket {
                    size: 20 << 20,
                    one_time_burst: None,
                    refill_time: 100,
                }),
                ops: Some(TokenBucket {
                    size: 1_000,
                    one_time_burst: None,
                    refill_time: 100,
                }),
            }),
            // 64 KiB/s: plenty for reseeding, useless as a host CPU sink.
            entropy: Some(RateLimiter {
                bandwidth: Some(TokenBucket {
                    size: 64 << 10,
                    one_time_burst: None,
                    refill_time: 1_000,
                }),
                ops: None,
            }),
            // 16 KiB/s after a 256 KiB allowance that covers a verbose boot.
            serial: Some(TokenBucket {
                size: 16 << 10,
                one_time_burst: Some(256 << 10),
                refill_time: 1_000,
            }),
        }
    }
}

/// `PUT /machine-config` (`MachineConfiguration`).
#[derive(Debug, Serialize)]
pub struct MachineConfig {
    pub vcpu_count: u32,
    pub mem_size_mib: u32,
    pub smt: bool,
    pub track_dirty_pages: bool,
}

/// `PUT /boot-source` (`BootSource`).
#[derive(Debug, Serialize)]
pub struct BootSource<'a> {
    pub kernel_image_path: &'a str,
    pub boot_args: &'a str,
}

/// `PUT /drives/{drive_id}` (`Drive`).
#[derive(Debug, Serialize)]
pub struct Drive<'a> {
    pub drive_id: &'a str,
    pub path_on_host: &'a str,
    pub is_root_device: bool,
    pub is_read_only: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limiter: Option<RateLimiter>,
}

/// `PATCH /drives/{drive_id}` (`PartialDrive`).
#[derive(Debug, Serialize)]
pub struct PartialDrive<'a> {
    pub drive_id: &'a str,
    pub rate_limiter: RateLimiter,
}

/// `PUT /network-interfaces/{iface_id}` (`NetworkInterface`).
#[derive(Debug, Serialize)]
pub struct NetworkInterface<'a> {
    pub iface_id: &'a str,
    pub host_dev_name: &'a str,
    pub guest_mac: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_rate_limiter: Option<RateLimiter>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_rate_limiter: Option<RateLimiter>,
}

/// `PATCH /network-interfaces/{iface_id}` (`PartialNetworkInterface`).
#[derive(Debug, Serialize)]
pub struct PartialNetworkInterface<'a> {
    pub iface_id: &'a str,
    pub rx_rate_limiter: RateLimiter,
    pub tx_rate_limiter: RateLimiter,
}

/// `PUT /entropy` (`EntropyDevice`).
#[derive(Debug, Serialize)]
pub struct EntropyDevice {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limiter: Option<RateLimiter>,
}

/// `PUT /serial` (`SerialDevice`). Without `serial_out_path` the console
/// keeps going to Firecracker's stdout.
#[derive(Debug, Serialize)]
pub struct SerialDevice {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limiter: Option<TokenBucket>,
}

/// `PUT /actions` (`InstanceActionInfo`).
#[derive(Debug, Serialize)]
pub struct InstanceAction {
    pub action_type: &'static str,
}

impl InstanceAction {
    pub const START: InstanceAction = InstanceAction {
        action_type: "InstanceStart",
    };
}

/// `PATCH /vm` (`Vm`).
#[derive(Debug, Serialize)]
pub struct VmState {
    pub state: &'static str,
}

impl VmState {
    pub const PAUSED: VmState = VmState { state: "Paused" };
}

/// `PUT /snapshot/create` (`SnapshotCreateParams`).
#[derive(Debug, Serialize)]
pub struct SnapshotCreate<'a> {
    pub snapshot_type: &'static str,
    pub snapshot_path: &'a str,
    pub mem_file_path: &'a str,
}

impl<'a> SnapshotCreate<'a> {
    pub fn full(snapshot_path: &'a str, mem_file_path: &'a str) -> Self {
        Self {
            snapshot_type: "Full",
            snapshot_path,
            mem_file_path,
        }
    }
}

/// `PUT /snapshot/load` (`SnapshotLoadParams`).
#[derive(Debug, Serialize)]
pub struct SnapshotLoad<'a> {
    pub snapshot_path: &'a str,
    pub mem_backend: MemoryBackend<'a>,
    pub resume_vm: bool,
}

/// `MemoryBackend`: `File` maps the memory file privately, so pages load on
/// demand and the file itself is never written.
#[derive(Debug, Serialize)]
pub struct MemoryBackend<'a> {
    pub backend_type: &'static str,
    pub backend_path: &'a str,
}

impl<'a> SnapshotLoad<'a> {
    pub fn from_file(snapshot_path: &'a str, mem_file_path: &'a str) -> Self {
        Self {
            snapshot_path,
            mem_backend: MemoryBackend {
                backend_type: "File",
                backend_path: mem_file_path,
            },
            resume_vm: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    /// Property names of the swagger definitions, Firecracker v1.17.0.
    const SWAGGER: &[(&str, &[&str])] = &[
        (
            "MachineConfiguration",
            &[
                "cpu_template",
                "smt",
                "mem_size_mib",
                "track_dirty_pages",
                "vcpu_count",
                "huge_pages",
            ],
        ),
        (
            "BootSource",
            &["boot_args", "initrd_path", "kernel_image_path"],
        ),
        (
            "Drive",
            &[
                "drive_id",
                "partuuid",
                "is_root_device",
                "cache_type",
                "is_read_only",
                "discard",
                "path_on_host",
                "rate_limiter",
                "io_engine",
                "blk_size",
                "topology",
                "socket",
            ],
        ),
        (
            "PartialDrive",
            &["drive_id", "path_on_host", "rate_limiter"],
        ),
        (
            "NetworkInterface",
            &[
                "guest_mac",
                "host_dev_name",
                "iface_id",
                "mtu",
                "rx_rate_limiter",
                "tx_rate_limiter",
            ],
        ),
        (
            "PartialNetworkInterface",
            &["iface_id", "rx_rate_limiter", "tx_rate_limiter"],
        ),
        ("EntropyDevice", &["rate_limiter"]),
        ("SerialDevice", &["serial_out_path", "rate_limiter"]),
        ("InstanceActionInfo", &["action_type"]),
        ("Vm", &["state"]),
        (
            "SnapshotCreateParams",
            &[
                "mem_file_path",
                "snapshot_path",
                "snapshot_type",
                "sync_snapshot_files",
            ],
        ),
        (
            "SnapshotLoadParams",
            &[
                "enable_diff_snapshots",
                "track_dirty_pages",
                "mem_file_path",
                "mem_backend",
                "snapshot_path",
                "resume_vm",
                "network_overrides",
                "vsock_override",
                "clock_realtime",
                "huge_pages",
            ],
        ),
        ("MemoryBackend", &["backend_type", "backend_path"]),
        ("RateLimiter", &["bandwidth", "ops"]),
        ("TokenBucket", &["one_time_burst", "refill_time", "size"]),
    ];

    fn assert_matches(definition: &str, body: &impl Serialize) -> Value {
        let value = serde_json::to_value(body).unwrap();
        check(definition, &value);
        value
    }

    fn check(definition: &str, value: &Value) {
        let allowed = SWAGGER.iter().find(|(d, _)| *d == definition).unwrap().1;
        let obj = value
            .as_object()
            .unwrap_or_else(|| panic!("{definition} must be an object"));
        for (key, v) in obj {
            assert!(
                allowed.contains(&key.as_str()),
                "{definition} has no property {key:?}"
            );
            let nested = match key.as_str() {
                "rate_limiter" if definition == "SerialDevice" => Some("TokenBucket"),
                "rate_limiter" | "rx_rate_limiter" | "tx_rate_limiter" => Some("RateLimiter"),
                "bandwidth" | "ops" => Some("TokenBucket"),
                "mem_backend" => Some("MemoryBackend"),
                _ => None,
            };
            if let Some(n) = nested {
                check(n, v);
            }
        }
    }

    #[test]
    fn bodies_use_swagger_names() {
        let limits = RateLimits::default();
        let machine = assert_matches(
            "MachineConfiguration",
            &MachineConfig {
                vcpu_count: 2,
                mem_size_mib: 1024,
                smt: false,
                track_dirty_pages: false,
            },
        );
        assert_eq!(
            machine,
            json!({"vcpu_count": 2, "mem_size_mib": 1024, "smt": false, "track_dirty_pages": false})
        );
        assert_matches(
            "BootSource",
            &BootSource {
                kernel_image_path: "/vmlinux",
                boot_args: "console=ttyS0",
            },
        );
        let drive = assert_matches(
            "Drive",
            &Drive {
                drive_id: "rootfs",
                path_on_host: "/rootfs.ext4",
                is_root_device: true,
                is_read_only: false,
                rate_limiter: limits.disk,
            },
        );
        assert_eq!(
            drive["rate_limiter"]["ops"],
            json!({"size": 1000, "refill_time": 100})
        );
        assert_matches(
            "PartialDrive",
            &PartialDrive {
                drive_id: "rootfs",
                rate_limiter: RateLimiter::live_update(limits.disk.as_ref()),
            },
        );
        let net = assert_matches(
            "NetworkInterface",
            &NetworkInterface {
                iface_id: "eth0",
                host_dev_name: "tap0",
                guest_mac: "06:00:a9:fe:00:15",
                rx_rate_limiter: limits.net_rx,
                tx_rate_limiter: None,
            },
        );
        assert!(
            net.get("tx_rate_limiter").is_none(),
            "unset limiters are omitted"
        );
        assert_matches(
            "PartialNetworkInterface",
            &PartialNetworkInterface {
                iface_id: "eth0",
                rx_rate_limiter: RateLimiter::live_update(None),
                tx_rate_limiter: RateLimiter::live_update(limits.net_tx.as_ref()),
            },
        );
        assert_eq!(
            assert_matches("EntropyDevice", &EntropyDevice { rate_limiter: None }),
            json!({})
        );
        let serial = assert_matches(
            "SerialDevice",
            &SerialDevice {
                rate_limiter: limits.serial,
            },
        );
        assert_eq!(
            serial,
            json!({"rate_limiter": {"size": 16384, "one_time_burst": 262144, "refill_time": 1000}})
        );
        assert_eq!(
            assert_matches("InstanceActionInfo", &InstanceAction::START),
            json!({"action_type": "InstanceStart"})
        );
        assert_eq!(
            assert_matches("Vm", &VmState::PAUSED),
            json!({"state": "Paused"})
        );
    }

    #[test]
    fn snapshot_bodies() {
        let create = assert_matches(
            "SnapshotCreateParams",
            &SnapshotCreate::full("/vmstate.new", "/memory.new"),
        );
        assert_eq!(
            create,
            json!({"snapshot_type": "Full", "snapshot_path": "/vmstate.new", "mem_file_path": "/memory.new"})
        );
        let load = assert_matches(
            "SnapshotLoadParams",
            &SnapshotLoad::from_file("/vmstate", "/memory"),
        );
        assert_eq!(
            load,
            json!({
                "snapshot_path": "/vmstate",
                "mem_backend": {"backend_type": "File", "backend_path": "/memory"},
                "resume_vm": true
            })
        );
    }

    #[test]
    fn live_updates_turn_unconfigured_buckets_off() {
        let off = serde_json::to_value(RateLimiter::live_update(None)).unwrap();
        assert_eq!(
            off,
            json!({"bandwidth": {"size": 0, "refill_time": 0}, "ops": {"size": 0, "refill_time": 0}})
        );
        let bw_only = RateLimiter {
            bandwidth: Some(TokenBucket {
                size: 10,
                one_time_burst: Some(5),
                refill_time: 100,
            }),
            ops: None,
        };
        let v = serde_json::to_value(RateLimiter::live_update(Some(&bw_only))).unwrap();
        assert_eq!(
            v["bandwidth"],
            json!({"size": 10, "one_time_burst": 5, "refill_time": 100})
        );
        assert_eq!(v["ops"], json!({"size": 0, "refill_time": 0}));
    }

    #[test]
    fn rate_limits_can_be_configured_and_disabled() {
        let d = RateLimits::default();
        // 1 Gbit/s = 125,000,000 bytes/s.
        let bw = d.net_rx.unwrap().bandwidth.unwrap();
        assert_eq!(bw.size * 1000 / bw.refill_time, 125_000_000);
        let none: RateLimits = serde_json::from_value(
            json!({"netRx": null, "netTx": null, "disk": null, "entropy": null, "serial": null}),
        )
        .unwrap();
        assert!(none.net_rx.is_none() && none.disk.is_none() && none.serial.is_none());
        // Omitted fields keep their defaults.
        let partial: RateLimits = serde_json::from_value(json!({"disk": null})).unwrap();
        assert_eq!(partial.net_rx, d.net_rx);
        assert!(partial.disk.is_none());
    }
}
