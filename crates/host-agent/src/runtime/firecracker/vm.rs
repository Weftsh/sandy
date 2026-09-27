//! What the runtime asks of Firecracker: the kernel command line and the
//! API call sequences that boot a template VM, restore a sandbox and take a
//! snapshot.
//!
//! Snapshots record device configuration, including the root drive's
//! chroot-relative path and the tap device's name, so every VM is configured
//! with the same names ([`super::jail::in_jail`], `tap0`, [`GUEST_MAC`]) and
//! any jail can restore any snapshot.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use super::api::{ApiClient, ApiError};
use super::jail::in_jail;
use super::model::{
    BootSource, Drive, EntropyDevice, InstanceAction, MachineConfig, NetworkInterface,
    PartialDrive, PartialNetworkInterface, RateLimiter, RateLimits, SerialDevice, SnapshotCreate,
    SnapshotLoad, VmState,
};
use crate::envd::ENVD_PORT;
use crate::net::{GUEST_GATEWAY, GUEST_IP, GUEST_PREFIX};
use crate::rootfs::{GUEST_ENVD_PATH, GUEST_INIT_PATH};

pub const ROOT_DRIVE: &str = "rootfs";
pub const GUEST_IFACE: &str = "eth0";
/// The slot namespace's tap device (see `net.rs`).
pub const TAP_DEVICE: &str = "tap0";
/// Locally administered, derived from the guest address 169.254.0.21. Part
/// of every snapshot, so it never changes.
pub const GUEST_MAC: &str = "06:00:a9:fe:00:15";

/// Kernel command line of a template VM. Restored sandboxes keep it.
///
/// `ip=` has the kernel configure `eth0` before init runs; `weft.*` are read
/// by `weft-guest-init` from `/proc/cmdline`. envd runs with `-isnotfc`
/// (settings come from `/init`, not from Firecracker's metadata service) and
/// manages cgroups inside the guest, which is its own kernel.
pub fn boot_args() -> String {
    let netmask = Ipv4Addr::from(u32::MAX << (32 - u32::from(GUEST_PREFIX)));
    [
        "console=ttyS0".to_owned(),
        "reboot=k".to_owned(),
        "panic=1".to_owned(),
        "pci=off".to_owned(),
        format!("ip={GUEST_IP}::{GUEST_GATEWAY}:{netmask}::{GUEST_IFACE}:off"),
        format!("init=/{GUEST_INIT_PATH}"),
        format!("weft.dns={GUEST_GATEWAY}"),
        format!("weft.envd=/{GUEST_ENVD_PATH}"),
        format!("weft.envd_args=-isnotfc,-port,{ENVD_PORT}"),
    ]
    .join(" ")
}

/// A fresh template VM.
pub struct BootPlan<'a> {
    pub vcpus: u32,
    pub memory_mib: u32,
    pub boot_args: &'a str,
    pub limits: &'a RateLimits,
    /// Custom CPU template JSON (`PUT /cpu-config`).
    pub cpu_template: Option<Vec<u8>>,
}

/// Configures and starts a VM whose kernel and root image are in the jail.
pub async fn boot(api: &ApiClient, plan: &BootPlan<'_>) -> Result<(), ApiError> {
    if plan.limits.serial.is_some() {
        api.put(
            "/serial",
            &SerialDevice {
                rate_limiter: plan.limits.serial,
            },
        )
        .await?;
    }
    let machine = MachineConfig {
        vcpu_count: plan.vcpus,
        mem_size_mib: plan.memory_mib,
        smt: false,
        track_dirty_pages: false,
    };
    api.put("/machine-config", &machine).await?;
    if let Some(template) = &plan.cpu_template {
        api.put_raw("/cpu-config", template.clone()).await?;
    }
    api.put(
        "/boot-source",
        &BootSource {
            kernel_image_path: in_jail::KERNEL,
            boot_args: plan.boot_args,
        },
    )
    .await?;
    let drive = Drive {
        drive_id: ROOT_DRIVE,
        path_on_host: in_jail::ROOTFS,
        is_root_device: true,
        is_read_only: false,
        rate_limiter: plan.limits.disk,
    };
    api.put(&format!("/drives/{ROOT_DRIVE}"), &drive).await?;
    let nic = NetworkInterface {
        iface_id: GUEST_IFACE,
        host_dev_name: TAP_DEVICE,
        guest_mac: GUEST_MAC,
        rx_rate_limiter: plan.limits.net_rx,
        tx_rate_limiter: plan.limits.net_tx,
    };
    api.put(&format!("/network-interfaces/{GUEST_IFACE}"), &nic)
        .await?;
    api.put(
        "/entropy",
        &EntropyDevice {
            rate_limiter: plan.limits.entropy,
        },
    )
    .await?;
    api.put("/actions", &InstanceAction::START).await
}

/// Loads the snapshot linked into the jail, resumes it, and re-applies the
/// configured I/O limits (the snapshot carries the ones it was taken with).
/// Before the load only the serial console may be configured: any other
/// device configuration makes Firecracker refuse to load a snapshot.
pub async fn restore(
    api: &ApiClient,
    limits: &RateLimits,
    load_timeout: Duration,
) -> Result<(), ApiError> {
    if limits.serial.is_some() {
        api.put(
            "/serial",
            &SerialDevice {
                rate_limiter: limits.serial,
            },
        )
        .await?;
    }
    api.put_within(
        "/snapshot/load",
        &SnapshotLoad::from_file(in_jail::VMSTATE, in_jail::MEMORY),
        load_timeout,
    )
    .await?;
    let drive = PartialDrive {
        drive_id: ROOT_DRIVE,
        rate_limiter: RateLimiter::live_update(limits.disk.as_ref()),
    };
    api.patch(&format!("/drives/{ROOT_DRIVE}"), &drive).await?;
    let nic = PartialNetworkInterface {
        iface_id: GUEST_IFACE,
        rx_rate_limiter: RateLimiter::live_update(limits.net_rx.as_ref()),
        tx_rate_limiter: RateLimiter::live_update(limits.net_tx.as_ref()),
    };
    api.patch(&format!("/network-interfaces/{GUEST_IFACE}"), &nic)
        .await
}

/// Pauses the VM and writes a full snapshot into the jail. Firecracker drains
/// and fsyncs the root drive as part of it, so the image matches the memory.
pub async fn snapshot(api: &ApiClient, timeout: Duration) -> Result<(), ApiError> {
    api.patch("/vm", &VmState::PAUSED).await?;
    api.put_within(
        "/snapshot/create",
        &SnapshotCreate::full(in_jail::VMSTATE_OUT, in_jail::MEMORY_OUT),
        timeout,
    )
    .await
}

/// Shell command that starts a template's start command in the background
/// and returns at once. Output goes to `/tmp/start.log` in the guest.
pub fn start_command(start_cmd: &str, env: &BTreeMap<String, String>) -> Result<String, String> {
    Ok(format!(
        "{}nohup sh -c {} >/tmp/start.log 2>&1 &",
        exports(env)?,
        sh_quote(start_cmd)
    ))
}

/// Shell command that runs a template's ready command once.
pub fn ready_command(ready_cmd: &str, env: &BTreeMap<String, String>) -> Result<String, String> {
    Ok(format!("{}{ready_cmd}", exports(env)?))
}

fn exports(env: &BTreeMap<String, String>) -> Result<String, String> {
    let mut out = String::new();
    for (name, value) in env {
        let valid = name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            return Err(format!("invalid environment variable name {name:?}"));
        }
        out.push_str(&format!("export {name}={}; ", sh_quote(value)));
    }
    Ok(out)
}

/// Quotes a string as one POSIX shell word.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::super::api::fake::FakeFirecracker;
    use super::*;
    use serde_json::json;

    #[test]
    fn kernel_command_line() {
        let args = boot_args();
        assert_eq!(
            args,
            "console=ttyS0 reboot=k panic=1 pci=off \
             ip=169.254.0.21::169.254.0.22:255.255.255.252::eth0:off \
             init=/usr/local/bin/weft-guest-init weft.dns=169.254.0.22 weft.envd=/usr/bin/envd \
             weft.envd_args=-isnotfc,-port,49983"
        );
        assert!(
            !args.contains("-no-cgroups"),
            "envd owns the guest's cgroups in a VM"
        );
        // The guest init parses the same keys (crates/guest-init/src/config.rs).
        let kv: BTreeMap<&str, &str> = args
            .split_whitespace()
            .filter_map(|t| t.split_once('='))
            .collect();
        assert_eq!(
            kv["weft.envd_args"].split(',').collect::<Vec<_>>(),
            ["-isnotfc", "-port", "49983"]
        );
    }

    #[test]
    fn guest_mac_is_unicast_and_locally_administered() {
        let first = u8::from_str_radix(&GUEST_MAC[..2], 16).unwrap();
        assert_eq!(first & 0b11, 0b10);
        assert_eq!(GUEST_MAC.split(':').count(), 6);
    }

    #[test]
    fn start_and_ready_commands_quote_everything() {
        let env = BTreeMap::from([
            ("A".to_owned(), "it's".to_owned()),
            ("B_2".to_owned(), "$HOME".to_owned()),
        ]);
        assert_eq!(
            start_command("python -m http.server 'x'", &env).unwrap(),
            r#"export A='it'\''s'; export B_2='$HOME'; nohup sh -c 'python -m http.server '\''x'\''' >/tmp/start.log 2>&1 &"#
        );
        assert_eq!(
            ready_command("curl -sf localhost:8000", &BTreeMap::new()).unwrap(),
            "curl -sf localhost:8000"
        );
        for bad in ["1A", "A-B", "", "A B", "A;rm"] {
            let env = BTreeMap::from([(bad.to_owned(), "v".to_owned())]);
            assert!(start_command("true", &env).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn quoted_commands_survive_a_real_shell() {
        let env = BTreeMap::from([("GREETING".to_owned(), "it's $(not) `run`".to_owned())]);
        let cmd = ready_command("printf '%s' \"$GREETING\"", &env).unwrap();
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .output()
            .unwrap();
        assert_eq!(String::from_utf8(out.stdout).unwrap(), "it's $(not) `run`");
    }

    fn api(dir: &std::path::Path) -> ApiClient {
        ApiClient::new(dir.join("api.sock"), Duration::from_secs(5))
    }

    #[tokio::test]
    async fn boot_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let fc = FakeFirecracker::serve(&dir.path().join("api.sock"), vec![]);
        let limits = RateLimits::default();
        let args = boot_args();
        let plan = BootPlan {
            vcpus: 2,
            memory_mib: 1024,
            boot_args: &args,
            limits: &limits,
            cpu_template: None,
        };
        boot(&api(dir.path()), &plan).await.unwrap();
        assert_eq!(
            fc.paths(),
            [
                "PUT /serial",
                "PUT /machine-config",
                "PUT /boot-source",
                "PUT /drives/rootfs",
                "PUT /network-interfaces/eth0",
                "PUT /entropy",
                "PUT /actions",
            ]
        );
        let calls = fc.calls();
        assert_eq!(
            calls[1].body,
            json!({"vcpu_count": 2, "mem_size_mib": 1024, "smt": false, "track_dirty_pages": false})
        );
        assert_eq!(
            calls[2].body,
            json!({"kernel_image_path": "/vmlinux", "boot_args": args})
        );
        assert_eq!(calls[3].body["path_on_host"], "/rootfs.ext4");
        assert_eq!(calls[3].body["is_root_device"], true);
        assert_eq!(calls[4].body["host_dev_name"], "tap0");
        assert_eq!(calls[4].body["guest_mac"], GUEST_MAC);
        assert!(calls[4].body["rx_rate_limiter"]["bandwidth"]["size"].is_u64());
        assert!(calls[5].body["rate_limiter"].is_object());
        assert_eq!(calls[6].body, json!({"action_type": "InstanceStart"}));
    }

    #[tokio::test]
    async fn boot_without_limits_but_with_a_cpu_template() {
        let dir = tempfile::tempdir().unwrap();
        let fc = FakeFirecracker::serve(&dir.path().join("api.sock"), vec![]);
        let limits = RateLimits {
            net_rx: None,
            net_tx: None,
            disk: None,
            entropy: None,
            serial: None,
        };
        let plan = BootPlan {
            vcpus: 1,
            memory_mib: 512,
            boot_args: "console=ttyS0",
            limits: &limits,
            cpu_template: Some(br#"{"cpuid_modifiers":[]}"#.to_vec()),
        };
        boot(&api(dir.path()), &plan).await.unwrap();
        assert_eq!(fc.paths()[0..2], ["PUT /machine-config", "PUT /cpu-config"]);
        let calls = fc.calls();
        let drive = calls.iter().find(|c| c.path == "/drives/rootfs").unwrap();
        assert!(drive.body.get("rate_limiter").is_none());
        let entropy = calls.iter().find(|c| c.path == "/entropy").unwrap();
        assert_eq!(
            entropy.body,
            json!({}),
            "the entropy device is always attached"
        );
    }

    #[tokio::test]
    async fn restore_sequence_configures_nothing_but_the_console_before_loading() {
        let dir = tempfile::tempdir().unwrap();
        let fc = FakeFirecracker::serve(&dir.path().join("api.sock"), vec![]);
        let limits = RateLimits {
            disk: None,
            ..RateLimits::default()
        };
        restore(&api(dir.path()), &limits, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(
            fc.paths(),
            [
                "PUT /serial",
                "PUT /snapshot/load",
                "PATCH /drives/rootfs",
                "PATCH /network-interfaces/eth0"
            ]
        );
        let calls = fc.calls();
        assert_eq!(
            calls[1].body,
            json!({
                "snapshot_path": "/vmstate",
                "mem_backend": {"backend_type": "File", "backend_path": "/memory"},
                "resume_vm": true
            })
        );
        // Disk limits are off in the config, so they are switched off live.
        assert_eq!(
            calls[2].body["rate_limiter"]["bandwidth"],
            json!({"size": 0, "refill_time": 0})
        );
        assert_eq!(
            calls[3].body["tx_rate_limiter"]["bandwidth"]["size"],
            12_500_000
        );
    }

    #[tokio::test]
    async fn failed_loads_stop_the_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let fc = FakeFirecracker::serve(
            &dir.path().join("api.sock"),
            vec![(
                "PUT",
                "/snapshot/load",
                400,
                r#"{"fault_message":"Snapshot version mismatch"}"#,
            )],
        );
        let err = restore(
            &api(dir.path()),
            &RateLimits::default(),
            Duration::from_secs(5),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("Snapshot version mismatch"),
            "{err}"
        );
        assert_eq!(fc.paths(), ["PUT /serial", "PUT /snapshot/load"]);
    }

    #[tokio::test]
    async fn snapshot_sequence_writes_new_files() {
        let dir = tempfile::tempdir().unwrap();
        let fc = FakeFirecracker::serve(&dir.path().join("api.sock"), vec![]);
        snapshot(&api(dir.path()), Duration::from_secs(5))
            .await
            .unwrap();
        let calls = fc.calls();
        assert_eq!(fc.paths(), ["PATCH /vm", "PUT /snapshot/create"]);
        assert_eq!(calls[0].body, json!({"state": "Paused"}));
        assert_eq!(
            calls[1].body,
            json!({"snapshot_type": "Full", "snapshot_path": "/vmstate.new", "mem_file_path": "/memory.new"})
        );
    }
}
