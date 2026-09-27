//! Configuration from kernel command-line parameters (VM mode) or flags
//! (namespace mode).

use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Vm,
    Namespace,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub mode: Mode,
    pub hostname: String,
    /// Resolver written to /etc/resolv.conf.
    pub dns: Option<String>,
    /// Path to envd inside the root filesystem.
    pub envd_path: String,
    pub envd_args: Vec<String>,
    /// For tests: run without being PID 1 and without mounting anything.
    pub allow_non_pid1: bool,
    pub skip_mounts: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

pub const DEFAULT_ENVD_PATH: &str = "/usr/bin/envd";
pub const DEFAULT_HOSTNAME: &str = "sandbox";

impl Config {
    /// Flags win over kernel parameters, so a VM can be debugged by editing
    /// the init arguments without rebuilding the kernel command line.
    pub fn from_sources(args: &[String], cmdline: &str) -> Result<Self, ConfigError> {
        let mut cfg = Config {
            mode: Mode::Vm,
            hostname: DEFAULT_HOSTNAME.to_owned(),
            dns: None,
            envd_path: DEFAULT_ENVD_PATH.to_owned(),
            envd_args: Vec::new(),
            allow_non_pid1: false,
            skip_mounts: false,
        };
        for (key, value) in parse_cmdline(cmdline) {
            match key {
                "weft.hostname" => cfg.hostname = value.to_owned(),
                "weft.dns" => cfg.dns = Some(value.to_owned()),
                "weft.envd" => cfg.envd_path = value.to_owned(),
                "weft.envd_args" => {
                    cfg.envd_args = value
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned)
                        .collect()
                }
                _ => {}
            }
        }

        let mut it = args.iter();
        while let Some(arg) = it.next() {
            let mut value = |name: &str| {
                it.next()
                    .cloned()
                    .ok_or_else(|| ConfigError(format!("{name} needs a value")))
            };
            match arg.as_str() {
                "--mode" => {
                    cfg.mode = match value("--mode")?.as_str() {
                        "vm" => Mode::Vm,
                        "namespace" => Mode::Namespace,
                        other => return Err(ConfigError(format!("unknown mode {other:?}"))),
                    }
                }
                "--hostname" => cfg.hostname = value("--hostname")?,
                "--dns" => cfg.dns = Some(value("--dns")?),
                "--envd" => cfg.envd_path = value("--envd")?,
                "--envd-arg" => cfg.envd_args.push(value("--envd-arg")?),
                "--allow-non-pid1" => cfg.allow_non_pid1 = true,
                "--skip-mounts" => cfg.skip_mounts = true,
                // The kernel passes plain words from the command line through
                // to init; ignore the ones we do not know.
                _ if !arg.starts_with("--") => {}
                other => return Err(ConfigError(format!("unknown flag {other}"))),
            }
        }
        if !is_valid_hostname(&cfg.hostname) {
            return Err(ConfigError(format!("invalid hostname {:?}", cfg.hostname)));
        }
        if let Some(dns) = &cfg.dns {
            if dns.parse::<std::net::IpAddr>().is_err() {
                return Err(ConfigError(format!("invalid DNS server {dns:?}")));
            }
        }
        Ok(cfg)
    }
}

/// Splits a kernel command line into `key=value` pairs. Quoted values are not
/// used by Weft and are not supported.
pub fn parse_cmdline(cmdline: &str) -> impl Iterator<Item = (&str, &str)> {
    cmdline
        .split_ascii_whitespace()
        .filter_map(|tok| tok.split_once('='))
}

fn is_valid_hostname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !name.starts_with('-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn reads_kernel_parameters() {
        let cfg = Config::from_sources(
            &[],
            "console=ttyS0 reboot=k panic=1 ip=169.254.0.21::169.254.0.22:255.255.255.252::eth0:off \
             weft.hostname=i7x2k9 weft.dns=169.254.0.22 weft.envd_args=-port,49983",
        )
        .unwrap();
        assert_eq!(cfg.mode, Mode::Vm);
        assert_eq!(cfg.hostname, "i7x2k9");
        assert_eq!(cfg.dns.as_deref(), Some("169.254.0.22"));
        assert_eq!(cfg.envd_args, s(&["-port", "49983"]));
        assert_eq!(cfg.envd_path, DEFAULT_ENVD_PATH);
    }

    #[test]
    fn flags_override_kernel_parameters() {
        let cfg = Config::from_sources(
            &s(&[
                "--mode",
                "namespace",
                "--hostname",
                "abc",
                "--envd-arg",
                "-isnotfc",
            ]),
            "weft.hostname=zzz",
        )
        .unwrap();
        assert_eq!(cfg.mode, Mode::Namespace);
        assert_eq!(cfg.hostname, "abc");
        assert_eq!(cfg.envd_args, s(&["-isnotfc"]));
    }

    #[test]
    fn rejects_bad_input() {
        assert!(Config::from_sources(&s(&["--mode", "container"]), "").is_err());
        assert!(Config::from_sources(&s(&["--hostname", "bad name"]), "").is_err());
        assert!(Config::from_sources(&s(&["--dns", "not-an-ip"]), "").is_err());
        assert!(Config::from_sources(&s(&["--bogus"]), "").is_err());
        assert!(Config::from_sources(&s(&["--hostname"]), "").is_err());
    }

    #[test]
    fn ignores_plain_words_from_the_kernel() {
        assert!(Config::from_sources(&s(&["quiet", "ro"]), "").is_ok());
    }
}
