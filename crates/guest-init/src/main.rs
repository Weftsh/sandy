//! `weft-guest-init` is PID 1 inside every Weft sandbox.
//!
//! It prepares the minimal Linux environment the in-guest agent (`envd`)
//! expects, starts `envd`, restarts it if it dies, and reaps orphaned
//! processes. It runs in two modes:
//!
//! * `vm`: inside a Firecracker microVM. Settings come from `weft.*` kernel
//!   command-line parameters. The kernel configures `eth0` from the `ip=`
//!   parameter.
//! * `namespace`: inside the development runtime's Linux namespaces. The host
//!   agent has already set up the network namespace; settings come from
//!   command-line flags.
//!
//! This binary contains no isolation logic. The isolation boundary is the
//! microVM (or, in development, nothing at all).

mod config;
mod mounts;
mod supervisor;

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let cfg = match config::Config::from_sources(&args, &cmdline) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("weft-guest-init: {err}");
            return ExitCode::from(2);
        }
    };
    if std::process::id() != 1 && !cfg.allow_non_pid1 {
        eprintln!("weft-guest-init: must run as PID 1 (pass --allow-non-pid1 for testing)");
        return ExitCode::from(2);
    }
    if let Err(err) = mounts::prepare(&cfg) {
        eprintln!("weft-guest-init: preparing the environment failed: {err}");
        // Keep going: a sandbox with a missing mount is still more useful to
        // debug than one that never starts.
    }
    supervisor::run(&cfg)
}
