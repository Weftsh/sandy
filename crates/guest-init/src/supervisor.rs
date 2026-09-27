//! Starts envd, restarts it when it exits, reaps orphans and shuts down on
//! SIGTERM.

use std::process::{Child, Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use signal_hook::consts::{SIGCHLD, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

use crate::config::{Config, Mode};

const PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const MAX_BACKOFF: Duration = Duration::from_secs(5);

pub fn run(cfg: &Config) -> ExitCode {
    let mut signals = match Signals::new([SIGCHLD, SIGTERM, SIGINT]) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("weft-guest-init: installing signal handlers: {err}");
            return ExitCode::FAILURE;
        }
    };
    let mut backoff = Duration::from_millis(100);
    let mut envd = spawn_envd(cfg);
    loop {
        for signal in signals.wait() {
            match signal {
                SIGTERM | SIGINT => return shutdown(cfg),
                SIGCHLD => {}
                _ => continue,
            }
        }
        // Reap every exited child, envd included.
        let envd_pid = envd.as_ref().map(|c| Pid::from_raw(c.id() as i32));
        let mut envd_exited = envd.is_none();
        loop {
            match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) | Err(Errno::ECHILD) => break,
                Ok(status) => {
                    if status.pid() == envd_pid {
                        eprintln!("weft-guest-init: envd exited: {status:?}");
                        envd_exited = true;
                    }
                }
                Err(Errno::EINTR) => continue,
                Err(err) => {
                    eprintln!("weft-guest-init: waitpid: {err}");
                    break;
                }
            }
        }
        if envd_exited {
            let started = Instant::now();
            std::thread::sleep(backoff);
            envd = spawn_envd(cfg);
            backoff = if started.elapsed() > Duration::from_secs(30) {
                Duration::from_millis(100)
            } else {
                (backoff * 2).min(MAX_BACKOFF)
            };
        }
    }
}

fn spawn_envd(cfg: &Config) -> Option<Child> {
    let child = Command::new(&cfg.envd_path)
        .args(&cfg.envd_args)
        .env_clear()
        .env("PATH", PATH)
        .env("HOME", "/root")
        .env("LANG", "C.UTF-8")
        .current_dir("/")
        .stdin(Stdio::null())
        .spawn();
    match child {
        Ok(child) => Some(child),
        Err(err) => {
            eprintln!("weft-guest-init: starting {}: {err}", cfg.envd_path);
            None
        }
    }
}

fn shutdown(cfg: &Config) -> ExitCode {
    // Ask everything to stop, give it a moment, then force it.
    let _ = kill(Pid::from_raw(-1), Signal::SIGTERM);
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
            Err(Errno::ECHILD) => break,
            Ok(WaitStatus::StillAlive) => std::thread::sleep(Duration::from_millis(50)),
            _ => {}
        }
    }
    let _ = kill(Pid::from_raw(-1), Signal::SIGKILL);
    nix::unistd::sync();
    if cfg.mode == Mode::Vm && !cfg.allow_non_pid1 {
        // Firecracker treats a guest reboot as VM exit.
        let _ = nix::sys::reboot::reboot(nix::sys::reboot::RebootMode::RB_AUTOBOOT);
    }
    ExitCode::SUCCESS
}
