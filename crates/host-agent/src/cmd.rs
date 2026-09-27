//! Runs the privileged commands (`ip`, `iptables`, `mount`...) that set up
//! sandboxes. Plans are built as data first so tests can check the exact
//! commands without root, and so operators can read what the agent does.

use std::fmt;
use std::process::Stdio;
#[cfg(test)]
use std::sync::Mutex;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// One command to run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cmd {
    pub program: String,
    pub args: Vec<String>,
    /// Written to the command's standard input.
    pub stdin: Option<String>,
    /// Failure is expected and ignored (idempotent cleanup, `-C` probes).
    pub allow_failure: bool,
}

impl Cmd {
    pub fn new<I, S>(program: &str, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            program: program.to_owned(),
            args: args.into_iter().map(Into::into).collect(),
            stdin: None,
            allow_failure: false,
        }
    }

    pub fn stdin(mut self, input: String) -> Self {
        self.stdin = Some(input);
        self
    }

    pub fn allow_failure(mut self) -> Self {
        self.allow_failure = true;
        self
    }
}

impl fmt::Display for Cmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.program)?;
        for a in &self.args {
            write!(f, " {a}")?;
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("`{cmd}` failed ({status}): {stderr}")]
pub struct CmdError {
    pub cmd: String,
    pub status: String,
    pub stderr: String,
}

/// Executes commands. The real runner shells out; the recorder captures
/// commands for tests.
pub trait Runner: Send + Sync {
    fn run(&self, cmd: &Cmd) -> impl std::future::Future<Output = Result<(), CmdError>> + Send;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemRunner;

impl Runner for SystemRunner {
    async fn run(&self, cmd: &Cmd) -> Result<(), CmdError> {
        let mut child = Command::new(&cmd.program)
            .args(&cmd.args)
            .stdin(if cmd.stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| CmdError {
                cmd: cmd.to_string(),
                status: "spawn failed".into(),
                stderr: e.to_string(),
            })?;
        if let (Some(input), Some(mut stdin)) = (&cmd.stdin, child.stdin.take()) {
            let _ = stdin.write_all(input.as_bytes()).await;
            drop(stdin);
        }
        let out = child.wait_with_output().await.map_err(|e| CmdError {
            cmd: cmd.to_string(),
            status: "wait failed".into(),
            stderr: e.to_string(),
        })?;
        if out.status.success() || cmd.allow_failure {
            if !out.status.success() {
                tracing::debug!(cmd = %cmd, status = %out.status, "command failed (ignored)");
            }
            return Ok(());
        }
        Err(CmdError {
            cmd: cmd.to_string(),
            status: out.status.to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
        })
    }
}

/// Runs a plan in order, stopping at the first failure.
pub async fn run_all<R: Runner>(runner: &R, plan: &[Cmd]) -> Result<(), CmdError> {
    for cmd in plan {
        runner.run(cmd).await?;
    }
    Ok(())
}

/// Records commands instead of running them.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct RecordingRunner {
    pub commands: Mutex<Vec<Cmd>>,
}

#[cfg(test)]
impl Runner for RecordingRunner {
    async fn run(&self, cmd: &Cmd) -> Result<(), CmdError> {
        self.commands.lock().expect("poisoned").push(cmd.clone());
        Ok(())
    }
}
