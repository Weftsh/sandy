//! Connection limits: one global cap on open connections and one per sandbox,
//! so a single sandbox cannot exhaust the gateway's sockets.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Debug)]
pub struct Limits {
    global: Arc<Semaphore>,
    global_max: usize,
    per_sandbox_max: usize,
    per_sandbox: Mutex<HashMap<String, usize>>,
}

impl Limits {
    pub fn new(global_max: usize, per_sandbox_max: usize) -> Arc<Self> {
        Arc::new(Self {
            global: Arc::new(Semaphore::new(global_max)),
            global_max,
            per_sandbox_max,
            per_sandbox: Mutex::new(HashMap::new()),
        })
    }

    pub fn try_global(&self) -> Option<OwnedSemaphorePermit> {
        self.global.clone().try_acquire_owned().ok()
    }

    /// Open connections across all sandboxes.
    pub fn open_connections(&self) -> usize {
        self.global_max - self.global.available_permits()
    }

    pub fn try_sandbox(self: &Arc<Self>, sandbox_id: &str) -> Option<SandboxPermit> {
        let mut counts = self.per_sandbox.lock().unwrap_or_else(|e| e.into_inner());
        let count = counts.entry(sandbox_id.to_owned()).or_insert(0);
        if *count >= self.per_sandbox_max {
            return None;
        }
        *count += 1;
        Some(SandboxPermit {
            limits: self.clone(),
            sandbox_id: sandbox_id.to_owned(),
        })
    }

    fn release(&self, sandbox_id: &str) {
        let mut counts = self.per_sandbox.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = counts.get_mut(sandbox_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(sandbox_id);
            }
        }
    }

    #[cfg(test)]
    fn tracked_sandboxes(&self) -> usize {
        self.per_sandbox.lock().unwrap().len()
    }
}

/// Held for the life of one sandbox connection.
#[derive(Debug)]
pub struct SandboxPermit {
    limits: Arc<Limits>,
    sandbox_id: String,
}

impl Drop for SandboxPermit {
    fn drop(&mut self) {
        self.limits.release(&self.sandbox_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_sandbox_limit_is_independent_and_released_on_drop() {
        let limits = Limits::new(10, 2);
        let a1 = limits.try_sandbox("a").unwrap();
        let _a2 = limits.try_sandbox("a").unwrap();
        assert!(limits.try_sandbox("a").is_none());
        let b1 = limits.try_sandbox("b").unwrap();
        drop(a1);
        assert!(limits.try_sandbox("a").is_some());
        drop(b1);
        assert_eq!(
            limits.tracked_sandboxes(),
            1,
            "idle sandboxes are forgotten"
        );
    }

    #[test]
    fn global_limit() {
        let limits = Limits::new(1, 5);
        let p = limits.try_global().unwrap();
        assert!(limits.try_global().is_none());
        assert_eq!(limits.open_connections(), 1);
        drop(p);
        assert_eq!(limits.open_connections(), 0);
    }
}
