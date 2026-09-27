//! Which sandbox occupies which network slot, shared by the manager, the
//! egress forwarder and the guest resolver.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};

use weft_netpolicy::CompiledPolicy;

use crate::net::{NetConfig, Slot};

#[derive(Clone, Debug)]
pub struct SlotEntry {
    pub sandbox_id: String,
    pub policy: Arc<CompiledPolicy>,
}

/// Slot index to occupant, plus the free list.
pub struct SlotTable {
    net: NetConfig,
    inner: RwLock<Inner>,
}

struct Inner {
    occupants: HashMap<u32, SlotEntry>,
    reserved: Vec<bool>,
    limit: u32,
}

impl SlotTable {
    pub fn new(net: NetConfig, limit: u32) -> Self {
        let limit = limit.min(net.max_slots());
        Self {
            net,
            inner: RwLock::new(Inner {
                occupants: HashMap::new(),
                reserved: vec![false; limit as usize],
                limit,
            }),
        }
    }

    pub fn net(&self) -> &NetConfig {
        &self.net
    }

    /// Reserves the lowest free slot.
    pub fn reserve(&self) -> Option<Slot> {
        let mut inner = self.inner.write().expect("poisoned");
        let limit = inner.limit as usize;
        let index = inner.reserved.iter().take(limit).position(|r| !r)?;
        inner.reserved[index] = true;
        Slot::new(&self.net, index as u32)
    }

    /// Marks a slot as used by a sandbox, making it visible to the forwarder
    /// and resolver.
    pub fn occupy(&self, index: u32, entry: SlotEntry) {
        self.inner
            .write()
            .expect("poisoned")
            .occupants
            .insert(index, entry);
    }

    pub fn set_policy(&self, index: u32, policy: Arc<CompiledPolicy>) {
        if let Some(e) = self
            .inner
            .write()
            .expect("poisoned")
            .occupants
            .get_mut(&index)
        {
            e.policy = policy;
        }
    }

    /// Stops routing a slot's traffic and DNS to its sandbox. The slot stays
    /// reserved until [`SlotTable::release`], after its network is torn down.
    pub fn vacate(&self, index: u32) {
        self.inner
            .write()
            .expect("poisoned")
            .occupants
            .remove(&index);
    }

    /// Returns a slot to the free pool. Call only once its network is gone,
    /// or the next sandbox could be set up while the old one is torn down.
    pub fn release(&self, index: u32) {
        let mut inner = self.inner.write().expect("poisoned");
        inner.occupants.remove(&index);
        if let Some(r) = inner.reserved.get_mut(index as usize) {
            *r = false;
        }
    }

    /// Looks up the sandbox behind a slot-namespace source address.
    pub fn by_source(&self, ip: Ipv4Addr) -> Option<SlotEntry> {
        let index = Slot::index_for_ns_ip(&self.net, ip)?;
        self.inner
            .read()
            .expect("poisoned")
            .occupants
            .get(&index)
            .cloned()
    }

    #[cfg(test)]
    pub fn in_use(&self) -> u32 {
        self.inner
            .read()
            .expect("poisoned")
            .reserved
            .iter()
            .filter(|r| **r)
            .count() as u32
    }

    pub fn limit(&self) -> u32 {
        self.inner.read().expect("poisoned").limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserves_occupies_and_releases() {
        let net = NetConfig {
            pool: "10.200.0.0/16".parse().unwrap(),
            dns_port: 1,
            egress_port: 2,
        };
        let t = SlotTable::new(net, 2);
        let a = t.reserve().unwrap();
        let b = t.reserve().unwrap();
        assert!(t.reserve().is_none(), "limit reached");
        t.occupy(
            b.index,
            SlotEntry {
                sandbox_id: "b".into(),
                policy: Arc::new(CompiledPolicy::deny_all()),
            },
        );
        assert_eq!(t.by_source(b.ns_ip).unwrap().sandbox_id, "b");
        assert!(
            t.by_source(a.ns_ip).is_none(),
            "reserved but not yet occupied"
        );
        assert!(t.by_source(b.host_ip).is_none());
        t.release(a.index);
        assert_eq!(t.reserve().unwrap().index, a.index);
        assert_eq!(t.in_use(), 2);
    }
}
