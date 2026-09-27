//! A small bounded cache with per-entry expiry, used for policies, secrets and
//! interception leaf certificates.
//!
//! Each entry gets its own deadline on insert, so positive and negative
//! results can live for different times. When the cache is full, expired
//! entries are dropped first, then the entry closest to its deadline. That
//! scan is linear, which is fine for the few thousand entries these caches
//! hold and keeps the structure obviously correct.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

pub struct TtlCache<K, V> {
    capacity: usize,
    entries: Mutex<HashMap<K, (Instant, V)>>,
}

impl<K: Eq + Hash + Clone, V: Clone> TtlCache<K, V> {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn get(&self, key: &K) -> Option<V> {
        self.get_at(key, Instant::now())
    }

    pub fn get_at(&self, key: &K, now: Instant) -> Option<V> {
        let mut entries = self.lock();
        match entries.get(key) {
            Some((deadline, value)) if now < *deadline => Some(value.clone()),
            Some(_) => {
                entries.remove(key);
                None
            }
            None => None,
        }
    }

    pub fn insert(&self, key: K, value: V, ttl: Duration) {
        let now = Instant::now();
        self.insert_at(key, value, now + ttl, now);
    }

    pub fn insert_at(&self, key: K, value: V, deadline: Instant, now: Instant) {
        let mut entries = self.lock();
        if !entries.contains_key(&key) && entries.len() >= self.capacity {
            entries.retain(|_, (d, _)| *d > now);
            if entries.len() >= self.capacity {
                let oldest = entries
                    .iter()
                    .min_by_key(|(_, (d, _))| *d)
                    .map(|(k, _)| k.clone());
                if let Some(oldest) = oldest {
                    entries.remove(&oldest);
                }
            }
        }
        entries.insert(key, (deadline, value));
    }

    pub fn remove(&self, key: &K) {
        self.lock().remove(key);
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<K, (Instant, V)>> {
        // A panic while holding the lock cannot leave the map inconsistent.
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_expire_at_their_own_deadline() {
        let cache = TtlCache::new(10);
        let t0 = Instant::now();
        cache.insert_at("pos", 1, t0 + Duration::from_secs(30), t0);
        cache.insert_at("neg", 2, t0 + Duration::from_secs(5), t0);
        let t = t0 + Duration::from_secs(6);
        assert_eq!(cache.get_at(&"pos", t), Some(1));
        assert_eq!(cache.get_at(&"neg", t), None);
        assert_eq!(cache.len(), 1, "expired entries are dropped on read");
        assert_eq!(cache.get_at(&"pos", t0 + Duration::from_secs(30)), None);
    }

    #[test]
    fn stays_bounded_and_evicts_expired_then_soonest_to_expire() {
        let cache = TtlCache::new(3);
        let t0 = Instant::now();
        let s = Duration::from_secs;
        cache.insert_at(1, "a", t0 + s(1), t0);
        cache.insert_at(2, "b", t0 + s(100), t0);
        cache.insert_at(3, "c", t0 + s(50), t0);
        // Key 1 has expired by t0+2s, so it goes first.
        cache.insert_at(4, "d", t0 + s(200), t0 + s(2));
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.get_at(&1, t0 + s(2)), None);
        // Nothing has expired; key 3 is closest to its deadline.
        cache.insert_at(5, "e", t0 + s(300), t0 + s(3));
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.get_at(&3, t0 + s(3)), None);
        assert_eq!(cache.get_at(&2, t0 + s(3)), Some("b"));
        // Replacing an existing key never evicts another.
        cache.insert_at(2, "b2", t0 + s(100), t0 + s(3));
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.get_at(&4, t0 + s(3)), Some("d"));
        cache.remove(&4);
        assert_eq!(cache.get_at(&4, t0 + s(3)), None);
    }
}
