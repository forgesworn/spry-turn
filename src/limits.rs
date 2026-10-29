//! Fixed-cost admission and packet accounting. Time comes from the caller.

use std::time::{Duration, Instant};

/// A bounded token bucket. Refill happens on demand, without a timer task.
#[derive(Debug)]
pub struct Bucket {
    available: u64,
    capacity: u64,
    per_second: u64,
    updated: Instant,
}

impl Bucket {
    pub fn new(per_second: u64, burst: u64, now: Instant) -> Self {
        Self {
            available: burst,
            capacity: burst,
            per_second,
            updated: now,
        }
    }

    pub fn take(&mut self, amount: usize, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.updated);
        let added = (elapsed.as_nanos() * u128::from(self.per_second) / 1_000_000_000)
            .min(u128::from(u64::MAX)) as u64;
        if added != 0 {
            self.available = self.available.saturating_add(added).min(self.capacity);
            self.updated = now;
        }
        if amount as u64 > self.available {
            return false;
        }
        self.available -= amount as u64;
        true
    }

    /// Return tokens taken for a packet that a second, shared limit then
    /// refused, so that refusal does not also spend this bucket.
    pub fn give_back(&mut self, amount: usize) {
        self.available = self
            .available
            .saturating_add(amount as u64)
            .min(self.capacity);
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub forwarded_packets: u64,
    pub forwarded_bytes: u64,
    pub dropped_packets: u64,
}

pub const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn limits_bursts_and_refills_without_overflow() {
        let now = Instant::now();
        let mut bucket = Bucket::new(100, 200, now);
        assert!(bucket.take(200, now));
        assert!(!bucket.take(1, now));
        assert!(bucket.take(50, now + Duration::from_millis(500)));
        assert!(!bucket.take(1, now + Duration::from_millis(500)));
        assert!(bucket.take(200, now + Duration::from_secs(100)));
        assert!(!bucket.take(201, now + Duration::from_secs(1000)));
    }

    #[test]
    fn returned_tokens_never_exceed_the_burst() {
        let now = Instant::now();
        let mut bucket = Bucket::new(100, 200, now);
        assert!(bucket.take(150, now));
        bucket.give_back(150);
        assert!(bucket.take(200, now));
        bucket.give_back(usize::MAX);
        assert!(bucket.take(200, now));
        assert!(!bucket.take(1, now));
    }
}
