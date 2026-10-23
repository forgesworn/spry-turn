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
}
