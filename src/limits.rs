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

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.updated);
        let added = (elapsed.as_nanos() * u128::from(self.per_second) / 1_000_000_000)
            .min(u128::from(u64::MAX)) as u64;
        if added != 0 {
            self.available = self.available.saturating_add(added).min(self.capacity);
            self.updated = now;
        }
    }

    pub fn take(&mut self, amount: usize, now: Instant) -> bool {
        self.take_above(amount, 0, now)
    }

    /// Takes `amount` only if at least `reserve` tokens would remain, so the
    /// reserve is left for callers that draw with `take`.
    pub fn take_above(&mut self, amount: usize, reserve: u64, now: Instant) -> bool {
        self.refill(now);
        let amount = amount as u64;
        if self.available < amount.saturating_add(reserve) {
            return false;
        }
        self.available -= amount;
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

/// A fixed table of per-source allowances. Each slot holds one number, the
/// theoretical arrival time of a generic cell rate algorithm, so a source
/// may make `burst` requests at once and then `per_second` a second. There
/// are no keys and nothing is evicted or grown: sources whose hashes share a
/// slot share its allowance, and a zeroed slot is a full allowance. Time is
/// supplied by the caller as nanoseconds since any fixed origin.
#[derive(Debug)]
pub struct SourceTable {
    arrival: Vec<u64>,
    interval: u64,
    tolerance: u64,
}

impl SourceTable {
    /// `slots` must be a power of two, and `per_second` and `burst` at least 1.
    pub fn new(slots: usize, per_second: u64, burst: u64) -> Self {
        assert!(slots.is_power_of_two() && per_second > 0 && burst > 0);
        let interval = 1_000_000_000 / per_second;
        Self {
            arrival: vec![0; slots],
            interval,
            tolerance: interval.saturating_mul(burst - 1),
        }
    }

    /// The slot for a hash of a source key.
    pub fn slot(&self, hash: u64) -> usize {
        hash as usize & (self.arrival.len() - 1)
    }

    /// Spends one request from `slot` at `at`. On success returns the slot's
    /// previous value, which `restore` takes if a later limit refuses.
    pub fn take(&mut self, slot: usize, at: u64) -> Option<u64> {
        let previous = self.arrival[slot];
        let arrival = previous.max(at);
        if arrival - at > self.tolerance {
            return None;
        }
        self.arrival[slot] = arrival.saturating_add(self.interval);
        Some(previous)
    }

    /// Undoes the `take` that returned `previous`.
    pub fn restore(&mut self, slot: usize, previous: u64) {
        self.arrival[slot] = previous;
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

    #[test]
    fn take_above_keeps_the_reserve() {
        let now = Instant::now();
        let mut bucket = Bucket::new(100, 10, now);
        let mut above = 0;
        while bucket.take_above(1, 4, now) {
            above += 1;
        }
        assert_eq!(above, 6);
        // The reserve is still there for plain draws, and only they spend it.
        assert!(!bucket.take_above(1, 4, now));
        for _ in 0..4 {
            assert!(bucket.take(1, now));
        }
        assert!(!bucket.take(1, now));
        // Refill is counted before the reserve is applied.
        assert!(!bucket.take_above(1, 4, now + Duration::from_millis(40)));
        assert!(bucket.take_above(1, 4, now + Duration::from_millis(50)));
    }

    #[test]
    fn source_table_admits_its_burst_then_its_rate() {
        let mut table = SourceTable::new(8, 5, 20);
        let start = 1_000_000_000;
        let admitted = (0..100).filter(|_| table.take(3, start).is_some()).count();
        assert_eq!(admitted, 20);
        // Another slot is untouched.
        assert!(table.take(4, start).is_some());
        // 5 a second is one every 200 ms.
        assert!(table.take(3, start + 199_999_999).is_none());
        assert!(table.take(3, start + 200_000_000).is_some());
        assert!(table.take(3, start + 200_000_000).is_none());
        // A long pause refills to the burst and no further.
        let later = start + 60_000_000_000;
        assert_eq!(
            (0..100).filter(|_| table.take(3, later).is_some()).count(),
            20
        );
        // Slots are chosen by masking, so any hash is in range.
        assert!(table.slot(u64::MAX) < 8);
    }

    #[test]
    fn source_table_restore_undoes_a_take() {
        let mut table = SourceTable::new(4, 1, 2);
        let start = 5_000_000_000;
        let first = table.take(1, start).unwrap();
        assert_eq!(first, 0);
        let second = table.take(1, start).unwrap();
        assert!(table.take(1, start).is_none());
        table.restore(1, second);
        assert!(table.take(1, start).is_some());
        assert!(table.take(1, start).is_none());
        table.restore(1, first);
        assert!(table.take(1, start).is_some());
        assert!(table.take(1, start).is_some());
        assert!(table.take(1, start).is_none());
    }
}
