//! Retries of conditional writes that a server answered with a transient `5xx`. RustFS answers
//! `503 SlowDownRead` under lock contention, which is neither a failed condition nor a missing
//! capability. A transport failure is never retried here: it is "offline".

use std::time::Duration;

/// How often, and how patiently, a conditional write is retried after a `5xx`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    /// Total attempts, including the first. At least 1.
    pub attempts: u32,
    /// The delay before the first retry; each later retry doubles it, plus up to the same again in
    /// random jitter.
    pub base: Duration,
}

impl Default for Backoff {
    /// Four attempts, starting at 100 ms.
    fn default() -> Self {
        Backoff {
            attempts: 4,
            base: Duration::from_millis(100),
        }
    }
}

/// Whether a status is a transient server error worth retrying. `501 NotImplemented` is a
/// missing capability, not a transient error.
pub(crate) fn is_transient(status: u16) -> bool {
    (500..600).contains(&status) && status != 501
}

impl Backoff {
    /// The delay before retry `n` (0-based).
    fn delay(&self, n: u32) -> Duration {
        let step = self.base.saturating_mul(1 << n.min(16));
        let mut r = [0u8; 2];
        let jitter = if getrandom::fill(&mut r).is_ok() {
            step.mul_f64(f64::from(u16::from_le_bytes(r)) / f64::from(u16::MAX))
        } else {
            Duration::ZERO
        };
        step + jitter
    }

    /// Runs `op` until it returns a result that `transient` rejects or the attempts run out, and
    /// returns the last result.
    pub(crate) fn run<T>(&self, mut op: impl FnMut() -> T, transient: impl Fn(&T) -> bool) -> T {
        let mut n = 0;
        loop {
            let out = op();
            n += 1;
            if n >= self.attempts.max(1) || !transient(&out) {
                return out;
            }
            std::thread::sleep(self.delay(n - 1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_statuses() {
        assert!(is_transient(500));
        assert!(is_transient(503));
        assert!(!is_transient(501));
        assert!(!is_transient(412));
        assert!(!is_transient(403));
    }

    #[test]
    fn retries_until_settled_or_exhausted() {
        let b = Backoff {
            attempts: 4,
            base: Duration::ZERO,
        };
        let mut calls = 0;
        let out = b.run(
            || {
                calls += 1;
                if calls < 3 { 503 } else { 200 }
            },
            |s| is_transient(*s),
        );
        assert_eq!((out, calls), (200, 3));
        let mut calls = 0;
        let out = b.run(
            || {
                calls += 1;
                503
            },
            |s| is_transient(*s),
        );
        assert_eq!((out, calls), (503, 4));
    }

    #[test]
    fn delays_grow() {
        let b = Backoff {
            attempts: 4,
            base: Duration::from_millis(100),
        };
        for n in 0..3 {
            let d = b.delay(n);
            let step = Duration::from_millis(100 << n);
            assert!(d >= step && d <= step * 2, "{n}: {d:?}");
        }
    }
}
