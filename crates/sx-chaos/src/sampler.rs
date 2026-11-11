//! Sampling abstractions — pluggable for deterministic testing.

use std::fmt;
use std::sync::Mutex;

use rand::rngs::ThreadRng;
use rand::Rng;

/// Pluggable random sampler.
///
/// Production uses [`ThreadRngSampler`] which delegates to
/// `rand::thread_rng()`. Tests substitute [`deterministic_sampler`] to
/// return a pre-canned sequence so assertions on fraction sampling are
/// stable.
pub trait Sampler: Send + Sync + fmt::Debug {
    /// Return a uniformly distributed value in `[0.0, 1.0)`.
    fn sample(&self) -> f64;
}

/// Thread-rng-backed sampler used in production.
#[derive(Debug, Default, Clone, Copy)]
pub struct ThreadRngSampler;

impl Sampler for ThreadRngSampler {
    fn sample(&self) -> f64 {
        let mut rng: ThreadRng = rand::thread_rng();
        rng.gen_range(0.0_f64..1.0_f64)
    }
}

/// Construct a deterministic sampler that yields the supplied values in
/// order, looping when exhausted. Intended for unit tests.
#[must_use]
pub fn deterministic_sampler(values: Vec<f64>) -> Box<dyn Sampler> {
    Box::new(DeterministicSampler {
        values,
        cursor: Mutex::new(0),
    })
}

struct DeterministicSampler {
    values: Vec<f64>,
    cursor: Mutex<usize>,
}

impl fmt::Debug for DeterministicSampler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeterministicSampler")
            .field("len", &self.values.len())
            .finish_non_exhaustive()
    }
}

impl Sampler for DeterministicSampler {
    fn sample(&self) -> f64 {
        if self.values.is_empty() {
            return 0.0;
        }
        let mut cur = match self.cursor.lock() {
            Ok(c) => c,
            Err(p) => p.into_inner(),
        };
        let v = self.values.get(*cur).copied().unwrap_or(0.0);
        *cur = (*cur + 1) % self.values.len();
        v
    }
}
