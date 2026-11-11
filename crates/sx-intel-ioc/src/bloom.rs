//! Sharded bloom filter for high-throughput indicator-of-compromise lookup.
//!
//! ## Design
//!
//! A bloom filter is a probabilistic set: `contains(x)` may return false
//! positives but never false negatives. For a target capacity `n` and false
//! positive rate `p`, the optimal parameters are:
//!
//! ```text
//! m = ceil(-n * ln(p) / (ln 2)^2)   bits
//! k = round((m / n) * ln 2)          hash functions
//! ```
//!
//! With `n = 10_000_000` and `p = 0.01`, this yields `m ≈ 95.85 M` bits and
//! `k = 7` hash probes.
//!
//! To support high-throughput concurrent inserts/queries, the structure is
//! sharded into 16 independent sub-filters, one `Mutex<BloomFilter>` per
//! shard. The shard index is derived from `hash(key) % 16`. Each shard sizes
//! itself for `n / 16` expected items while preserving the configured FPR.
//!
//! Hashing uses [`ahash::RandomState`] seeded once per [`ShardedBloomFilter`]
//! (so a single process produces stable hashes across all shards) and the
//! Kirsch-Mitzenmacher double-hashing trick to derive `k` probes from two
//! 64-bit base hashes.
//!
//! ## Concurrency
//!
//! Each shard is wrapped in a [`std::sync::Mutex`]; concurrent traffic
//! distributed uniformly across shards yields 16x lock parallelism for
//! collision-free inserts/queries. Critical sections are tight bit-twiddles,
//! so contention should stay low even under load.

use std::hash::Hash;
use std::sync::Mutex;

use ahash::RandomState;

/// Number of independent shards.
///
/// Picked to balance lock contention vs memory overhead; 16 is enough
/// parallelism for typical IOC ingestion workloads while keeping per-shard
/// size large enough for stable hashing behaviour.
pub const SHARD_COUNT: usize = 16;

/// Default total expected capacity (sum across all shards).
pub const DEFAULT_CAPACITY: usize = 10_000_000;

/// Default target false-positive rate.
pub const DEFAULT_FPR: f64 = 0.01;

/// Parameters describing a single bloom-filter shard's geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BloomParams {
    /// Bit count for a single shard.
    pub bits_per_shard: usize,
    /// Number of hash probes per insertion/lookup.
    pub hash_count: u32,
    /// Expected items per shard.
    pub capacity_per_shard: usize,
}

impl BloomParams {
    /// Derive shard geometry from a total expected capacity and target FPR.
    ///
    /// `total_capacity` is divided evenly across [`SHARD_COUNT`] shards.
    /// Returns `None` if either input is non-finite, FPR is outside `(0, 1)`,
    /// or capacity is zero.
    #[must_use]
    pub fn from_capacity_and_fpr(total_capacity: usize, fpr: f64) -> Option<Self> {
        if total_capacity == 0 || !fpr.is_finite() || fpr <= 0.0 || fpr >= 1.0 {
            return None;
        }
        // Per-shard capacity; never zero (we'd have returned above otherwise).
        let per_shard = total_capacity.div_ceil(SHARD_COUNT);
        // Bits: m = -n * ln(p) / (ln 2)^2
        #[allow(clippy::cast_precision_loss)]
        let n = per_shard as f64;
        let ln2 = std::f64::consts::LN_2;
        let m_float = -(n * fpr.ln()) / (ln2 * ln2);
        if !m_float.is_finite() || m_float <= 0.0 {
            return None;
        }
        // Round up so we never under-allocate.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let bits = m_float.ceil() as usize;
        // Round bits to next multiple of 64 so the bit-vector aligns to u64.
        let bits = bits.div_ceil(64).saturating_mul(64).max(64);
        // Hash count: k = (m / n) * ln 2, rounded, min 1.
        #[allow(clippy::cast_precision_loss)]
        let k_float = (bits as f64 / n) * ln2;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let k = k_float.round().max(1.0) as u32;
        Some(Self {
            bits_per_shard: bits,
            hash_count: k,
            capacity_per_shard: per_shard,
        })
    }
}

/// A single bloom-filter shard, backed by a packed `Vec<u64>` bit vector.
#[derive(Debug)]
struct BloomShard {
    bits: Vec<u64>,
    bit_len: usize,
    hash_count: u32,
}

impl BloomShard {
    fn new(params: BloomParams) -> Self {
        // bit_len is always a multiple of 64 (BloomParams enforces this).
        let words = params.bits_per_shard >> 6;
        Self {
            bits: vec![0u64; words],
            bit_len: params.bits_per_shard,
            hash_count: params.hash_count,
        }
    }

    /// Set `k` bits derived from the two base hashes via Kirsch-Mitzenmacher.
    fn insert(&mut self, h1: u64, h2: u64) {
        for i in 0..self.hash_count {
            let bit_index = combine_hash(h1, h2, i) % (self.bit_len as u64);
            #[allow(clippy::cast_possible_truncation)]
            let bit_index = bit_index as usize;
            let word = bit_index >> 6;
            let bit = bit_index & 0x3F;
            if let Some(slot) = self.bits.get_mut(word) {
                *slot |= 1u64 << bit;
            }
        }
    }

    /// Check whether all `k` probes are set.
    fn contains(&self, h1: u64, h2: u64) -> bool {
        for i in 0..self.hash_count {
            let bit_index = combine_hash(h1, h2, i) % (self.bit_len as u64);
            #[allow(clippy::cast_possible_truncation)]
            let bit_index = bit_index as usize;
            let word = bit_index >> 6;
            let bit = bit_index & 0x3F;
            let Some(slot) = self.bits.get(word) else {
                return false;
            };
            if (*slot >> bit) & 1 == 0 {
                return false;
            }
        }
        true
    }
}

/// Kirsch-Mitzenmacher combiner: `g_i(x) = h1 + i * h2`.
///
/// All math is wrapping so we get well-defined output for any `i` without
/// overflow panics under `overflow-checks = true`.
#[inline]
fn combine_hash(h1: u64, h2: u64, i: u32) -> u64 {
    h1.wrapping_add(u64::from(i).wrapping_mul(h2))
}

/// Sharded bloom filter with 16 independent shards.
///
/// Each call to [`Self::insert`] / [`Self::contains`] picks a shard based on
/// the top 8 bits of the primary hash, then takes that shard's mutex.
#[derive(Debug)]
pub struct ShardedBloomFilter {
    shards: [Mutex<BloomShard>; SHARD_COUNT],
    primary: RandomState,
    secondary: RandomState,
    params: BloomParams,
}

impl ShardedBloomFilter {
    /// Build a filter sized for the default `(capacity, fpr)` pair.
    #[must_use]
    pub fn with_defaults() -> Self {
        // Defaults are valid; falling back to a 1-bit filter would only happen
        // if the constants were misconfigured at compile time.
        let params = BloomParams::from_capacity_and_fpr(DEFAULT_CAPACITY, DEFAULT_FPR).unwrap_or(
            BloomParams {
                bits_per_shard: 64,
                hash_count: 1,
                capacity_per_shard: 1,
            },
        );
        Self::with_params(params)
    }

    /// Build a filter with explicit parameters.
    #[must_use]
    pub fn with_params(params: BloomParams) -> Self {
        // Two independent seeds so the "double hashing" combiner produces
        // hash functions that are statistically independent.
        let primary = RandomState::with_seeds(
            0x5165_4E54_494E_454C,
            0x582D_494F_432D_4831,
            0xA5A5_A5A5_5A5A_5A5A,
            0xDEAD_BEEF_CAFE_BABE,
        );
        let secondary = RandomState::with_seeds(
            0x1234_5678_9ABC_DEF0,
            0x0FED_CBA9_8765_4321,
            0xF00D_F00D_F00D_F00D,
            0xBEEF_BEEF_BEEF_BEEF,
        );
        let shards = std::array::from_fn(|_| Mutex::new(BloomShard::new(params)));
        Self {
            shards,
            primary,
            secondary,
            params,
        }
    }

    /// Build a filter from a total expected capacity and target FPR. Returns
    /// `None` for invalid inputs (zero capacity, FPR outside `(0, 1)`, or
    /// non-finite FPR).
    #[must_use]
    pub fn try_new(total_capacity: usize, fpr: f64) -> Option<Self> {
        BloomParams::from_capacity_and_fpr(total_capacity, fpr).map(Self::with_params)
    }

    /// Geometry of every shard.
    #[must_use]
    pub const fn params(&self) -> BloomParams {
        self.params
    }

    /// Insert a key into the filter.
    ///
    /// If a shard's mutex is poisoned (a panic occurred while holding it), the
    /// insertion is silently skipped — the bloom filter is a hint, and the
    /// next caller will still observe the partial state without surfacing a
    /// panic to unrelated tenants.
    pub fn insert<K: Hash + ?Sized>(&self, key: &K) {
        let (h1, h2) = self.hash_pair(key);
        let shard_idx = Self::shard_index(h1);
        if let Some(shard) = self.shards.get(shard_idx) {
            if let Ok(mut guard) = shard.lock() {
                guard.insert(h1, h2);
            }
        }
    }

    /// Probe the filter.
    ///
    /// Returns `false` if no shard contains evidence of the key. Returns
    /// `true` if the corresponding shard's `k` probes all light up — which
    /// means the key was inserted *or* this is a false positive (bounded by
    /// the configured FPR).
    pub fn contains<K: Hash + ?Sized>(&self, key: &K) -> bool {
        let (h1, h2) = self.hash_pair(key);
        let shard_idx = Self::shard_index(h1);
        let Some(shard) = self.shards.get(shard_idx) else {
            return false;
        };
        let Ok(guard) = shard.lock() else {
            // Poisoned mutex: best-effort answer is "unknown" — return false
            // rather than panic; callers treat false negatives as the caller's
            // responsibility (verify upstream).
            return false;
        };
        guard.contains(h1, h2)
    }

    fn hash_pair<K: Hash + ?Sized>(&self, key: &K) -> (u64, u64) {
        // `BuildHasher::hash_one` needs `T: Hash` directly; we pass `&K`
        // because `&K: Hash` even when `K: ?Sized`.
        let h1 = self.primary.hash_one(key);
        let h2 = self.secondary.hash_one(key);
        (h1, h2)
    }

    const fn shard_index(h1: u64) -> usize {
        // Top 8 bits avoid colliding with the bits we'd reuse for in-shard
        // indexing; SHARD_COUNT is a small power of two so the modulo
        // compiles to a mask.
        ((h1 >> 56) as usize) % SHARD_COUNT
    }
}

impl Default for ShardedBloomFilter {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn params_for_defaults_yield_expected_geometry() {
        let p = BloomParams::from_capacity_and_fpr(DEFAULT_CAPACITY, DEFAULT_FPR).unwrap();
        // Per-shard: 10M / 16 = 625_000 items, m ≈ 5_990_588 bits, rounded to
        // next 64-bit word boundary. k = round((m/n) * ln2) = 7.
        assert_eq!(p.capacity_per_shard, 625_000);
        assert!(p.bits_per_shard >= 5_990_000);
        assert_eq!(p.hash_count, 7);
    }

    #[test]
    fn params_reject_invalid_inputs() {
        assert!(BloomParams::from_capacity_and_fpr(0, 0.01).is_none());
        assert!(BloomParams::from_capacity_and_fpr(100, 0.0).is_none());
        assert!(BloomParams::from_capacity_and_fpr(100, 1.0).is_none());
        assert!(BloomParams::from_capacity_and_fpr(100, f64::NAN).is_none());
    }

    #[test]
    fn insert_and_contains_round_trip() {
        let filter = ShardedBloomFilter::try_new(100_000, 0.01).unwrap();
        let keys = [
            "evil.example.com",
            "203.0.113.66",
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "phish.invalid",
        ];
        for k in &keys {
            filter.insert(*k);
        }
        for k in &keys {
            assert!(filter.contains(*k), "expected hit for {k}");
        }
    }

    #[test]
    fn contains_returns_false_for_unseen() {
        let filter = ShardedBloomFilter::try_new(100_000, 0.01).unwrap();
        filter.insert("known.example.com");
        // None of these were inserted; expect overwhelmingly false. We allow
        // false positives at the configured rate, so a single negative draw is
        // sufficient evidence the API distinguishes the two states.
        let unseen = [
            "totally.unseen.1",
            "totally.unseen.2",
            "totally.unseen.3",
            "totally.unseen.4",
        ];
        let hits = unseen.iter().filter(|k| filter.contains(**k)).count();
        assert!(hits < unseen.len(), "expected at least one miss");
    }

    #[test]
    fn sharding_uses_all_16_shards_uniformly() {
        let filter = ShardedBloomFilter::try_new(100_000, 0.01).unwrap();
        let mut hits_per_shard = [0u32; SHARD_COUNT];
        for i in 0..1000u32 {
            let key = format!("ioc-{i:06}");
            let (h1, _h2) = filter.hash_pair(&key);
            let idx = ShardedBloomFilter::shard_index(h1);
            if let Some(slot) = hits_per_shard.get_mut(idx) {
                *slot = slot.saturating_add(1);
            }
            filter.insert(&key);
        }
        for (i, count) in hits_per_shard.iter().enumerate() {
            assert!(
                *count > 0,
                "shard {i} got 0 inserts (distribution counts: {hits_per_shard:?})",
            );
        }
    }

    #[test]
    fn false_positive_rate_below_two_percent() {
        // Size for the workload we actually exercise: 10_000 inserts.
        let filter = ShardedBloomFilter::try_new(10_000, 0.01).unwrap();
        for i in 0..10_000u32 {
            filter.insert(&format!("in-{i:08}"));
        }
        // Disjoint query set — different prefix guarantees no overlap with
        // inserted keys.
        let mut false_positives = 0u32;
        for i in 0..10_000u32 {
            if filter.contains(&format!("out-{i:08}")) {
                false_positives = false_positives.saturating_add(1);
            }
        }
        let fpr = f64::from(false_positives) / 10_000.0;
        assert!(
            fpr < 0.02,
            "measured FPR {fpr:.4} exceeds 2% (false_positives={false_positives})",
        );
    }
}
