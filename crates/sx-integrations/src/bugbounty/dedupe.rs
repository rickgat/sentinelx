//! De-duplication of inbound bug-bounty reports against existing
//! `SentinelX` findings.
//!
//! The strategy is a TF-IDF + cosine-similarity fingerprint of
//! `title + "\n" + description`. We keep this dependency-free: a small
//! tokenizer, an in-process inverted index, and a cosine-similarity
//! comparator are enough at the volumes a bug-bounty webhook produces.
//!
//! ## Algorithm
//!
//! 1. Tokenise into lowercase alphanumeric tokens; drop tokens shorter
//!    than 3 characters (eliminates noise like `a`, `is`, `to`, …).
//! 2. Build a per-corpus document-frequency table.
//! 3. For each document, compute term frequencies, multiply by
//!    `idf = ln((N + 1) / (df + 1)) + 1` (smoothed IDF), and L2-normalise
//!    the resulting vector.
//! 4. Cosine similarity is the dot product of two L2-normalised vectors.
//!
//! ## Threshold
//!
//! Per the P3-010 spec, two findings are considered duplicates when
//! cosine ≥ [`DEDUP_THRESHOLD`] (0.85). The threshold is a runtime
//! constant on a strict-greater-or-equal check — callers can tune it
//! by passing a different value to [`Deduplicator::is_duplicate_with`].

use std::collections::HashMap;

/// Cosine similarity cutoff for declaring two findings duplicates.
pub const DEDUP_THRESHOLD: f64 = 0.85;

/// A pre-fingerprinted existing finding the deduper compares against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingFinding {
    /// Stable finding uuid the caller uses to identify the existing row.
    pub id: String,
    /// Short title (fingerprinted together with `description`).
    pub title: String,
    /// Long-form description (fingerprinted together with `title`).
    pub description: String,
}

/// Outcome of [`Deduplicator::is_duplicate`].
#[derive(Debug, Clone, PartialEq)]
pub enum DedupResult {
    /// No existing finding scored at or above the threshold.
    Unique,
    /// At least one existing finding matched; the carried tuple is the
    /// `(id, score)` of the **best** match.
    Duplicate {
        /// Id of the best-matching existing finding.
        existing_id: String,
        /// Cosine similarity score in `[0.0, 1.0]`.
        score: f64,
    },
}

impl DedupResult {
    /// Whether this outcome indicates a duplicate.
    #[must_use]
    pub const fn is_duplicate(&self) -> bool {
        matches!(self, Self::Duplicate { .. })
    }
}

/// Stateless de-duplicator. Builds a fresh TF-IDF index every call so
/// the caller does not have to track invalidation when findings are
/// added / removed.
#[derive(Debug, Default, Clone, Copy)]
pub struct Deduplicator;

impl Deduplicator {
    /// Construct a deduplicator.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Compare the candidate `title`+`description` against `existing` and
    /// return [`DedupResult::Duplicate`] when any existing finding scores
    /// at or above [`DEDUP_THRESHOLD`].
    #[must_use]
    pub fn is_duplicate(
        self,
        candidate_title: &str,
        candidate_description: &str,
        existing: &[ExistingFinding],
    ) -> DedupResult {
        self.is_duplicate_with(
            candidate_title,
            candidate_description,
            existing,
            DEDUP_THRESHOLD,
        )
    }

    /// Same as [`Self::is_duplicate`] but with a caller-supplied
    /// threshold (used by tests and tuning).
    #[must_use]
    #[allow(clippy::unused_self)]
    pub fn is_duplicate_with(
        self,
        candidate_title: &str,
        candidate_description: &str,
        existing: &[ExistingFinding],
        threshold: f64,
    ) -> DedupResult {
        if existing.is_empty() {
            return DedupResult::Unique;
        }

        // Build a corpus: index 0 is the candidate, index 1..=N are the
        // existing findings. Document frequency is computed across all
        // documents.
        let candidate_text = combine(candidate_title, candidate_description);
        let mut documents: Vec<Vec<String>> = Vec::with_capacity(existing.len() + 1);
        documents.push(tokenize(&candidate_text));
        for f in existing {
            documents.push(tokenize(&combine(&f.title, &f.description)));
        }

        let df = document_frequencies(&documents);
        let n_docs = documents.len();

        let vectors: Vec<HashMap<String, f64>> = documents
            .into_iter()
            .map(|tokens| tfidf_vector(&tokens, &df, n_docs))
            .collect();

        // First vector is the candidate. The remaining vectors line up
        // with `existing` by index.
        let Some(candidate_vec) = vectors.first() else {
            return DedupResult::Unique;
        };
        if candidate_vec.is_empty() {
            // Candidate has no usable tokens — fall back to a literal
            // title-equality probe so very short, repeated titles still
            // dedupe.
            for f in existing {
                if eq_ignore_case(&f.title, candidate_title)
                    && eq_ignore_case(&f.description, candidate_description)
                {
                    return DedupResult::Duplicate {
                        existing_id: f.id.clone(),
                        score: 1.0,
                    };
                }
            }
            return DedupResult::Unique;
        }

        let mut best: Option<(String, f64)> = None;
        for (idx, existing_finding) in existing.iter().enumerate() {
            // `vectors` has the candidate at index 0; existing findings
            // start at index 1.
            let Some(other_vec) = vectors.get(idx + 1) else {
                continue;
            };
            let score = cosine(candidate_vec, other_vec);
            if score >= threshold && best.as_ref().is_none_or(|(_, b)| score > *b) {
                best = Some((existing_finding.id.clone(), score));
            }
        }

        match best {
            Some((existing_id, score)) => DedupResult::Duplicate { existing_id, score },
            None => DedupResult::Unique,
        }
    }
}

fn combine(title: &str, description: &str) -> String {
    let mut s = String::with_capacity(title.len() + 1 + description.len());
    s.push_str(title);
    s.push('\n');
    s.push_str(description);
    s
}

fn eq_ignore_case(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

/// Tokenise into lowercase alphanumeric tokens, dropping tokens shorter
/// than 3 characters.
fn tokenize(text: &str) -> Vec<String> {
    let lowered = text.to_lowercase();
    let mut tokens = Vec::new();
    let mut current = String::new();
    for ch in lowered.chars() {
        if ch.is_alphanumeric() {
            current.push(ch);
        } else if !current.is_empty() {
            if current.chars().count() >= 3 {
                tokens.push(std::mem::take(&mut current));
            } else {
                current.clear();
            }
        }
    }
    if !current.is_empty() && current.chars().count() >= 3 {
        tokens.push(current);
    }
    tokens
}

/// Document frequency: number of documents each token appears in.
fn document_frequencies(documents: &[Vec<String>]) -> HashMap<String, usize> {
    let mut df: HashMap<String, usize> = HashMap::new();
    for doc in documents {
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for token in doc {
            if seen.insert(token.as_str()) {
                *df.entry(token.clone()).or_insert(0) += 1;
            }
        }
    }
    df
}

/// Build the L2-normalised TF-IDF vector for `tokens`.
///
/// IDF uses the smoothed form `ln((N + 1) / (df + 1)) + 1` so a term
/// that appears in every document still carries non-zero weight (rare
/// but keeps cosine well-defined for tiny corpora).
fn tfidf_vector(
    tokens: &[String],
    df: &HashMap<String, usize>,
    n_docs: usize,
) -> HashMap<String, f64> {
    if tokens.is_empty() {
        return HashMap::new();
    }
    let mut tf: HashMap<String, f64> = HashMap::new();
    for token in tokens {
        *tf.entry(token.clone()).or_insert(0.0) += 1.0;
    }
    #[allow(clippy::cast_precision_loss)]
    let n = n_docs as f64;
    let mut vec: HashMap<String, f64> = HashMap::with_capacity(tf.len());
    for (token, count) in tf {
        #[allow(clippy::cast_precision_loss)]
        let df_token = df.get(&token).copied().unwrap_or(0) as f64;
        let idf = ((n + 1.0) / (df_token + 1.0)).ln() + 1.0;
        vec.insert(token, count * idf);
    }
    // L2 normalise.
    let norm: f64 = vec.values().map(|v| v * v).sum::<f64>().sqrt();
    if norm > 0.0 {
        for v in vec.values_mut() {
            *v /= norm;
        }
    }
    vec
}

/// Cosine similarity of two L2-normalised TF-IDF vectors. Because both
/// vectors are pre-normalised, the dot product *is* the cosine.
fn cosine(a: &HashMap<String, f64>, b: &HashMap<String, f64>) -> f64 {
    // Iterate over the smaller map for efficiency.
    let (small, large) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    let mut dot = 0.0;
    for (token, weight) in small {
        if let Some(other) = large.get(token) {
            dot += weight * other;
        }
    }
    dot.clamp(0.0, 1.0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn existing(id: &str, title: &str, description: &str) -> ExistingFinding {
        ExistingFinding {
            id: id.into(),
            title: title.into(),
            description: description.into(),
        }
    }

    #[test]
    fn unique_when_corpus_is_empty() {
        let r = Deduplicator::new().is_duplicate("X", "Y", &[]);
        assert_eq!(r, DedupResult::Unique);
    }

    #[test]
    fn near_identical_finding_flagged_duplicate() {
        let dedup = Deduplicator::new();
        let existing = vec![existing(
            "f-1",
            "SQL injection in /login endpoint",
            "Boolean-based blind SQLi via username parameter; payload triggers always-true clause",
        )];
        let r = dedup.is_duplicate(
            "SQL injection in /login endpoint",
            "Boolean-based blind SQLi via username parameter; payload triggers always-true clause",
            &existing,
        );
        match r {
            DedupResult::Duplicate { existing_id, score } => {
                assert_eq!(existing_id, "f-1");
                assert!(score >= 0.99, "score: {score}");
            }
            DedupResult::Unique => panic!("expected duplicate, got unique"),
        }
    }

    #[test]
    fn paraphrased_finding_above_threshold_flagged_duplicate() {
        let dedup = Deduplicator::new();
        let existing = vec![existing(
            "f-1",
            "Reflected XSS in search query parameter",
            "Reflected cross-site scripting via the search query parameter on the /search endpoint allows attacker controlled javascript execution.",
        )];
        // Same vocabulary, slightly different word order.
        let r = dedup.is_duplicate(
            "Reflected XSS via search query parameter",
            "Reflected XSS through search query parameter on the /search endpoint allows attacker controlled javascript execution.",
            &existing,
        );
        assert!(r.is_duplicate(), "expected duplicate, got {r:?}");
    }

    #[test]
    fn unrelated_finding_returns_unique() {
        let dedup = Deduplicator::new();
        let existing = vec![existing(
            "f-1",
            "Reflected XSS in search query parameter",
            "Attacker controlled HTML rendered without escaping in the search results page.",
        )];
        let r = dedup.is_duplicate(
            "Missing security headers",
            "Server response is missing Strict-Transport-Security and Content-Security-Policy.",
            &existing,
        );
        assert_eq!(r, DedupResult::Unique);
    }

    #[test]
    fn picks_best_matching_existing_finding() {
        let dedup = Deduplicator::new();
        let corpus = vec![
            existing(
                "f-distractor",
                "Open redirect",
                "Unvalidated redirect via next parameter",
            ),
            existing(
                "f-target",
                "Stored XSS in profile bio",
                "Stored cross-site scripting via the profile bio field allows persistent javascript execution",
            ),
            existing(
                "f-noise",
                "Insecure direct object reference",
                "Server does not check ownership before returning resource",
            ),
        ];
        let r = dedup.is_duplicate(
            "Stored XSS in profile bio field",
            "Stored cross-site scripting via the profile bio field allows persistent javascript execution",
            &corpus,
        );
        match r {
            DedupResult::Duplicate { existing_id, score } => {
                assert_eq!(existing_id, "f-target");
                assert!(score >= 0.85);
            }
            DedupResult::Unique => panic!("expected duplicate"),
        }
    }

    #[test]
    fn threshold_is_respected_strict_geq() {
        let dedup = Deduplicator::new();
        let existing = vec![existing("f-1", "alpha beta", "gamma delta epsilon")];
        // With a low threshold this should match easily.
        let low = dedup.is_duplicate_with("alpha beta", "gamma delta epsilon", &existing, 0.5);
        assert!(low.is_duplicate());
        // With an impossible threshold it must not match.
        let high = dedup.is_duplicate_with("alpha beta", "gamma delta epsilon", &existing, 1.0001);
        assert_eq!(high, DedupResult::Unique);
    }

    #[test]
    fn tokenize_drops_short_tokens_and_punctuation() {
        let tokens = tokenize("a quick brown fox: jumped over the lazy dog");
        assert!(tokens.iter().all(|t| t.chars().count() >= 3));
        assert!(tokens.contains(&"quick".to_owned()));
        assert!(tokens.contains(&"brown".to_owned()));
        assert!(tokens.contains(&"fox".to_owned()));
        assert!(!tokens.contains(&"a".to_owned()));
    }

    #[test]
    fn cosine_of_orthogonal_vectors_is_zero() {
        let mut a: HashMap<String, f64> = HashMap::new();
        a.insert("x".into(), 1.0);
        let mut b: HashMap<String, f64> = HashMap::new();
        b.insert("y".into(), 1.0);
        let c = cosine(&a, &b);
        assert!(c.abs() < f64::EPSILON);
    }

    #[test]
    fn cosine_of_identical_vectors_is_one() {
        let mut a: HashMap<String, f64> = HashMap::new();
        a.insert("x".into(), 1.0);
        let c = cosine(&a, &a);
        assert!((c - 1.0).abs() < f64::EPSILON);
    }
}
