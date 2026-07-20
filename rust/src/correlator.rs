//! 3-tier correlation engine: deterministic blocking → MinHash/LSH → weighted scoring.
//!
//! Tier 1: Build hash indexes on structured fields (CWE, host, title prefix, exact title)
//!         to generate candidate pairs cheaply in O(n).
//! Tier 2: MinHash/LSH via gaoya on character trigrams of "title|description" to catch
//!         fuzzy near-duplicates that blocking misses.
//! Tier 3: Weighted scoring on union of Tier 1+2 candidates using Jaro-Winkler on title
//!         and description, plus exact-match signals for CWE, host overlap, and severity.
//!
//! For n < 100 findings, falls back to brute-force pairwise (simpler, fast enough).
//! The GIL is released for the compute-heavy phases so Python threads are not blocked.

use ahash::AHashMap;
use gaoya::minhash::{MinHasher, MinHasher16};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyTuple};
use rayon::prelude::*;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};

// ---------------------------------------------------------------------------
// Memory guards
// ---------------------------------------------------------------------------

/// Hard caps to prevent unbounded memory/CPU usage.
const MAX_TIER2_CANDIDATES: usize = 2_000_000;
const MAX_TOTAL_CANDIDATES: usize = 5_000_000;

/// Maximum LSH bucket size — skip degenerate buckets that would produce O(n²) pairs.
const MAX_LSH_BUCKET: usize = 500;

/// Read available memory from /proc/meminfo (Linux only).
/// Returns `None` on non-Linux or if parsing fails — callers should proceed anyway.
fn available_memory_bytes() -> Option<u64> {
    let content = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in content.lines() {
        if line.starts_with("MemAvailable:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let kb: u64 = parts[1].parse().ok()?;
                return Some(kb * 1024);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Data extraction (Phase 1, GIL held)
// ---------------------------------------------------------------------------

struct FindingData {
    index: usize,
    title_lower: String,
    description: String,
    severity: String,
    cwe_id: Option<i64>,
    affected_hosts: Vec<String>,
    /// Lowercased "title|description" used for LSH shingling.
    text_for_lsh: String,
}

fn extract_str(dict: &Bound<'_, PyDict>, key: &str) -> String {
    dict.get_item(key)
        .ok()
        .flatten()
        .map(|v| v.str().map(|s| s.to_string()).unwrap_or_default())
        .unwrap_or_default()
}

fn extract_findings(findings: &Bound<'_, PyList>) -> Vec<FindingData> {
    findings
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let dict = item.downcast::<PyDict>().expect("expected dict");
            let title = extract_str(dict, "title");
            let description = extract_str(dict, "description");
            let severity = extract_str(dict, "severity");

            let cwe_id = dict
                .get_item("cwe_id")
                .ok()
                .flatten()
                .and_then(|v| v.extract::<i64>().ok());

            let affected_hosts: Vec<String> = dict
                .get_item("affected_hosts")
                .ok()
                .flatten()
                .and_then(|v| v.extract::<Vec<String>>().ok())
                .unwrap_or_default();

            let title_lower = title.to_lowercase();
            let desc_lower = description.to_lowercase();
            let text_for_lsh = format!("{}|{}", title_lower, desc_lower);

            FindingData {
                index,
                title_lower,
                description,
                severity,
                cwe_id,
                affected_hosts,
                text_for_lsh,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Severity threshold lookup
// ---------------------------------------------------------------------------

/// Severity ordering: CRITICAL > HIGH > MEDIUM > LOW > INFO.
fn severity_rank(s: &str) -> u8 {
    match s {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        "INFO" => 0,
        _ => 0,
    }
}

fn parse_severity_thresholds(
    py_dict: Option<&Bound<'_, PyDict>>,
    default: f64,
) -> AHashMap<String, f64> {
    let mut map = AHashMap::new();
    if let Some(d) = py_dict {
        for (k, v) in d.iter() {
            if let (Ok(key), Ok(val)) = (k.extract::<String>(), v.extract::<f64>()) {
                map.insert(key, val);
            }
        }
    }
    // Ensure all severity levels have an entry.
    for sev in &["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] {
        map.entry(sev.to_string()).or_insert(default);
    }
    map
}

/// Threshold for a pair: use the higher-severity finding's threshold.
fn threshold_for_pair(a: &FindingData, b: &FindingData, sev_map: &AHashMap<String, f64>) -> f64 {
    let max_sev = if severity_rank(&a.severity) >= severity_rank(&b.severity) {
        &a.severity
    } else {
        &b.severity
    };
    sev_map.get(max_sev).copied().unwrap_or(0.8)
}

// ---------------------------------------------------------------------------
// Tier 1: Deterministic blocking
// ---------------------------------------------------------------------------

/// Maximum bucket size — skip overly broad buckets (defer to Tier 2).
/// Keeps candidate pair generation bounded: a bucket of 200 entries produces
/// at most 200*199/2 = ~20k pairs, which is manageable for Tier 3 scoring.
const MAX_BUCKET_SIZE: usize = 200;

fn blocking_candidates(data: &[FindingData]) -> HashSet<(usize, usize)> {
    let mut buckets: AHashMap<u64, Vec<usize>> = AHashMap::new();

    for f in data {
        // Key 1: CWE
        if let Some(cwe) = f.cwe_id {
            let key = ahash::RandomState::with_seeds(1, 0, 0, 0).hash_one(format!("cwe:{}", cwe));
            buckets.entry(key).or_default().push(f.index);
        }

        // Key 2: first 5 lowercase tokens of title
        let prefix: String = f
            .title_lower
            .split_whitespace()
            .take(5)
            .collect::<Vec<_>>()
            .join(" ");
        if !prefix.is_empty() {
            let key =
                ahash::RandomState::with_seeds(2, 0, 0, 0).hash_one(format!("title5:{}", prefix));
            buckets.entry(key).or_default().push(f.index);
        }

        // Key 3: exact title hash
        {
            let key = ahash::RandomState::with_seeds(3, 0, 0, 0)
                .hash_one(format!("exact:{}", f.title_lower));
            buckets.entry(key).or_default().push(f.index);
        }

        // Key 4: host+CWE combos
        if let Some(cwe) = f.cwe_id {
            for host in &f.affected_hosts {
                let key = ahash::RandomState::with_seeds(4, 0, 0, 0)
                    .hash_one(format!("hostcwe:{}|{}", host, cwe));
                buckets.entry(key).or_default().push(f.index);
            }
        }

        // Key 5: host+severity combos
        for host in &f.affected_hosts {
            let key = ahash::RandomState::with_seeds(5, 0, 0, 0)
                .hash_one(format!("hostsev:{}|{}", host, f.severity));
            buckets.entry(key).or_default().push(f.index);
        }
    }

    // Generate candidate pairs from buckets, skipping oversized ones.
    let mut candidates = HashSet::new();
    for members in buckets.values() {
        if members.len() > MAX_BUCKET_SIZE || members.len() < 2 {
            continue;
        }
        for (pos_a, &idx_a) in members.iter().enumerate() {
            for &idx_b in &members[pos_a + 1..] {
                let pair = if idx_a < idx_b {
                    (idx_a, idx_b)
                } else {
                    (idx_b, idx_a)
                };
                candidates.insert(pair);
            }
        }
    }
    candidates
}

// ---------------------------------------------------------------------------
// Tier 2: MinHash/LSH via gaoya
// ---------------------------------------------------------------------------

/// Generate character trigrams from a string.
fn char_trigrams(s: &str) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() < 3 {
        return vec![s.to_string()];
    }
    chars.windows(3).map(|w| w.iter().collect()).collect()
}

/// Pick (num_bands, band_width) where bands * width <= num_hashes and the LSH
/// probability curve crosses closest to 0.5 at the target threshold.
fn minhash_band_params(threshold: f64, num_hashes: usize) -> (usize, usize) {
    let mut best = (1usize, num_hashes);
    let mut best_err = f64::MAX;
    for bands in 1..=num_hashes {
        let rows = num_hashes / bands;
        if rows == 0 {
            break;
        }
        // P(candidate) = 1 - (1 - threshold^rows)^bands
        let prob = 1.0 - (1.0 - threshold.powi(rows as i32)).powi(bands as i32);
        let err = (prob - 0.5).abs();
        if err < best_err {
            best_err = err;
            best = (bands, rows);
        }
    }
    best
}

/// Hash a band slice to a single u64 for bucket assignment.
fn hash_band_slice(band: &[u16], band_idx: usize) -> u64 {
    let mut h = ahash::AHasher::default();
    band_idx.hash(&mut h);
    for &val in band {
        val.hash(&mut h);
    }
    h.finish()
}

/// Band-at-a-time LSH: processes one band, collects pairs, drops the band map,
/// then moves to the next. Peak memory is one band map (~2 MB) instead of the
/// full gaoya MinHashIndex (~1.6 GB at 200k findings).
fn lsh_candidates(data: &[FindingData], lsh_threshold: f64) -> HashSet<(usize, usize)> {
    let num_hashes: usize = if data.len() > 50_000 { 64 } else { 128 };
    let (num_bands, band_width) = minhash_band_params(lsh_threshold, num_hashes);
    let actual_hashes = num_bands * band_width;
    let hasher = MinHasher16::new(actual_hashes);

    // Generate signatures in parallel (temporary — ~25 MB for 200k findings).
    let signatures: Vec<Vec<u16>> = data
        .par_iter()
        .map(|f| hasher.create_signature(char_trigrams(&f.text_for_lsh).iter()))
        .collect();

    let mut candidates = HashSet::new();

    // Process one band at a time — only one AHashMap in memory.
    for band_idx in 0..num_bands {
        let start = band_idx * band_width;
        let end = start + band_width;

        let mut buckets: AHashMap<u64, Vec<usize>> = AHashMap::new();
        for (idx, sig) in signatures.iter().enumerate() {
            let band_hash = hash_band_slice(&sig[start..end], band_idx);
            buckets.entry(band_hash).or_default().push(idx);
        }

        for members in buckets.values() {
            if members.len() < 2 || members.len() > MAX_LSH_BUCKET {
                continue;
            }
            for (pos_a, &idx_a) in members.iter().enumerate() {
                for &idx_b in &members[pos_a + 1..] {
                    let pair = if idx_a < idx_b {
                        (idx_a, idx_b)
                    } else {
                        (idx_b, idx_a)
                    };
                    candidates.insert(pair);
                }
            }
        }

        if candidates.len() > MAX_TIER2_CANDIDATES {
            eprintln!(
                "[correlator] Tier 2 candidate cap reached ({} > {}), stopping LSH early",
                candidates.len(),
                MAX_TIER2_CANDIDATES
            );
            break;
        }
        // `buckets` dropped here — only one band map at a time
    }
    candidates
}

// ---------------------------------------------------------------------------
// Tier 3: Weighted scoring
// ---------------------------------------------------------------------------

fn jaccard_hosts(a: &[String], b: &[String]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0; // both empty → indistinguishable
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let set_a: HashSet<&str> = a.iter().map(|s| s.as_str()).collect();
    let set_b: HashSet<&str> = b.iter().map(|s| s.as_str()).collect();
    let intersection = set_a.intersection(&set_b).count();
    let union = set_a.union(&set_b).count();
    if union == 0 {
        0.0
    } else {
        intersection as f64 / union as f64
    }
}

fn score_pair(a: &FindingData, b: &FindingData) -> f64 {
    let title_sim = strsim::jaro_winkler(&a.title_lower, &b.title_lower);

    let cwe_sim = match (a.cwe_id, b.cwe_id) {
        (Some(ca), Some(cb)) if ca == cb => 1.0,
        (Some(_), Some(_)) => 0.0,
        (None, None) => 1.0,  // both missing — indistinguishable
        _ => 0.5,             // one present, one missing — uncertain
    };

    let host_sim = jaccard_hosts(&a.affected_hosts, &b.affected_hosts);

    // Truncate description to 200 chars for speed.
    let desc_a: String = a.description.chars().take(200).collect();
    let desc_b: String = b.description.chars().take(200).collect();
    let desc_sim = strsim::jaro_winkler(
        &desc_a.to_lowercase(),
        &desc_b.to_lowercase(),
    );

    let sev_sim = if a.severity == b.severity {
        1.0
    } else {
        0.0
    };

    0.35 * title_sim + 0.25 * cwe_sim + 0.15 * host_sim + 0.15 * desc_sim + 0.10 * sev_sim
}

fn score_candidates(
    data: &[FindingData],
    candidates: &HashSet<(usize, usize)>,
    sev_map: &AHashMap<String, f64>,
) -> Vec<(usize, usize, f64)> {
    let pairs: Vec<(usize, usize)> = candidates.iter().copied().collect();
    pairs
        .par_iter()
        .filter_map(|&(i, j)| {
            let score = score_pair(&data[i], &data[j]);
            let threshold = threshold_for_pair(&data[i], &data[j], sev_map);
            if score >= threshold {
                Some((i, j, score))
            } else {
                None
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Brute-force fallback for small sets (n < 100)
// ---------------------------------------------------------------------------

fn brute_force(data: &[FindingData], sev_map: &AHashMap<String, f64>) -> Vec<(usize, usize, f64)> {
    let n = data.len();
    (0..n)
        .into_par_iter()
        .flat_map_iter(|i| {
            (i + 1..n).filter_map(move |j| {
                let score = score_pair(&data[i], &data[j]);
                let threshold = threshold_for_pair(&data[i], &data[j], sev_map);
                if score >= threshold {
                    Some((i, j, score))
                } else {
                    None
                }
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Public Python API
// ---------------------------------------------------------------------------

/// Find pairs of correlated findings above the similarity threshold.
///
/// Returns a list of `(index_a, index_b, similarity_score)` tuples.
///
/// Uses a 3-tier pipeline for large sets: deterministic blocking → MinHash/LSH → weighted
/// scoring. For n < 100, falls back to brute-force pairwise with the same weighted scoring.
#[pyfunction]
#[pyo3(signature = (findings, threshold, severity_thresholds=None))]
pub fn correlate_findings<'py>(
    py: Python<'py>,
    findings: &Bound<'py, PyList>,
    threshold: f64,
    severity_thresholds: Option<&Bound<'py, PyDict>>,
) -> PyResult<Bound<'py, PyList>> {
    // --- Phase 1: extract all finding data while holding the GIL ---
    let data = extract_findings(findings);
    let sev_map = parse_severity_thresholds(severity_thresholds, threshold);

    // --- Phase 2: compute correlations — release the GIL ---
    let pairs: Vec<(usize, usize, f64)> = py.allow_threads(|| {
        if data.len() < 100 {
            return brute_force(&data, &sev_map);
        }

        // Tier 1: deterministic blocking
        let mut candidates = blocking_candidates(&data);

        // Tier 2: MinHash/LSH — memory-efficient band-at-a-time approach.
        // Guard: skip if available memory is critically low (< 2 GB).
        let skip_lsh = match available_memory_bytes() {
            Some(avail) if avail < 2 * 1024 * 1024 * 1024 => {
                eprintln!(
                    "[correlator] Skipping Tier 2 LSH: only {} MB available (need 2048 MB)",
                    avail / (1024 * 1024)
                );
                true
            }
            _ => false, // non-Linux or enough memory — proceed
        };

        if !skip_lsh {
            let lsh_threshold = if threshold < 0.65 { 0.3 } else { 0.5 };
            let tier2 = lsh_candidates(&data, lsh_threshold);
            candidates.extend(tier2);
        }

        // Guard: cap total candidates before expensive Tier 3 scoring.
        if candidates.len() > MAX_TOTAL_CANDIDATES {
            eprintln!(
                "[correlator] Total candidate cap reached ({} > {}), truncating",
                candidates.len(),
                MAX_TOTAL_CANDIDATES
            );
            let truncated: HashSet<(usize, usize)> =
                candidates.into_iter().take(MAX_TOTAL_CANDIDATES).collect();
            candidates = truncated;
        }

        // Tier 3: weighted scoring on all candidates
        score_candidates(&data, &candidates, &sev_map)
    });

    // --- Phase 3: build Python result list (GIL re-acquired) ---
    let result = PyList::empty_bound(py);
    for &(i, j, score) in &pairs {
        let items: Vec<PyObject> = vec![i.into_py(py), j.into_py(py), score.into_py(py)];
        let tuple = PyTuple::new_bound(py, items);
        result.append(tuple)?;
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jaro_winkler_identical() {
        let score = strsim::jaro_winkler("SQL Injection", "SQL Injection");
        assert!((score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_jaro_winkler_similar() {
        let score = strsim::jaro_winkler("SQL Injection in Login", "SQL Injection in Search");
        assert!(score > 0.7);
    }

    #[test]
    fn test_jaro_winkler_different() {
        let score = strsim::jaro_winkler("SQL Injection", "Cross-Site Scripting");
        assert!(score < 0.8);
    }

    #[test]
    fn test_char_trigrams() {
        let tg = char_trigrams("abcde");
        assert_eq!(tg, vec!["abc", "bcd", "cde"]);
    }

    #[test]
    fn test_char_trigrams_short() {
        let tg = char_trigrams("ab");
        assert_eq!(tg, vec!["ab"]);
    }

    #[test]
    fn test_score_pair_identical() {
        let a = FindingData {
            index: 0,
            title_lower: "sql injection".into(),
            description: "SQL injection in login form".into(),
            severity: "HIGH".into(),
            cwe_id: Some(89),
            affected_hosts: vec!["host1".into()],
            text_for_lsh: "sql injection|sql injection in login form".into(),
        };
        let b = FindingData {
            index: 1,
            title_lower: "sql injection".into(),
            description: "SQL injection in login form".into(),
            severity: "HIGH".into(),
            cwe_id: Some(89),
            affected_hosts: vec!["host1".into()],
            text_for_lsh: "sql injection|sql injection in login form".into(),
        };
        let score = score_pair(&a, &b);
        assert!((score - 1.0).abs() < 0.01, "identical findings should score ~1.0, got {}", score);
    }

    #[test]
    fn test_score_pair_different_cwe() {
        let a = FindingData {
            index: 0,
            title_lower: "sql injection".into(),
            description: "desc".into(),
            severity: "HIGH".into(),
            cwe_id: Some(89),
            affected_hosts: vec![],
            text_for_lsh: "sql injection|desc".into(),
        };
        let b = FindingData {
            index: 1,
            title_lower: "sql injection".into(),
            description: "desc".into(),
            severity: "HIGH".into(),
            cwe_id: Some(79),
            affected_hosts: vec![],
            text_for_lsh: "sql injection|desc".into(),
        };
        let score_diff = score_pair(&a, &b);
        // Change b to same CWE
        let c = FindingData { cwe_id: Some(89), ..b };
        let score_same = score_pair(&a, &c);
        assert!(score_same > score_diff, "same CWE should score higher");
    }

    #[test]
    fn test_severity_rank() {
        assert!(severity_rank("CRITICAL") > severity_rank("HIGH"));
        assert!(severity_rank("HIGH") > severity_rank("MEDIUM"));
        assert!(severity_rank("MEDIUM") > severity_rank("LOW"));
        assert!(severity_rank("LOW") > severity_rank("INFO"));
    }

    #[test]
    fn test_minhash_band_params() {
        let (bands, rows) = minhash_band_params(0.5, 128);
        assert!(bands > 0);
        assert!(rows > 0);
        assert!(bands * rows <= 128);
        // Should produce a reasonable split, not degenerate (1, 128) or (128, 1)
        assert!(bands > 1, "expected bands > 1, got {}", bands);
        assert!(rows > 1, "expected rows > 1, got {}", rows);
    }

    #[test]
    fn test_minhash_band_params_high_threshold() {
        let (bands, rows) = minhash_band_params(0.8, 64);
        assert!(bands * rows <= 64);
        // High threshold should favor more rows per band
        assert!(rows >= 2);
    }

    #[test]
    fn test_lsh_candidates_identical_texts() {
        let data: Vec<FindingData> = (0..10)
            .map(|i| FindingData {
                index: i,
                title_lower: "sql injection in login form".into(),
                description: "A SQL injection vulnerability was found in the login form".into(),
                severity: "HIGH".into(),
                cwe_id: Some(89),
                affected_hosts: vec!["host1".into()],
                text_for_lsh: "sql injection in login form|a sql injection vulnerability was found in the login form".into(),
            })
            .collect();
        let candidates = lsh_candidates(&data, 0.5);
        // All 10 identical texts should produce pairs
        assert!(!candidates.is_empty(), "identical texts should produce LSH candidates");
        // Check that at least (0,1) is a candidate
        assert!(candidates.contains(&(0, 1)), "pair (0,1) should be a candidate");
    }

    #[test]
    fn test_lsh_candidates_different_texts() {
        let texts = vec![
            "sql injection in login form|a sql injection vulnerability",
            "cross-site scripting in search|reflected xss in search bar",
            "buffer overflow in kernel module|stack-based buffer overflow",
            "path traversal in file upload|directory traversal allows reading system files",
            "insecure deserialization in api|untrusted data deserialized without validation",
        ];
        let data: Vec<FindingData> = texts
            .into_iter()
            .enumerate()
            .map(|(i, t)| FindingData {
                index: i,
                title_lower: t.split('|').next().unwrap().into(),
                description: t.split('|').nth(1).unwrap().into(),
                severity: "HIGH".into(),
                cwe_id: Some((79 + i as i64) * 10),
                affected_hosts: vec![format!("host{}", i)],
                text_for_lsh: t.into(),
            })
            .collect();
        let candidates = lsh_candidates(&data, 0.5);
        // Very different texts should produce few or no candidates
        assert!(
            candidates.len() <= 3,
            "expected <= 3 candidates for very different texts, got {}",
            candidates.len()
        );
    }

    #[test]
    fn test_available_memory_returns_some() {
        // On Linux CI, /proc/meminfo should exist and return > 100 MB
        if std::path::Path::new("/proc/meminfo").exists() {
            let mem = available_memory_bytes();
            assert!(mem.is_some(), "should parse /proc/meminfo on Linux");
            assert!(
                mem.unwrap() > 100 * 1024 * 1024,
                "available memory should be > 100 MB, got {} bytes",
                mem.unwrap()
            );
        }
    }

    #[test]
    fn test_blocking_candidates_same_cwe() {
        let data = vec![
            FindingData {
                index: 0,
                title_lower: "vuln a".into(),
                description: "".into(),
                severity: "HIGH".into(),
                cwe_id: Some(89),
                affected_hosts: vec![],
                text_for_lsh: "vuln a|".into(),
            },
            FindingData {
                index: 1,
                title_lower: "vuln b".into(),
                description: "".into(),
                severity: "HIGH".into(),
                cwe_id: Some(89),
                affected_hosts: vec![],
                text_for_lsh: "vuln b|".into(),
            },
        ];
        let candidates = blocking_candidates(&data);
        assert!(candidates.contains(&(0, 1)));
    }
}
