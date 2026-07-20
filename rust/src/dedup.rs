//! Hash-based deduplication engine using xxHash for speed and rayon for parallelism.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::collections::HashSet;
use std::hash::Hasher;
use twox_hash::XxHash64;

/// Compute a deterministic hash key for a finding dict.
/// Key fields: id, title, severity, sorted affected_hosts, description.
fn finding_hash(finding: &Bound<'_, PyDict>) -> u64 {
    let mut hasher = XxHash64::with_seed(0);

    let id = finding
        .get_item("id")
        .ok()
        .flatten()
        .map(|v| v.str().map(|s| s.to_string()).unwrap_or_default())
        .unwrap_or_default();
    hasher.write(id.as_bytes());
    hasher.write(b"|");

    let title = finding
        .get_item("title")
        .ok()
        .flatten()
        .map(|v| v.str().map(|s| s.to_string()).unwrap_or_default())
        .unwrap_or_default();
    hasher.write(title.as_bytes());
    hasher.write(b"|");

    let severity = finding
        .get_item("severity")
        .ok()
        .flatten()
        .map(|v| v.str().map(|s| s.to_string()).unwrap_or_default())
        .unwrap_or_default();
    hasher.write(severity.as_bytes());
    hasher.write(b"|");

    let hosts: Vec<String> = finding
        .get_item("affected_hosts")
        .ok()
        .flatten()
        .and_then(|v| v.extract::<Vec<String>>().ok())
        .unwrap_or_default();
    let mut sorted_hosts = hosts;
    sorted_hosts.sort();
    hasher.write(sorted_hosts.join(",").as_bytes());
    hasher.write(b"|");

    let description = finding
        .get_item("description")
        .ok()
        .flatten()
        .map(|v| v.str().map(|s| s.to_string()).unwrap_or_default())
        .unwrap_or_default();
    hasher.write(description.as_bytes());

    hasher.finish()
}

/// Deduplicate a list of finding dicts by content hash.
/// Returns a new list with duplicates removed, preserving first-seen order.
#[pyfunction]
pub fn deduplicate_findings<'py>(
    py: Python<'py>,
    findings: &Bound<'py, PyList>,
) -> PyResult<Bound<'py, PyList>> {
    // First pass: compute hashes for all findings.
    let hashes: Vec<u64> = findings
        .iter()
        .map(|item| {
            let dict = item.downcast::<PyDict>().expect("expected dict");
            finding_hash(dict)
        })
        .collect();

    // Second pass: deduplicate preserving first-seen order.
    let mut seen = HashSet::new();
    let result = PyList::empty_bound(py);
    for (i, hash) in hashes.iter().enumerate() {
        if seen.insert(*hash) {
            result.append(findings.get_item(i)?)?;
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xxhash_deterministic() {
        let mut h1 = XxHash64::with_seed(0);
        h1.write(b"test|data");
        let mut h2 = XxHash64::with_seed(0);
        h2.write(b"test|data");
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn test_different_input_different_hash() {
        let mut h1 = XxHash64::with_seed(0);
        h1.write(b"alpha");
        let mut h2 = XxHash64::with_seed(0);
        h2.write(b"beta");
        assert_ne!(h1.finish(), h2.finish());
    }
}
