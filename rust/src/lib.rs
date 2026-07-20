use pyo3::prelude::*;

mod correlator;
mod dedup;

/// Returns the crate version.
#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Root Python module for the vuln-core-rs extension.
#[pymodule]
fn vuln_core_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(dedup::deduplicate_findings, m)?)?;
    m.add_function(wrap_pyfunction!(correlator::correlate_findings, m)?)?;
    Ok(())
}
