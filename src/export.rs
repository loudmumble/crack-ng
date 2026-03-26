use crate::state::ExportRecord;
use anyhow::Result;
use std::{fs, path::PathBuf};

pub fn export_results(path: &PathBuf, recovered: &[ExportRecord]) -> Result<()> {
    if recovered.is_empty() {
        return Ok(());
    }
    if path.extension().unwrap_or_default() == "json" {
        fs::write(path, serde_json::to_string_pretty(recovered)?)?;
    } else {
        let mut wtr = csv::Writer::from_path(path)?;
        wtr.write_record(["timestamp", "algorithm", "hash", "plaintext"])?;
        for r in recovered {
            wtr.write_record([&r.timestamp, &r.algo, &r.hash, &r.plaintext])?;
        }
        wtr.flush()?;
    }
    Ok(())
}
