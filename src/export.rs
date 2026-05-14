use crate::state::ExportRecord;
use anyhow::Result;
use std::{fs, path::Path};

pub fn export_results(path: &Path, recovered: &[ExportRecord]) -> Result<()> {
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
    // Restrict permissions -- exports contain cracked credentials
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}
