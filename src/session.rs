use crate::state::CrackState;
use anyhow::{Context, Result};
use std::{fs, path::PathBuf};

#[cfg(unix)]
fn set_owner_only(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

pub fn get_session_dir() -> PathBuf {
    let mut path = home::home_dir().unwrap_or_else(|| PathBuf::from("."));
    path.push(".crack-ng");
    path.push("sessions");
    fs::create_dir_all(&path).unwrap_or_default();
    path
}

fn validate_session_name(name: &str) -> Result<()> {
    if name.is_empty() {
        anyhow::bail!("Session name must not be empty");
    }
    if name.len() > 128 {
        anyhow::bail!("Session name too long (max 128 characters)");
    }
    if name == "." || name == ".." {
        anyhow::bail!("Session name must not be '.' or '..'");
    }
    if name.contains('/') || name.contains('\\') || name.contains("..") {
        anyhow::bail!("Invalid session name: must not contain path separators or '..'");
    }
    if name.chars().any(|c| c.is_control()) {
        anyhow::bail!("Session name must not contain control characters");
    }
    Ok(())
}

pub fn save_session(session_name: &str, state: &CrackState) -> Result<()> {
    validate_session_name(session_name)?;
    let mut session_dir = get_session_dir();
    session_dir.push(session_name);
    fs::create_dir_all(&session_dir)?;

    let mut persisted_state = state.clone();
    for job in &mut persisted_state.jobs {
        let src = PathBuf::from(&job.hash_file_path);
        if src.exists() && !src.starts_with(&session_dir) {
            let dest = session_dir.join(format!("job_{}.hashes", job.id));
            fs::copy(&src, &dest)?;
            job.hash_file_path = dest.to_string_lossy().to_string();
        }
    }

    let json_path = session_dir.join("session.json");
    let tmp_path = session_dir.join("session.json.tmp");
    let json = serde_json::to_string_pretty(&persisted_state)?;
    fs::write(&tmp_path, &json)?;
    fs::rename(&tmp_path, &json_path)?;
    #[cfg(unix)]
    set_owner_only(&json_path);
    Ok(())
}

pub fn load_session(session_name: &str) -> Result<CrackState> {
    validate_session_name(session_name)?;
    let mut path = get_session_dir();
    path.push(session_name);
    path.push("session.json");
    if !path.exists() {
        path = get_session_dir();
        path.push(format!("{}.json", session_name));
    }
    let json =
        fs::read_to_string(&path).context(format!("Could not find session at {:?}", path))?;
    let state: CrackState = serde_json::from_str(&json)?;
    Ok(state)
}
