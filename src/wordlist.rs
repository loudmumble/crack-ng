use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct WordlistInfo {
    pub path: PathBuf,
    pub name: String,
    pub size_bytes: u64,
    pub line_count: Option<u64>,
    /// True if the file is compressed (.gz, .bz2, .xz) and needs decompression
    /// before passing to hashcat/john.
    pub compressed: bool,
}

/// Decompress a compressed wordlist to a cache file, returning the decompressed path.
/// Cached in ~/.crack-ng/cache/ so it persists across runs.
/// Returns None if decompression fails or the file is not compressed.
pub fn decompress_wordlist(wl: &WordlistInfo) -> Option<PathBuf> {
    decompress_path(&wl.path)
}

/// Decompress any compressed file (.gz, .bz2, .xz) to ~/.crack-ng/cache/.
/// Returns the decompressed path, or None if the file is not compressed or
/// decompression fails. Idempotent: reuses cached result if it exists.
pub fn decompress_path(path: &std::path::Path) -> Option<PathBuf> {
    let ext = path.extension().and_then(|e| e.to_str())?;
    let decomp_cmd = match ext {
        "gz" => "gunzip",
        "bz2" => "bunzip2",
        "xz" => "unxz",
        _ => return None,
    };

    let cache_dir = home::home_dir()?.join(".crack-ng").join("cache");
    std::fs::create_dir_all(&cache_dir).ok()?;

    // Use a hash of the full canonical path as a prefix to avoid collisions
    // between files with the same stem in different directories.
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let path_hash = simple_hash(canonical.to_string_lossy().as_bytes());
    let stem = path.file_stem()?.to_string_lossy();
    let out_name = format!("{}_{}", path_hash, stem);
    let out_path = cache_dir.join(out_name);

    if out_path.exists() {
        return Some(out_path);
    }

    let status = std::process::Command::new(decomp_cmd)
        .arg("-k")  // keep original
        .arg("-c")  // write to stdout
        .arg(path)
        .stdout(std::fs::File::create(&out_path).ok()?)
        .stderr(std::process::Stdio::null())
        .status()
        .ok()?;

    if status.success() {
        Some(out_path)
    } else {
        let _ = std::fs::remove_file(&out_path);
        None
    }
}

/// Cheap deterministic hash for cache key differentiation. Not cryptographic.
fn simple_hash(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Discover wordlists from default dirs, user-specified dirs (--wordlist-dir),
/// and CRACK_NG_WORDLIST_DIRS env var (colon-separated).
/// All directories are scanned recursively with no depth limit.
pub fn discover_wordlists(extra_dirs: &[PathBuf]) -> Vec<WordlistInfo> {
    let mut wordlists = Vec::new();

    let mut search_dirs = build_search_dirs();

    // Env var: CRACK_NG_WORDLIST_DIRS (colon-separated)
    if let Ok(env_dirs) = std::env::var("CRACK_NG_WORDLIST_DIRS") {
        for d in env_dirs.split(':') {
            let p = PathBuf::from(d.trim());
            if !d.trim().is_empty() {
                search_dirs.push(p);
            }
        }
    }

    // CLI --wordlist-dir flags
    for d in extra_dirs {
        search_dirs.push(d.clone());
    }

    let mut visited = std::collections::HashSet::new();
    for dir in &search_dirs {
        if !dir.exists() || !dir.is_dir() {
            continue;
        }
        scan_recursive(dir, &mut wordlists, &mut visited);
    }

    // Sort largest-first so cascade stages get the most comprehensive wordlist
    wordlists.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));
    dedup_by_path(&mut wordlists);

    wordlists
}

fn build_search_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    if let Some(home) = home::home_dir() {
        dirs.push(home.join("wordlists"));
        dirs.push(home.join("SecLists"));
    }

    dirs.push(PathBuf::from("/usr/share/wordlists"));
    dirs.push(PathBuf::from("/usr/share/seclists"));
    dirs.push(PathBuf::from("/opt/wordlists"));

    dirs
}

/// Known wordlist extensions (uncompressed).
const WORDLIST_EXTS: &[&str] = &[
    "txt", "lst", "dict", "wordlist", "words", "passwords", "dic",
];

/// Compressed extensions we can transparently decompress.
const COMPRESSED_EXTS: &[&str] = &["gz", "bz2", "xz"];

/// Check if a path has a compressed extension (.gz, .bz2, .xz).
pub fn is_compressed(path: &std::path::Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| COMPRESSED_EXTS.contains(&e))
}

/// Check if a file looks like a wordlist (by extension).
/// Accepts both plain files and compressed variants (e.g. rockyou.txt.gz).
/// Files with NO extension are accepted too -- many SecLists entries have none.
fn is_wordlist_file(path: &std::path::Path) -> bool {
    let name = match path.file_name().and_then(|f| f.to_str()) {
        Some(n) => n,
        None => return false,
    };

    // Skip obvious non-wordlist files
    if name.starts_with('.') || name.ends_with(".rule") || name.ends_with(".md")
        || name.ends_with(".py") || name.ends_with(".sh") || name.ends_with(".json")
        || name.ends_with(".xml") || name.ends_with(".html") || name.ends_with(".csv")
        || name.ends_with(".pdf") || name.ends_with(".png") || name.ends_with(".jpg")
    {
        return false;
    }

    // Check for compressed wordlist: stem must have a wordlist ext (e.g. rockyou.txt.gz)
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        if COMPRESSED_EXTS.contains(&ext) {
            let stem = std::path::Path::new(path.file_stem().unwrap_or_default());
            return stem.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| WORDLIST_EXTS.contains(&e));
        }
        if WORDLIST_EXTS.contains(&ext) {
            return true;
        }
    }

    // No extension -- accept it (common in SecLists and custom collections).
    // The 10KB min-size filter downstream weeds out tiny noise files.
    path.extension().is_none()
}

/// Recursively walk `dir` and collect all wordlist files (no depth limit).
/// Skips files smaller than 10 KB to filter noise.
/// Compressed files (.gz, .bz2, .xz) are flagged for decompression.
/// Tracks visited directories (by inode/device) to avoid symlink loops.
fn scan_recursive(
    dir: &std::path::Path,
    wordlists: &mut Vec<WordlistInfo>,
    visited: &mut std::collections::HashSet<PathBuf>,
) {
    // Resolve symlinks and track canonical paths to break cycles
    let canonical = match dir.canonicalize() {
        Ok(c) => c,
        Err(_) => return,
    };
    if !visited.insert(canonical) {
        return;
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            scan_recursive(&path, wordlists, visited);
        } else if path.is_file() && is_wordlist_file(&path) {
            if let Ok(meta) = path.metadata() {
                if meta.len() < 10_000 {
                    continue;
                }
                let name = path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                let compressed = path.extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| COMPRESSED_EXTS.contains(&e));
                wordlists.push(WordlistInfo {
                    path,
                    name,
                    size_bytes: meta.len(),
                    line_count: None,
                    compressed,
                });
            }
        }
    }
}

fn dedup_by_path(wordlists: &mut Vec<WordlistInfo>) {
    let mut seen = std::collections::HashSet::new();
    wordlists.retain(|wl| {
        let canonical = wl.path.canonicalize().unwrap_or_else(|_| wl.path.clone());
        seen.insert(canonical)
    });
}

pub fn find_rules() -> Vec<PathBuf> {
    let mut rules = Vec::new();

    let rule_dirs = build_rule_dirs();
    let wanted_rules = [
        "best64.rule",
        "dive.rule",
        "rockyou-30000.rule",
        "OneRuleToRuleThemAll.rule",
        "toggles1.rule",
        "d3ad0ne.rule",
    ];

    for dir in &rule_dirs {
        if !dir.exists() || !dir.is_dir() {
            continue;
        }
        for name in &wanted_rules {
            let path = dir.join(name);
            if path.exists() && path.is_file() {
                rules.push(path);
            }
        }
    }

    // Deduplicate
    let mut seen = std::collections::HashSet::new();
    rules.retain(|r| {
        let canonical = r.canonicalize().unwrap_or_else(|_| r.clone());
        seen.insert(canonical)
    });

    rules
}

fn build_rule_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    dirs.push(PathBuf::from("/usr/share/hashcat/rules"));
    dirs.push(PathBuf::from("/usr/local/share/hashcat/rules"));

    if let Some(home) = home::home_dir() {
        dirs.push(home.join(".hashcat").join("rules"));
    }

    dirs.push(PathBuf::from("/opt/hashcat/rules"));

    dirs
}
