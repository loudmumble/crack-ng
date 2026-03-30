use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct WordlistInfo {
    pub path: PathBuf,
    pub name: String,
    pub size_bytes: u64,
    pub line_count: Option<u64>,
}

pub fn discover_wordlists() -> Vec<WordlistInfo> {
    let mut wordlists = Vec::new();

    let search_dirs = build_search_dirs();

    for dir in &search_dirs {
        if !dir.exists() || !dir.is_dir() {
            continue;
        }
        scan_directory(dir, &mut wordlists);
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

fn scan_directory(dir: &std::path::Path, wordlists: &mut Vec<WordlistInfo>) {
    // Look for known wordlist names directly
    let known_names = [
        "rockyou.txt",
        "common.txt",
        "passwords.txt",
        "darkweb2017-top10000.txt",
    ];
    for name in &known_names {
        let path = dir.join(name);
        if path.exists() && path.is_file() {
            if let Ok(meta) = path.metadata() {
                wordlists.push(WordlistInfo {
                    name: name.to_string(),
                    size_bytes: meta.len(),
                    line_count: None,
                    path,
                });
            }
        }
    }

    // Glob for .txt and .lst files
    let patterns = [
        format!("{}/**/*.txt", dir.display()),
        format!("{}/**/*.lst", dir.display()),
    ];

    for pattern in &patterns {
        if let Ok(paths) = glob::glob(pattern) {
            for entry in paths.flatten() {
                if !entry.is_file() {
                    continue;
                }
                // Skip tiny files (< 10KB) -- filters out User-Agent fragments,
                // single-entry credential lists, and other non-password-list files.
                if let Ok(meta) = entry.metadata() {
                    if meta.len() < 10_000 {
                        continue;
                    }
                    let name = entry
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    wordlists.push(WordlistInfo {
                        path: entry,
                        name,
                        size_bytes: meta.len(),
                        line_count: None,
                    });
                }
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
