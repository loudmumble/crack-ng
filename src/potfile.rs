use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct PotfileEntry {
    pub hash: String,
    pub plaintext: String,
}

pub fn read_potfiles() -> Vec<PotfileEntry> {
    let mut entries: HashMap<String, String> = HashMap::new();

    // Read ~/.hashcat/hashcat.potfile (format: hash:plaintext per line)
    if let Some(home) = home::home_dir() {
        let hashcat_pot = home.join(".hashcat").join("hashcat.potfile");
        read_potfile_colon_format(&hashcat_pot, &mut entries);

        // Read ~/.john/john.pot (format: $format$hash:plaintext or hash:plaintext)
        let john_pot = home.join(".john").join("john.pot");
        read_potfile_colon_format(&john_pot, &mut entries);
    }

    // Check system-level potfile (avoid world-writable paths like /tmp)
    let system_paths = [
        PathBuf::from("/usr/share/hashcat/hashcat.potfile"),
    ];
    for path in &system_paths {
        read_potfile_colon_format(path, &mut entries);
    }

    entries
        .into_iter()
        .map(|(hash, plaintext)| PotfileEntry { hash, plaintext })
        .collect()
}

fn read_potfile_colon_format(path: &Path, entries: &mut HashMap<String, String>) {
    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return,
    };
    for line in BufReader::new(file).lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        // Potfile format: hash:plaintext
        // For hashes containing ':', we split on the LAST ':'
        // JtR format can be: $format$hash:plaintext or user:hash:plaintext
        if let Some(sep_pos) = line.rfind(':') {
            let hash_part = &line[..sep_pos];
            let plain_part = &line[sep_pos + 1..];
            if !hash_part.is_empty() {
                entries
                    .entry(hash_part.to_string())
                    .or_insert_with(|| plain_part.to_string());
            }
        }
    }
}

pub fn filter_known_hashes(
    hashes: &[String],
    potfile: &[PotfileEntry],
) -> (Vec<String>, Vec<PotfileEntry>) {
    let pot_map: HashMap<&str, &str> = potfile
        .iter()
        .map(|e| (e.hash.as_str(), e.plaintext.as_str()))
        .collect();

    let mut unknown = Vec::new();
    let mut already_cracked = Vec::new();

    for hash in hashes {
        if let Some(plaintext) = pot_map.get(hash.as_str()) {
            already_cracked.push(PotfileEntry {
                hash: hash.clone(),
                plaintext: plaintext.to_string(),
            });
        } else {
            unknown.push(hash.clone());
        }
    }

    (unknown, already_cracked)
}
