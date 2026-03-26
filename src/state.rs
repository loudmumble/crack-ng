use clap::Parser;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(short = 'H', long)]
    pub hashes: Option<PathBuf>,

    #[arg(short = 'w', long)]
    pub wordlist: Option<PathBuf>,

    #[arg(long)]
    pub force_cpu: bool,

    #[arg(long)]
    pub force_gpu: bool,

    #[arg(short = 'a', long)]
    pub attack_mode: Option<String>,

    /// Universal Fallback Mode. E.g., "-m 1000" for NTLM. Applied to any "Unknown" hashes.
    #[arg(short = 'm', long)]
    pub mode: Option<String>,

    #[arg(long)]
    pub no_tui: bool,

    #[arg(long)]
    pub export: Option<PathBuf>,

    /// Save the current session so it can be resumed later
    #[arg(long)]
    pub session: Option<String>,

    /// Resume a previously saved session
    #[arg(long)]
    pub resume: Option<String>,

    /// Enable smart cascade attack mode
    #[arg(long)]
    pub cascade: bool,

    /// Input format: auto, ntds, shadow, kerberoast, asrep, responder
    #[arg(long, default_value = "auto")]
    pub format: String,

    /// Generate HTML report on exit
    #[arg(long)]
    pub report: Option<PathBuf>,

    /// Show discovered wordlists and exit
    #[arg(long)]
    pub discover_wordlists: bool,

    #[arg(last = true)]
    pub passthrough: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct HashSignature {
    pub name: &'static str,
    pub regex: Regex,
    pub hashcat_mode: Option<&'static str>,
    pub jtr_format: Option<&'static str>,
}

lazy_static! {
    // Order matters: iter().find() returns first match, so SPECIFIC patterns (unique
    // prefixes like $2, $6$, $5$, $y$, $1$, $krb5, pbkdf2_, 0x0200, *) must come
    // BEFORE generic fixed-length hex patterns (MD5 32, SHA1 40, etc.).
    pub static ref SIGNATURES: Vec<HashSignature> = vec![
        // --- Prefixed / structured patterns (unambiguous) ---
        HashSignature { name: "Bcrypt ($2*)", regex: Regex::new(r"^\$2[abyx]\$\d{2}\$[./A-Za-z0-9]{53}$").unwrap(), hashcat_mode: Some("3200"), jtr_format: Some("bcrypt") },
        HashSignature { name: "Linux SHA-512 crypt", regex: Regex::new(r"^\$6\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]{86}$").unwrap(), hashcat_mode: Some("1800"), jtr_format: Some("sha512crypt") },
        HashSignature { name: "Linux SHA-256 crypt", regex: Regex::new(r"^\$5\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]{43}$").unwrap(), hashcat_mode: Some("7400"), jtr_format: Some("sha256crypt") },
        HashSignature { name: "Linux yescrypt", regex: Regex::new(r"^\$y\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+$").unwrap(), hashcat_mode: None, jtr_format: Some("yescrypt") },
        HashSignature { name: "Cisco IOS Type 5", regex: Regex::new(r"^\$1\$[a-zA-Z0-9./]{4}\$[a-zA-Z0-9./]{22}$").unwrap(), hashcat_mode: Some("500"), jtr_format: Some("md5crypt") },
        HashSignature { name: "MD5 Crypt", regex: Regex::new(r"^\$1\$[a-zA-Z0-9./]{1,8}\$[a-zA-Z0-9./]{22}$").unwrap(), hashcat_mode: Some("500"), jtr_format: Some("md5crypt") },
        HashSignature { name: "Django PBKDF2-SHA256", regex: Regex::new(r"^pbkdf2_sha256\$\d+\$[a-zA-Z0-9+/=]+\$[a-zA-Z0-9+/=]+$").unwrap(), hashcat_mode: Some("10000"), jtr_format: Some("PBKDF2-HMAC-SHA256") },
        HashSignature { name: "Kerberos 5 TGS-REP", regex: Regex::new(r"^\$krb5tgs\$\d+\$[a-zA-Z0-9.]+@[a-zA-Z0-9.]+:.*$").unwrap(), hashcat_mode: Some("13100"), jtr_format: Some("krb5tgs") },
        HashSignature { name: "Kerberos 5 AS-REP", regex: Regex::new(r"^\$krb5asrep\$\d+\$[a-zA-Z0-9.]+@[a-zA-Z0-9.]+:.*$").unwrap(), hashcat_mode: Some("19600"), jtr_format: Some("krb5asrep") },
        // --- Structured colon-delimited patterns ---
        HashSignature { name: "NTLM (LM:NT pair)", regex: Regex::new(r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$").unwrap(), hashcat_mode: Some("1000"), jtr_format: Some("nt") },
        HashSignature { name: "NetNTLMv2", regex: Regex::new(r"^\w+::\w+:[a-fA-F0-9]{16}:[a-fA-F0-9]{32}:[a-fA-F0-9]+$").unwrap(), hashcat_mode: Some("5600"), jtr_format: Some("netntlmv2") },
        HashSignature { name: "NetNTLMv1", regex: Regex::new(r"^\w+::\w+:[a-fA-F0-9]{48}:[a-fA-F0-9]{48}:[a-fA-F0-9]+$").unwrap(), hashcat_mode: Some("5500"), jtr_format: Some("netntlm") },
        HashSignature { name: "WPA/WPA2 (EAPOL)", regex: Regex::new(r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{12}:[a-fA-F0-9]{12}:[a-fA-F0-9]+$").unwrap(), hashcat_mode: Some("22000"), jtr_format: Some("wpapsk") },
        // --- Prefix-identified hex patterns ---
        HashSignature { name: "MSSQL 2012+", regex: Regex::new(r"^0x0200[a-fA-F0-9]+$").unwrap(), hashcat_mode: Some("1731"), jtr_format: Some("mssql12") },
        HashSignature { name: "MySQL 4.1+", regex: Regex::new(r"^\*[a-fA-F0-9]{40}$").unwrap(), hashcat_mode: Some("300"), jtr_format: Some("mysql-sha1") },
        // --- Generic fixed-length patterns (most ambiguous, checked last) ---
        HashSignature { name: "DES Crypt", regex: Regex::new(r"^[a-zA-Z0-9./]{13}$").unwrap(), hashcat_mode: Some("1500"), jtr_format: Some("descrypt") },
        HashSignature { name: "SHA512", regex: Regex::new(r"^[a-fA-F0-9]{128}$").unwrap(), hashcat_mode: Some("1700"), jtr_format: Some("raw-sha512") },
        HashSignature { name: "SHA256", regex: Regex::new(r"^[a-fA-F0-9]{64}$").unwrap(), hashcat_mode: Some("1400"), jtr_format: Some("raw-sha256") },
        HashSignature { name: "SHA1", regex: Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(), hashcat_mode: Some("100"), jtr_format: Some("raw-sha1") },
        HashSignature { name: "MD5", regex: Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(), hashcat_mode: Some("0"), jtr_format: Some("raw-md5") },
    ];
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: usize,
    pub algo_name: String,
    pub hashcat_mode: Option<String>,
    pub jtr_format: Option<String>,
    pub hash_file_path: String,
    pub total_hashes: usize,
    pub status: String,
    pub speed: String,
    pub eta: String,
    pub cracked: usize,
    pub engine_used: String,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct CrackState {
    pub jobs: Vec<Job>,
    pub active_job_idx: Option<usize>,
    pub log: VecDeque<String>,
    pub recovered: Vec<ExportRecord>,
    pub is_paused: bool,
    pub show_help: bool,
    pub active_tab: usize,
    pub overall_status: String,
    pub start_time: Option<i64>,
    #[serde(default)]
    pub cascade_stage: Option<String>,
    #[serde(default)]
    pub discovered_wordlists: Vec<String>,
    /// Fast O(1) lookup for recovered hash deduplication: (hash, plaintext)
    #[serde(skip)]
    pub recovered_set: HashSet<(String, String)>,
    /// Epoch seconds of last session save, for debouncing
    #[serde(skip)]
    pub last_save_time: i64,
    /// Active search query for filtering recovered hashes
    #[serde(skip)]
    pub search_query: String,
    /// Whether search input mode is active
    #[serde(skip)]
    pub search_active: bool,
}

impl CrackState {
    /// Insert a recovered hash if not already seen. Returns true if inserted.
    pub fn insert_recovered(&mut self, record: ExportRecord) -> bool {
        let key = (record.hash.clone(), record.plaintext.clone());
        if self.recovered_set.insert(key) {
            self.recovered.push(record);
            true
        } else {
            false
        }
    }

    /// Rebuild the recovered_set from the recovered vec (e.g. after deserialization).
    pub fn rebuild_recovered_set(&mut self) {
        self.recovered_set = self.recovered
            .iter()
            .map(|r| (r.hash.clone(), r.plaintext.clone()))
            .collect();
    }

    /// Push a log message, trimming to max 200 entries via O(1) pop_front.
    pub fn push_log(&mut self, msg: String) {
        self.log.push_back(msg);
        while self.log.len() > 200 {
            self.log.pop_front();
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportRecord {
    pub hash: String,
    pub plaintext: String,
    pub algo: String,
    pub timestamp: String,
}
