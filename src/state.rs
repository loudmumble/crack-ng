use clap::Parser;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "crack-ng",
    version,
    about = "Intelligent hash cracking orchestrator wrapping Hashcat and John the Ripper",
    long_about = "Intelligent hash cracking orchestrator wrapping Hashcat and John the Ripper.\n\n\
        Automatically identifies 60+ hash types, selects the optimal cracking engine,\n\
        and applies hardware-tuned parameters for maximum performance.\n\n\
        QUICK START:\n  \
        crack-ng hashes.txt rockyou.txt         Crack hash file with wordlist\n  \
        crack-ng 5f4dcc3b5aa765d61d8327deb882cf99 rockyou.txt\n                                            \
        Crack a single hash directly\n  \
        crack-ng hashes.txt --cascade           Smart multi-stage attack\n  \
        crack-ng --identify hashes.txt          Identify hash types (no cracking)\n  \
        crack-ng --identify '$2a$10$...'        Identify a single hash\n  \
        crack-ng --list-modes                   Show all 60+ supported hash types\n  \
        crack-ng                                Browse recovered credentials DB\n\n\
        INPUT:\n  \
        First positional arg can be a hash FILE or a raw HASH STRING.\n  \
        If the argument doesn't exist as a file and looks like a hash,\n  \
        it's treated as a direct hash input automatically.\n  \
        Binary files (.pcap, .kdbx, .zip, etc.) are detected with\n  \
        extraction guidance printed.\n\n\
        FORMATS:\n  \
        --format auto       Auto-detect (default)\n  \
        --format ntds       Impacket secretsdump output (user:rid:lm:nt:::)\n  \
        --format shadow     Linux /etc/shadow\n  \
        --format kerberoast Kerberoast ($krb5tgs$) output\n  \
        --format asrep      AS-REP roast ($krb5asrep$) output\n  \
        --format responder  Responder NetNTLMv2 captures",
    after_help = "OPTIMIZATION:\n  \
        GPU auto-detected via nvidia-smi. Hashcat params applied automatically:\n    \
        8+ GB VRAM -> -w 4 (nightmare) + -O (optimized kernels)\n    \
        4-8 GB VRAM -> -w 3 (high) + -O\n    \
        < 4 GB VRAM -> -w 2 (default) + -O\n    \
        No GPU      -> Falls back to John the Ripper (CPU)\n  \
        Override: crack-ng hashes.txt wl.txt -- -w 2\n\n\
        PASSTHROUGH:\n  \
        Arguments after -- are passed directly to the cracking engine:\n    \
        crack-ng hashes.txt wl.txt -- --rules=best64\n    \
        crack-ng hashes.txt wl.txt -- -w 2 --force\n\n\
        AMBIGUOUS HASHES:\n  \
        32-char hex defaults to MD5. Use -m to override:\n    \
        crack-ng hashes.txt wl.txt -m 1000    # Force NTLM\n    \
        crack-ng hashes.txt wl.txt -m 900     # Force MD4\n  \
        Run --list-modes to see all supported hash types."
)]
pub struct Args {
    /// Hash file or raw hash string, optionally followed by wordlist
    #[arg(value_name = "HASHFILE|HASH [WORDLIST]")]
    pub positional: Vec<PathBuf>,

    /// Hash file to crack (flag alternative to positional)
    #[arg(short = 'H', long = "hashes", help_heading = "Input")]
    pub hashes: Option<PathBuf>,

    /// Wordlist for dictionary attack (flag alternative to positional)
    #[arg(short = 'w', long = "wordlist", help_heading = "Input")]
    pub wordlist: Option<PathBuf>,

    /// Force CPU-only cracking via John the Ripper
    #[arg(long, help_heading = "Engine")]
    pub force_cpu: bool,

    /// Force GPU cracking via Hashcat
    #[arg(long, help_heading = "Engine")]
    pub force_gpu: bool,

    /// Hashcat attack mode: 0=dictionary, 1=combinator, 3=brute-force, 6=hybrid-wordlist, 7=hybrid-mask
    #[arg(short = 'a', long, help_heading = "Engine")]
    pub attack_mode: Option<String>,

    /// Fallback hashcat mode for unidentified hashes (e.g. -m 1000 for NTLM, -m 900 for MD4)
    #[arg(short = 'm', long, help_heading = "Engine")]
    pub mode: Option<String>,

    /// Run in headless/batch mode without the TUI
    #[arg(long, help_heading = "Output")]
    pub no_tui: bool,

    /// Export recovered hashes to CSV (.csv) or JSON (.json) file
    #[arg(long, help_heading = "Output")]
    pub export: Option<PathBuf>,

    /// Save session for later resumption (stored in ~/.crack-ng/sessions/)
    #[arg(long, help_heading = "Session")]
    pub session: Option<String>,

    /// Resume a previously saved session by name
    #[arg(long, help_heading = "Session")]
    pub resume: Option<String>,

    /// Smart cascade attack: potfile -> wordlist+rules -> masks -> brute-force
    #[arg(long, help_heading = "Attack")]
    pub cascade: bool,

    /// Input format hint: auto, ntds, shadow, kerberoast, asrep, responder
    #[arg(long, default_value = "auto", help_heading = "Input")]
    pub format: String,

    /// Generate styled HTML post-crack analysis report
    #[arg(long, help_heading = "Output")]
    pub report: Option<PathBuf>,

    /// List all 60+ supported hash types with hashcat/JtR modes, then exit
    #[arg(long, help_heading = "Info")]
    pub list_modes: bool,

    /// Extra directories to scan for wordlists (recursive). Repeatable.
    /// Also reads CRACK_NG_WORDLIST_DIRS (colon-separated paths).
    #[arg(long, value_name = "DIR", help_heading = "Input")]
    pub wordlist_dir: Vec<PathBuf>,

    /// Scan system for available wordlists and rule files, then exit
    #[arg(long, help_heading = "Info")]
    pub discover_wordlists: bool,

    /// Identify hash types in a file or hash string, then exit (no cracking)
    #[arg(long, help_heading = "Info")]
    pub identify: bool,

    /// Extra arguments passed directly to the cracking engine (after --)
    #[arg(last = true, help_heading = "Engine")]
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
    // Order matters: iter().find() returns first match. SPECIFIC patterns (unique
    // prefixes like $6$, $2a$, $krb5tgs$) MUST come BEFORE generic fixed-length
    // hex patterns (MD5 32, SHA1 40, etc.) to avoid misidentification.
    //
    // 62 signature types covering ~95% of real-world pentesting encounters.
    // Ambiguous fixed-length hex (32/40/64/128 chars) defaults to the most common
    // algorithm; use --mode to override for rarer variants.
    pub static ref SIGNATURES: Vec<HashSignature> = vec![
        // === Bcrypt ===
        HashSignature { name: "Bcrypt ($2*)", regex: Regex::new(r"^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$").unwrap(), hashcat_mode: Some("3200"), jtr_format: Some("bcrypt") },

        // === Unix crypt family ===
        HashSignature { name: "Linux SHA-512 crypt", regex: Regex::new(r"^\$6\$(rounds=\d+\$)?[a-zA-Z0-9./]+\$[a-zA-Z0-9./]{86}$").unwrap(), hashcat_mode: Some("1800"), jtr_format: Some("sha512crypt") },
        HashSignature { name: "Linux SHA-256 crypt", regex: Regex::new(r"^\$5\$(rounds=\d+\$)?[a-zA-Z0-9./]+\$[a-zA-Z0-9./]{43}$").unwrap(), hashcat_mode: Some("7400"), jtr_format: Some("sha256crypt") },
        HashSignature { name: "Linux yescrypt", regex: Regex::new(r"^\$y\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+$").unwrap(), hashcat_mode: None, jtr_format: Some("yescrypt") },

        // === Modern KDFs ===
        HashSignature { name: "Argon2id", regex: Regex::new(r"^\$argon2id\$").unwrap(), hashcat_mode: None, jtr_format: Some("argon2") },
        HashSignature { name: "Argon2i", regex: Regex::new(r"^\$argon2i\$").unwrap(), hashcat_mode: None, jtr_format: Some("argon2") },
        HashSignature { name: "Argon2d", regex: Regex::new(r"^\$argon2d\$").unwrap(), hashcat_mode: None, jtr_format: Some("argon2") },
        HashSignature { name: "scrypt ($7$)", regex: Regex::new(r"^\$7\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+$").unwrap(), hashcat_mode: Some("8900"), jtr_format: Some("scrypt") },

        // === PHP / Web application ===
        HashSignature { name: "phpass (WordPress/Joomla)", regex: Regex::new(r"^\$[PH]\$[./0-9A-Za-z]{31}$").unwrap(), hashcat_mode: Some("400"), jtr_format: Some("phpass") },
        HashSignature { name: "Apache APR1", regex: Regex::new(r"^\$apr1\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]{22}$").unwrap(), hashcat_mode: Some("1600"), jtr_format: Some("md5apr1") },
        HashSignature { name: "Django PBKDF2-SHA256", regex: Regex::new(r"^pbkdf2_sha256\$\d+\$[a-zA-Z0-9+/=]+\$[a-zA-Z0-9+/=]+$").unwrap(), hashcat_mode: Some("10000"), jtr_format: Some("PBKDF2-HMAC-SHA256") },
        HashSignature { name: "EPiServer", regex: Regex::new(r"^\$episerver\$").unwrap(), hashcat_mode: Some("141"), jtr_format: None },

        // === Cisco ===
        HashSignature { name: "Cisco IOS Type 5", regex: Regex::new(r"^\$1\$[a-zA-Z0-9./]{4}\$[a-zA-Z0-9./]{22}$").unwrap(), hashcat_mode: Some("500"), jtr_format: Some("md5crypt") },
        HashSignature { name: "Cisco Type 8 (PBKDF2-SHA256)", regex: Regex::new(r"^\$8\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+$").unwrap(), hashcat_mode: Some("9200"), jtr_format: Some("cisco8") },
        HashSignature { name: "Cisco Type 9 (scrypt)", regex: Regex::new(r"^\$9\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+$").unwrap(), hashcat_mode: Some("9300"), jtr_format: Some("cisco9") },
        HashSignature { name: "MD5 Crypt", regex: Regex::new(r"^\$1\$[a-zA-Z0-9./]{1,8}\$[a-zA-Z0-9./]{22}$").unwrap(), hashcat_mode: Some("500"), jtr_format: Some("md5crypt") },

        // === Kerberos / Active Directory ===
        HashSignature { name: "Kerberos 5 TGS-REP", regex: Regex::new(r"^\$krb5tgs\$").unwrap(), hashcat_mode: Some("13100"), jtr_format: Some("krb5tgs") },
        HashSignature { name: "Kerberos 5 AS-REP", regex: Regex::new(r"^\$krb5asrep\$").unwrap(), hashcat_mode: Some("18200"), jtr_format: Some("krb5asrep") },
        HashSignature { name: "Kerberos 5 Pre-Auth etype 23", regex: Regex::new(r"^\$krb5pa\$23\$").unwrap(), hashcat_mode: Some("7500"), jtr_format: Some("krb5pa-md5") },
        HashSignature { name: "Domain Cached Credentials 2", regex: Regex::new(r"^\$DCC2\$\d+#[^#]+#[a-fA-F0-9]{32}$").unwrap(), hashcat_mode: Some("2100"), jtr_format: Some("mscach2") },

        // === LDAP (longer prefixes first to avoid partial matches) ===
        HashSignature { name: "LDAP SSHA512", regex: Regex::new(r"(?i)^\{SSHA512\}[a-zA-Z0-9+/=]+$").unwrap(), hashcat_mode: Some("1711"), jtr_format: Some("ssha512") },
        HashSignature { name: "LDAP SSHA256", regex: Regex::new(r"(?i)^\{SSHA256\}[a-zA-Z0-9+/=]+$").unwrap(), hashcat_mode: Some("1411"), jtr_format: Some("ssha256") },
        HashSignature { name: "LDAP SHA512", regex: Regex::new(r"(?i)^\{SHA512\}[a-zA-Z0-9+/=]+$").unwrap(), hashcat_mode: Some("1700"), jtr_format: Some("raw-sha512") },
        HashSignature { name: "LDAP SHA256", regex: Regex::new(r"(?i)^\{SHA256\}[a-zA-Z0-9+/=]+$").unwrap(), hashcat_mode: Some("1400"), jtr_format: Some("raw-sha256") },
        HashSignature { name: "LDAP SSHA", regex: Regex::new(r"(?i)^\{SSHA\}[a-zA-Z0-9+/=]+$").unwrap(), hashcat_mode: Some("111"), jtr_format: Some("nsldaps") },
        HashSignature { name: "LDAP SHA", regex: Regex::new(r"(?i)^\{SHA\}[a-zA-Z0-9+/=]+$").unwrap(), hashcat_mode: Some("101"), jtr_format: Some("nsldap") },

        // === GRUB / Boot ===
        HashSignature { name: "GRUB PBKDF2-SHA512", regex: Regex::new(r"^grub\.pbkdf2\.sha512\.\d+\.[a-fA-F0-9]+\.[a-fA-F0-9]+$").unwrap(), hashcat_mode: Some("7200"), jtr_format: None },

        // === Blockchain / Cryptocurrency ===
        HashSignature { name: "Bitcoin/Litecoin wallet", regex: Regex::new(r"^\$bitcoin\$").unwrap(), hashcat_mode: Some("11300"), jtr_format: Some("bitcoin") },
        HashSignature { name: "Blockchain.info wallet", regex: Regex::new(r"^\$blockchain\$").unwrap(), hashcat_mode: Some("12700"), jtr_format: Some("blockchain") },
        HashSignature { name: "Ethereum wallet", regex: Regex::new(r"^\$ethereum\$").unwrap(), hashcat_mode: Some("15600"), jtr_format: Some("ethereum") },

        // === Encrypted archives ===
        HashSignature { name: "RAR3", regex: Regex::new(r"^\$RAR3\$").unwrap(), hashcat_mode: Some("12500"), jtr_format: Some("rar") },
        HashSignature { name: "RAR5", regex: Regex::new(r"^\$RAR5\$").unwrap(), hashcat_mode: Some("13000"), jtr_format: Some("rar5") },
        HashSignature { name: "7-Zip", regex: Regex::new(r"^\$7z\$").unwrap(), hashcat_mode: Some("11600"), jtr_format: Some("7z") },
        HashSignature { name: "KeePass", regex: Regex::new(r"^\$keepass\$").unwrap(), hashcat_mode: Some("13400"), jtr_format: None },
        HashSignature { name: "WinZip ($zip2$)", regex: Regex::new(r"^\$zip2\$").unwrap(), hashcat_mode: Some("13600"), jtr_format: Some("ZIP") },
        HashSignature { name: "PKZIP", regex: Regex::new(r"^\$pkzip2?\$").unwrap(), hashcat_mode: Some("17200"), jtr_format: Some("pkzip") },

        // === Encrypted documents ===
        HashSignature { name: "PDF", regex: Regex::new(r"^\$pdf\$").unwrap(), hashcat_mode: Some("10500"), jtr_format: Some("pdf") },
        HashSignature { name: "MS Office 2013+", regex: Regex::new(r"^\$office\$\*2013").unwrap(), hashcat_mode: Some("9600"), jtr_format: Some("office") },
        HashSignature { name: "MS Office 2010", regex: Regex::new(r"^\$office\$\*2010").unwrap(), hashcat_mode: Some("9500"), jtr_format: Some("office") },
        HashSignature { name: "MS Office 2007", regex: Regex::new(r"^\$office\$\*2007").unwrap(), hashcat_mode: Some("9400"), jtr_format: Some("office") },
        HashSignature { name: "MS Office 97-2003", regex: Regex::new(r"^\$oldoffice\$").unwrap(), hashcat_mode: Some("9700"), jtr_format: Some("oldoffice") },

        // === Disk encryption ===
        HashSignature { name: "BitLocker", regex: Regex::new(r"^\$bitlocker\$").unwrap(), hashcat_mode: Some("22100"), jtr_format: Some("bitlocker") },
        HashSignature { name: "FileVault 2", regex: Regex::new(r"^\$fvde\$").unwrap(), hashcat_mode: Some("16700"), jtr_format: Some("fvde2") },
        HashSignature { name: "TrueCrypt", regex: Regex::new(r"^\$truecrypt\$").unwrap(), hashcat_mode: None, jtr_format: Some("tc_aes_xts") },
        HashSignature { name: "VeraCrypt", regex: Regex::new(r"^\$veracrypt\$").unwrap(), hashcat_mode: None, jtr_format: Some("vc") },
        HashSignature { name: "LUKS", regex: Regex::new(r"^\$luks\$").unwrap(), hashcat_mode: Some("14600"), jtr_format: None },

        // === Other encryption / authentication ===
        HashSignature { name: "GPG/PGP", regex: Regex::new(r"^\$gpg\$").unwrap(), hashcat_mode: Some("17010"), jtr_format: Some("gpg") },
        HashSignature { name: "Ansible Vault", regex: Regex::new(r"^\$ansible\$").unwrap(), hashcat_mode: Some("16900"), jtr_format: Some("ansible") },

        // === Structured colon-delimited patterns ===
        // LM:NT pair -- hashcat -m 1000 expects bare NT hash, not the pair. Force JtR which
        // handles the colon format natively. Secretsdump parser extracts bare NTLM for hashcat.
        HashSignature { name: "NTLM (LM:NT pair)", regex: Regex::new(r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$").unwrap(), hashcat_mode: None, jtr_format: Some("nt") },
        // NetNTLM: use [^\s:]+ for user/domain to support dotted names (CORP.LOCAL) and hyphens
        HashSignature { name: "NetNTLMv2", regex: Regex::new(r"^[^\s:]+::[^\s:]+:[a-fA-F0-9]{16}:[a-fA-F0-9]{32}:[a-fA-F0-9]+$").unwrap(), hashcat_mode: Some("5600"), jtr_format: Some("netntlmv2") },
        HashSignature { name: "NetNTLMv1", regex: Regex::new(r"^[^\s:]+::[^\s:]+:[a-fA-F0-9]{48}:[a-fA-F0-9]{48}:[a-fA-F0-9]+$").unwrap(), hashcat_mode: Some("5500"), jtr_format: Some("netntlm") },
        // WPA/WPA2 hashcat 22000 format: WPA*TYPE*PMKID/MIC*MAC_AP*MAC_STA*ESSID*...
        HashSignature { name: "WPA/WPA2 (hashcat 22000)", regex: Regex::new(r"^WPA\*[0-9]{2}\*[a-fA-F0-9]+\*[a-fA-F0-9]{12}\*[a-fA-F0-9]{12}\*").unwrap(), hashcat_mode: Some("22000"), jtr_format: None },

        // === Prefix-identified hex patterns ===
        HashSignature { name: "MSSQL 2012+", regex: Regex::new(r"^0x0200[a-fA-F0-9]+$").unwrap(), hashcat_mode: Some("1731"), jtr_format: Some("mssql12") },
        HashSignature { name: "MSSQL 2005", regex: Regex::new(r"^0x0100[a-fA-F0-9]+$").unwrap(), hashcat_mode: Some("132"), jtr_format: Some("mssql05") },
        HashSignature { name: "MySQL 4.1+", regex: Regex::new(r"^\*[a-fA-F0-9]{40}$").unwrap(), hashcat_mode: Some("300"), jtr_format: Some("mysql-sha1") },
        HashSignature { name: "Oracle 11g", regex: Regex::new(r"^S:[a-fA-F0-9]{60}$").unwrap(), hashcat_mode: Some("112"), jtr_format: Some("oracle11") },

        // === Generic fixed-length hex (most ambiguous, checked last) ===
        // These default to the most common algorithm for each length.
        // 32-char hex could also be: NTLM (1000), MD4 (900), LM (3000), DCC1 (1100)
        // 40-char hex could also be: MySQL 3.2.3 (200), RIPEMD-160 (6000)
        // 64-char hex could also be: SHA3-256 (17400), Keccak-256 (17800)
        // 96-char hex is effectively unambiguous (only SHA3-384 is an alternative)
        // 128-char hex could also be: SHA3-512 (17600), Whirlpool (6100)
        // Use --mode (-m) to override for rarer variants.
        HashSignature { name: "DES Crypt", regex: Regex::new(r"^[a-zA-Z0-9./]{13}$").unwrap(), hashcat_mode: Some("1500"), jtr_format: Some("descrypt") },
        HashSignature { name: "SHA-512", regex: Regex::new(r"^[a-fA-F0-9]{128}$").unwrap(), hashcat_mode: Some("1700"), jtr_format: Some("raw-sha512") },
        HashSignature { name: "SHA-384", regex: Regex::new(r"^[a-fA-F0-9]{96}$").unwrap(), hashcat_mode: Some("10800"), jtr_format: Some("raw-sha384") },
        HashSignature { name: "SHA-256", regex: Regex::new(r"^[a-fA-F0-9]{64}$").unwrap(), hashcat_mode: Some("1400"), jtr_format: Some("raw-sha256") },
        HashSignature { name: "SHA-1", regex: Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(), hashcat_mode: Some("100"), jtr_format: Some("raw-sha1") },
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
    /// Raw ETA in seconds for the current attack (for stage-level calculations)
    #[serde(default)]
    pub eta_seconds: i64,
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
    /// Epoch seconds when overall_status became "Finished". Freezes uptime/duration.
    #[serde(default)]
    pub end_time: Option<i64>,
    #[serde(default)]
    pub cascade_stage: Option<String>,
    #[serde(default)]
    pub cascade_plan: Vec<String>,
    /// Last completed cascade stage index (for resume). 0 = none completed.
    #[serde(default)]
    pub cascade_completed_idx: usize,
    /// Per-stage timing: (start_epoch, Option<end_epoch>) for each cascade stage.
    /// Index corresponds to stage index in cascade_plan.
    #[serde(default)]
    pub stage_times: Vec<(i64, Option<i64>)>,
    /// Current stage attack progress: (completed, total, last_completion_epoch).
    /// last_completion_epoch is used to compute per-attack average without clock drift.
    #[serde(skip)]
    pub stage_attack_progress: (usize, usize, i64),
    /// User requested skipping the current cascade stage via 'N' keybind.
    #[serde(skip)]
    pub skip_stage_requested: bool,
    /// PID of the active child process (hashcat/john). Used to kill on quit.
    #[serde(skip)]
    pub active_child_pid: Option<u32>,
    /// User requested quit -- signals orchestrator to terminate child and stop.
    #[serde(skip)]
    pub quit_requested: bool,
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
    /// Cached report text and the recovered count when it was generated
    #[serde(skip)]
    pub cached_report_text: Option<(usize, String)>,
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
