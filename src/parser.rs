/// Input format parsers for common offensive tool output.
/// Handles secretsdump, shadow, kerberoast, AS-REP roast, and Responder logs.

#[derive(Debug, Clone, PartialEq)]
pub enum InputFormat {
    RawHashes,
    SecretsDump,
    Shadow,
    Kerberoast,
    AsrepRoast,
    Responder,
}

#[derive(Debug, Clone)]
pub struct ParsedHash {
    pub hash: String,
    pub username: Option<String>,
    pub domain: Option<String>,
    pub original_line: String,
    /// Format-aware algorithm hint. When set, bypasses regex matching.
    /// Tuple: (algo_name, hashcat_mode, jtr_format)
    pub forced_algo: Option<(&'static str, &'static str, &'static str)>,
}

/// Empty NTLM hash (disabled/blank password accounts).
const EMPTY_NTLM: &str = "31d6cfe0d16ae931b73c59d7e0c089c0";
/// Empty LM hash.
const EMPTY_LM: &str = "aad3b435b51404eeaad3b435b51404ee";

pub fn detect_format(content: &str) -> InputFormat {
    let sample_lines: Vec<&str> = content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .take(20)
        .collect();

    if sample_lines.is_empty() {
        return InputFormat::RawHashes;
    }

    // Check for secretsdump format: user:rid:lmhash:ntlmhash:::
    let secretsdump_count = sample_lines
        .iter()
        .filter(|line| {
            let parts: Vec<&str> = line.split(':').collect();
            parts.len() >= 7
                && parts[1].chars().all(|c| c.is_ascii_digit())
                && parts[2].len() == 32
                && parts[3].len() == 32
        })
        .count();
    if secretsdump_count > sample_lines.len() / 2 {
        return InputFormat::SecretsDump;
    }

    // Check for shadow format: user:$type$salt$hash:...
    let shadow_count = sample_lines
        .iter()
        .filter(|line| {
            let parts: Vec<&str> = line.split(':').collect();
            parts.len() >= 2
                && (parts[1].starts_with("$6$")
                    || parts[1].starts_with("$5$")
                    || parts[1].starts_with("$y$")
                    || parts[1].starts_with("$1$")
                    || parts[1].starts_with("$2"))
        })
        .count();
    if shadow_count > sample_lines.len() / 2 {
        return InputFormat::Shadow;
    }

    // Check for Kerberoast: lines starting with $krb5tgs$
    let kerb_count = sample_lines
        .iter()
        .filter(|l| l.starts_with("$krb5tgs$"))
        .count();
    if kerb_count > 0 {
        return InputFormat::Kerberoast;
    }

    // Check for AS-REP roast: lines starting with $krb5asrep$
    let asrep_count = sample_lines
        .iter()
        .filter(|l| l.starts_with("$krb5asrep$"))
        .count();
    if asrep_count > 0 {
        return InputFormat::AsrepRoast;
    }

    // Check for Responder format: user::domain:challenge:hash:blob
    // Validate that parts[3] (server challenge) is exactly 16 hex characters.
    let responder_count = sample_lines
        .iter()
        .filter(|line| {
            let parts: Vec<&str> = line.split(':').collect();
            parts.len() >= 6
                && parts[1].is_empty()
                && parts[3].len() == 16
                && parts[3].chars().all(|c| c.is_ascii_hexdigit())
        })
        .count();
    if responder_count > sample_lines.len() / 2 {
        return InputFormat::Responder;
    }

    InputFormat::RawHashes
}

pub fn parse_format_arg(arg: &str) -> InputFormat {
    match arg.to_lowercase().as_str() {
        "ntds" | "secretsdump" => InputFormat::SecretsDump,
        "shadow" => InputFormat::Shadow,
        "kerberoast" | "krb5tgs" => InputFormat::Kerberoast,
        "asrep" | "krb5asrep" => InputFormat::AsrepRoast,
        "responder" | "netntlm" => InputFormat::Responder,
        "raw" => InputFormat::RawHashes,
        _ => InputFormat::RawHashes, // "auto" handled by caller
    }
}

pub fn parse_input(content: &str, format: InputFormat) -> Vec<ParsedHash> {
    match format {
        InputFormat::RawHashes => parse_raw(content),
        InputFormat::SecretsDump => parse_secretsdump(content),
        InputFormat::Shadow => parse_shadow(content),
        InputFormat::Kerberoast => parse_kerberoast(content),
        InputFormat::AsrepRoast => parse_asrep(content),
        InputFormat::Responder => parse_responder(content),
    }
}

fn parse_raw(content: &str) -> Vec<ParsedHash> {
    content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .map(|l| ParsedHash {
            hash: l.to_string(),
            username: None,
            domain: None,
            original_line: l.to_string(),
            forced_algo: None,
        })
        .collect()
}

fn parse_secretsdump(content: &str) -> Vec<ParsedHash> {
    let mut results = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Format: user:rid:lm:ntlm:::
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 4 {
            continue;
        }

        let username = parts[0];
        let lm_hash = parts[2];
        let ntlm_hash = parts[3];

        // Skip machine accounts (ending in $)
        if username.ends_with('$') {
            continue;
        }

        // Skip empty/disabled NTLM hashes
        if ntlm_hash.to_lowercase() == EMPTY_NTLM {
            continue;
        }

        // Extract domain if present (DOMAIN\user or user@domain)
        let (domain, clean_user) = if let Some(pos) = username.find('\\') {
            (
                Some(username[..pos].to_string()),
                username[pos + 1..].to_string(),
            )
        } else if let Some(pos) = username.find('@') {
            (
                Some(username[pos + 1..].to_string()),
                username[..pos].to_string(),
            )
        } else {
            (None, username.to_string())
        };

        results.push(ParsedHash {
            hash: ntlm_hash.to_string(),
            username: Some(clean_user.clone()),
            domain: domain.clone(),
            original_line: line.to_string(),
            forced_algo: Some(("NTLM", "1000", "nt")),
        });

        if lm_hash.to_lowercase() != EMPTY_LM && !lm_hash.is_empty() {
            results.push(ParsedHash {
                hash: lm_hash.to_string(),
                username: Some(clean_user),
                domain,
                original_line: line.to_string(),
                forced_algo: Some(("LM", "3000", "lm")),
            });
        }
    }

    results
}

fn parse_shadow(content: &str) -> Vec<ParsedHash> {
    let mut results = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 2 {
            continue;
        }

        let username = parts[0];
        let hash = parts[1];

        // Skip locked/disabled accounts
        if hash.is_empty() || hash == "*" || hash == "!" || hash == "!!" || hash.starts_with('!') {
            continue;
        }

        // Skip NP (no password) entries
        if hash == "NP" || hash == "x" {
            continue;
        }

        results.push(ParsedHash {
            hash: hash.to_string(),
            username: Some(username.to_string()),
            domain: None,
            original_line: line.to_string(),
            forced_algo: None,
        });
    }

    results
}

fn parse_kerberoast(content: &str) -> Vec<ParsedHash> {
    let mut results = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if !line.starts_with("$krb5tgs$") {
            continue;
        }

        // Format: $krb5tgs$23$*user$DOMAIN$spn*$hash...
        // Or: $krb5tgs$23$user@DOMAIN:hash
        let username = extract_kerberos_username(line);
        let domain = extract_kerberos_domain(line);

        results.push(ParsedHash {
            hash: line.to_string(),
            username,
            domain,
            original_line: line.to_string(),
            forced_algo: None,
        });
    }

    results
}

fn parse_asrep(content: &str) -> Vec<ParsedHash> {
    let mut results = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if !line.starts_with("$krb5asrep$") {
            continue;
        }

        let username = extract_kerberos_username(line);
        let domain = extract_kerberos_domain(line);

        results.push(ParsedHash {
            hash: line.to_string(),
            username,
            domain,
            original_line: line.to_string(),
            forced_algo: None,
        });
    }

    results
}

fn parse_responder(content: &str) -> Vec<ParsedHash> {
    let mut results = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Format: user::domain:challenge:hash:blob
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 6 {
            continue;
        }

        let username = if parts[0].is_empty() {
            None
        } else {
            Some(parts[0].to_string())
        };
        let domain = if parts[2].is_empty() {
            None
        } else {
            Some(parts[2].to_string())
        };

        results.push(ParsedHash {
            hash: line.to_string(),
            username,
            domain,
            original_line: line.to_string(),
            forced_algo: Some(("NetNTLMv2", "5600", "netntlmv2")),
        });
    }

    results
}

fn extract_kerberos_username(hash: &str) -> Option<String> {
    // Try $krb5tgs$23$*user$DOMAIN$spn*$... format
    if let Some(start) = hash.find("$*") {
        let rest = &hash[start + 2..];
        if let Some(end) = rest.find('$') {
            let user = &rest[..end];
            if !user.is_empty() {
                return Some(user.to_string());
            }
        }
    }
    // Try $krb5tgs$23$user@DOMAIN:... format
    if let Some(dollar_pos) = hash.rfind('$') {
        let rest = &hash[dollar_pos + 1..];
        if let Some(at_pos) = rest.find('@') {
            let user = &rest[..at_pos];
            if !user.is_empty() {
                return Some(user.to_string());
            }
        } else if let Some(colon_pos) = rest.find(':') {
            let user = &rest[..colon_pos];
            if !user.is_empty() {
                return Some(user.to_string());
            }
        }
    }
    None
}

fn extract_kerberos_domain(hash: &str) -> Option<String> {
    // Try $krb5tgs$23$*user$DOMAIN$spn*$... format
    if let Some(start) = hash.find("$*") {
        let rest = &hash[start + 2..];
        if let Some(first_dollar) = rest.find('$') {
            let after_user = &rest[first_dollar + 1..];
            if let Some(next_dollar) = after_user.find('$') {
                let domain = &after_user[..next_dollar];
                if !domain.is_empty() {
                    return Some(domain.to_string());
                }
            }
        }
    }
    // Try user@DOMAIN format
    if let Some(at_pos) = hash.find('@') {
        let rest = &hash[at_pos + 1..];
        if let Some(colon_pos) = rest.find(':') {
            let domain = &rest[..colon_pos];
            if !domain.is_empty() {
                return Some(domain.to_string());
            }
        }
    }
    None
}
