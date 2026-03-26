use std::collections::HashMap;

/// Analyze a set of cracked passwords and return the most common hashcat mask
/// patterns, suitable for feeding into a MaskAttack cascade stage.
pub fn analyze_cracked_passwords(passwords: &[String]) -> Vec<String> {
    let mut mask_counts: HashMap<String, usize> = HashMap::new();

    for pw in passwords {
        let mask = password_to_mask(pw);
        *mask_counts.entry(mask).or_insert(0) += 1;
    }

    // Generate smart structural masks from observed patterns
    let structural_masks = generate_structural_masks(passwords);
    for m in &structural_masks {
        mask_counts.entry(m.clone()).or_insert(1);
    }

    // Sort by frequency descending, take top 20
    let mut ranked: Vec<(String, usize)> = mask_counts.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1));
    ranked.truncate(20);

    ranked.into_iter().map(|(mask, _)| mask).collect()
}

/// Convert a plaintext password into a hashcat mask string.
/// Each character maps to its character class:
///   ?u = uppercase, ?l = lowercase, ?d = digit, ?s = special
fn password_to_mask(password: &str) -> String {
    let mut mask = String::with_capacity(password.len() * 2);
    for ch in password.chars() {
        if ch.is_ascii_uppercase() {
            mask.push_str("?u");
        } else if ch.is_ascii_lowercase() {
            mask.push_str("?l");
        } else if ch.is_ascii_digit() {
            mask.push_str("?d");
        } else {
            mask.push_str("?s");
        }
    }
    mask
}

/// Generate "smart" masks based on common password construction patterns
/// observed in the cracked set.
fn generate_structural_masks(passwords: &[String]) -> Vec<String> {
    let mut extra_masks = Vec::new();

    for pw in passwords {
        let structure = classify_structure(pw);

        match structure.as_str() {
            // Season+Year+Special: "Summer2024!" -> all season/year combos
            "word_year_special" | "word_year" => {
                // Ucfirst word (4-8 chars) + 4 digits + optional special
                for word_len in 4..=8 {
                    let word_mask: String = std::iter::once("?u")
                        .chain(std::iter::repeat("?l").take(word_len - 1))
                        .collect::<Vec<_>>()
                        .join("");
                    extra_masks.push(format!("{}?d?d?d?d", word_mask));
                    extra_masks.push(format!("{}?d?d?d?d?s", word_mask));
                }
            }
            // Word+Digits: "Company123" -> Ucfirst + 2-4 digits
            "word_digits" => {
                let alpha_len = pw.chars().take_while(|c| c.is_ascii_alphabetic()).count();
                if alpha_len >= 3 {
                    let word_mask: String = std::iter::once("?u")
                        .chain(std::iter::repeat("?l").take(alpha_len - 1))
                        .collect::<Vec<_>>()
                        .join("");
                    for d in 1..=4 {
                        let digits: String =
                            std::iter::repeat("?d").take(d).collect::<Vec<_>>().join("");
                        extra_masks.push(format!("{}{}", word_mask, digits));
                    }
                }
            }
            _ => {}
        }
    }

    // Deduplicate
    extra_masks.sort();
    extra_masks.dedup();
    extra_masks.truncate(30);
    extra_masks
}

/// Classify the high-level structure of a password.
fn classify_structure(password: &str) -> String {
    let chars: Vec<char> = password.chars().collect();
    if chars.is_empty() {
        return "empty".to_string();
    }

    let has_alpha_prefix = chars
        .first()
        .map(|c| c.is_ascii_alphabetic())
        .unwrap_or(false);

    if has_alpha_prefix {
        let alpha_end = chars
            .iter()
            .position(|c| !c.is_ascii_alphabetic())
            .unwrap_or(chars.len());
        let rest = &chars[alpha_end..];

        if rest.is_empty() {
            return "word_only".to_string();
        }

        let digit_count = rest.iter().take_while(|c| c.is_ascii_digit()).count();
        let after_digits = &rest[digit_count..];

        if digit_count == 4 && after_digits.is_empty() {
            return "word_year".to_string();
        }
        if digit_count == 4 && after_digits.len() == 1 && !after_digits[0].is_ascii_alphanumeric() {
            return "word_year_special".to_string();
        }
        if digit_count > 0 && after_digits.is_empty() {
            return "word_digits".to_string();
        }
        if digit_count > 0 {
            return "word_digits_mixed".to_string();
        }
        return "word_mixed".to_string();
    }

    if chars.iter().all(|c| c.is_ascii_digit()) {
        return "all_digits".to_string();
    }

    "mixed".to_string()
}
