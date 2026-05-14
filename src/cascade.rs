use crate::wordlist::WordlistInfo;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct CascadeConfig {
    pub stages: Vec<CascadeStage>,
}

#[derive(Debug, Clone)]
pub enum CascadeStage {
    PotfileCheck,
    WordlistAttack {
        wordlist: PathBuf,
        rules: Option<PathBuf>,
    },
    MaskAttack {
        masks: Vec<String>,
    },
    IncrementalBrute {
        min_len: u8,
        max_len: u8,
        charset: String,
    },
}

pub fn build_default_cascade(
    user_wordlist: Option<&PathBuf>,
    wordlists: &[WordlistInfo],
    rules: &[PathBuf],
) -> CascadeConfig {
    let mut stages = vec![CascadeStage::PotfileCheck];

    // Stage 1: User-provided wordlist (no rules -- raw, as the user intended)
    if let Some(wl) = user_wordlist {
        stages.push(CascadeStage::WordlistAttack {
            wordlist: wl.clone(),
            rules: None,
        });
    }

    // Stage 2: Best auto-discovered wordlist + fast rules (best64.rule)
    if let Some(wl) = wordlists.first() {
        // Skip if the user wordlist is the same file (avoid duplicate stage)
        let dominated = user_wordlist.is_some_and(|uw| {
            uw.canonicalize().ok() == wl.path.canonicalize().ok()
        });
        let fast_rule = rules
            .iter()
            .find(|r| r.file_name().map(|f| f == "best64.rule").unwrap_or(false));
        if !dominated || fast_rule.is_some() {
            stages.push(CascadeStage::WordlistAttack {
                wordlist: wl.path.clone(),
                rules: fast_rule.cloned(),
            });
        }
    }

    // Stage 3: Best auto-discovered wordlist + deep rules (dive.rule)
    if let Some(wl) = wordlists.first() {
        let deep_rule = rules
            .iter()
            .find(|r| r.file_name().map(|f| f == "dive.rule").unwrap_or(false));
        if deep_rule.is_some() {
            stages.push(CascadeStage::WordlistAttack {
                wordlist: wl.path.clone(),
                rules: deep_rule.cloned(),
            });
        }
    }

    // Common password masks
    stages.push(CascadeStage::MaskAttack {
        masks: vec![
            "?u?l?l?l?l?l?d?d".into(),
            "?u?l?l?l?l?l?l?d?d".into(),
            "?u?l?l?l?l?l?d?d?s".into(),
            "?u?l?l?l?l?l?l?d?d?d?d".into(),
            "?d?d?d?d?d?d".into(),
            "?d?d?d?d?d?d?d?d".into(),
        ],
    });

    // Incremental brute force (last resort)
    stages.push(CascadeStage::IncrementalBrute {
        min_len: 1,
        max_len: 8,
        charset: "?a".into(),
    });

    CascadeConfig { stages }
}

/// Insert dynamically-generated masks from cracked password analysis into an
/// existing cascade config. Only modifies stages AFTER `after_stage_idx` to avoid
/// injecting into already-executed stages.
pub fn inject_dynamic_masks(config: &mut CascadeConfig, masks: Vec<String>, after_stage_idx: usize) {
    if masks.is_empty() {
        return;
    }

    // Try to find an existing MaskAttack stage AFTER the current position
    for stage in config.stages.iter_mut().skip(after_stage_idx + 1) {
        if let CascadeStage::MaskAttack { masks: existing } = stage {
            for m in &masks {
                if !existing.contains(m) {
                    existing.push(m.clone());
                }
            }
            return;
        }
    }

    // No future mask stage found -- insert after current stage (before brute force if possible)
    let insert_pos = config
        .stages
        .iter()
        .skip(after_stage_idx + 1)
        .position(|s| matches!(s, CascadeStage::IncrementalBrute { .. }))
        .map(|p| p + after_stage_idx + 1)
        .unwrap_or(config.stages.len());

    config
        .stages
        .insert(insert_pos, CascadeStage::MaskAttack { masks });
}
