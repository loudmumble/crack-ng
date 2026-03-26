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

pub fn build_default_cascade(wordlists: &[WordlistInfo], rules: &[PathBuf]) -> CascadeConfig {
    let mut stages = vec![CascadeStage::PotfileCheck];

    // Stage 1: Best wordlist + fast rules (best64.rule)
    if let Some(wl) = wordlists.first() {
        let fast_rule = rules
            .iter()
            .find(|r| r.file_name().map(|f| f == "best64.rule").unwrap_or(false));
        stages.push(CascadeStage::WordlistAttack {
            wordlist: wl.path.clone(),
            rules: fast_rule.cloned(),
        });
    }

    // Stage 2: Best wordlist + deep rules (dive.rule)
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

    // Stage 3: Common password masks
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

    // Stage 4: Incremental brute force
    stages.push(CascadeStage::IncrementalBrute {
        min_len: 1,
        max_len: 8,
        charset: "?a".into(),
    });

    CascadeConfig { stages }
}

/// Insert dynamically-generated masks from cracked password analysis into an
/// existing cascade config. Merges them into any existing MaskAttack stage,
/// or appends a new MaskAttack stage before the brute-force stage.
pub fn inject_dynamic_masks(config: &mut CascadeConfig, masks: Vec<String>) {
    if masks.is_empty() {
        return;
    }

    // Try to find an existing MaskAttack stage and extend it
    for stage in &mut config.stages {
        if let CascadeStage::MaskAttack { masks: existing } = stage {
            for m in &masks {
                if !existing.contains(m) {
                    existing.push(m.clone());
                }
            }
            return;
        }
    }

    // No existing mask stage found -- insert before brute force
    let insert_pos = config
        .stages
        .iter()
        .position(|s| matches!(s, CascadeStage::IncrementalBrute { .. }))
        .unwrap_or(config.stages.len());

    config
        .stages
        .insert(insert_pos, CascadeStage::MaskAttack { masks });
}
