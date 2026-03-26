use crate::mask::analyze_cracked_passwords;
use crate::state::CrackState;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct CrackReport {
    pub total_hashes: usize,
    pub total_cracked: usize,
    pub crack_rate: f64,
    pub by_algorithm: Vec<AlgoStats>,
    pub length_distribution: Vec<(usize, usize)>,
    pub top_base_words: Vec<(String, usize)>,
    pub top_masks: Vec<(String, usize)>,
    pub policy_compliance: PolicyStats,
    pub duration: std::time::Duration,
}

#[derive(Debug, Clone)]
pub struct AlgoStats {
    pub name: String,
    pub total: usize,
    pub cracked: usize,
    pub rate: f64,
}

#[derive(Debug, Clone)]
pub struct PolicyStats {
    pub min_8_chars: f64,
    pub has_upper: f64,
    pub has_lower: f64,
    pub has_digit: f64,
    pub has_special: f64,
    pub meets_complexity: f64,
}

pub fn generate_report(state: &CrackState) -> CrackReport {
    // Total hashes = job hashes + potfile-only recoveries (not in any job)
    let job_hashes: usize = state.jobs.iter().map(|j| j.total_hashes).sum();
    let job_cracked: usize = state.jobs.iter().map(|j| j.cracked).sum();
    // Potfile-recovered hashes are in state.recovered but not in any job
    let potfile_only = state.recovered.len().saturating_sub(job_cracked);
    let total_hashes = job_hashes + potfile_only;
    let total_cracked = state.recovered.len();
    let crack_rate = if total_hashes > 0 {
        total_cracked as f64 / total_hashes as f64 * 100.0
    } else {
        0.0
    };

    let duration = if let Some(start) = state.start_time {
        let elapsed = chrono::Local::now().timestamp() - start;
        std::time::Duration::from_secs(elapsed.max(0) as u64)
    } else {
        std::time::Duration::from_secs(0)
    };

    // Per-algorithm stats
    let mut by_algorithm: Vec<AlgoStats> = state
        .jobs
        .iter()
        .map(|j| {
            let rate = if j.total_hashes > 0 {
                j.cracked as f64 / j.total_hashes as f64 * 100.0
            } else {
                0.0
            };
            AlgoStats {
                name: j.algo_name.clone(),
                total: j.total_hashes,
                cracked: j.cracked,
                rate,
            }
        })
        .collect();

    // Add potfile-only recoveries as a separate line if any exist
    if potfile_only > 0 {
        by_algorithm.insert(0, AlgoStats {
            name: "Potfile (pre-cracked)".to_string(),
            total: potfile_only,
            cracked: potfile_only,
            rate: 100.0,
        });
    }

    let plaintexts: Vec<String> = state
        .recovered
        .iter()
        .map(|r| r.plaintext.clone())
        .collect();

    // Length distribution
    let length_distribution = compute_length_distribution(&plaintexts);

    // Top base words (strip trailing digits/specials)
    let top_base_words = compute_base_words(&plaintexts);

    // Top masks
    let top_masks = compute_mask_frequency(&plaintexts);

    // Policy compliance
    let policy_compliance = compute_policy_stats(&plaintexts);

    CrackReport {
        total_hashes,
        total_cracked,
        crack_rate,
        by_algorithm,
        length_distribution,
        top_base_words,
        top_masks,
        policy_compliance,
        duration,
    }
}

fn compute_length_distribution(plaintexts: &[String]) -> Vec<(usize, usize)> {
    let mut dist: HashMap<usize, usize> = HashMap::new();
    for pw in plaintexts {
        *dist.entry(pw.len()).or_insert(0) += 1;
    }
    let mut sorted: Vec<(usize, usize)> = dist.into_iter().collect();
    sorted.sort_by_key(|&(len, _)| len);
    sorted
}

fn compute_base_words(plaintexts: &[String]) -> Vec<(String, usize)> {
    let mut words: HashMap<String, usize> = HashMap::new();
    for pw in plaintexts {
        let base = pw
            .chars()
            .take_while(|c| c.is_ascii_alphabetic())
            .collect::<String>()
            .to_lowercase();
        if base.len() >= 3 {
            *words.entry(base).or_insert(0) += 1;
        }
    }
    let mut sorted: Vec<(String, usize)> = words.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    sorted.truncate(15);
    sorted
}

fn compute_mask_frequency(plaintexts: &[String]) -> Vec<(String, usize)> {
    let masks = analyze_cracked_passwords(plaintexts);
    // Re-count actual frequency
    let mut freq: HashMap<String, usize> = HashMap::new();
    for pw in plaintexts {
        let mask = pw
            .chars()
            .map(|c| {
                if c.is_ascii_uppercase() {
                    "?u"
                } else if c.is_ascii_lowercase() {
                    "?l"
                } else if c.is_ascii_digit() {
                    "?d"
                } else {
                    "?s"
                }
            })
            .collect::<String>();
        *freq.entry(mask).or_insert(0) += 1;
    }
    let mut sorted: Vec<(String, usize)> = freq.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    sorted.truncate(15);
    // Make sure masks from analyze_cracked_passwords are also returned for cascade use
    let _ = masks;
    sorted
}

fn compute_policy_stats(plaintexts: &[String]) -> PolicyStats {
    if plaintexts.is_empty() {
        return PolicyStats {
            min_8_chars: 0.0,
            has_upper: 0.0,
            has_lower: 0.0,
            has_digit: 0.0,
            has_special: 0.0,
            meets_complexity: 0.0,
        };
    }

    let total = plaintexts.len() as f64;
    let mut count_8 = 0usize;
    let mut count_upper = 0usize;
    let mut count_lower = 0usize;
    let mut count_digit = 0usize;
    let mut count_special = 0usize;
    let mut count_complex = 0usize;

    for pw in plaintexts {
        let len_ok = pw.len() >= 8;
        let has_u = pw.chars().any(|c| c.is_ascii_uppercase());
        let has_l = pw.chars().any(|c| c.is_ascii_lowercase());
        let has_d = pw.chars().any(|c| c.is_ascii_digit());
        let has_s = pw.chars().any(|c| !c.is_ascii_alphanumeric());

        if len_ok {
            count_8 += 1;
        }
        if has_u {
            count_upper += 1;
        }
        if has_l {
            count_lower += 1;
        }
        if has_d {
            count_digit += 1;
        }
        if has_s {
            count_special += 1;
        }

        // 3-of-4 complexity + 8 chars
        let class_count = [has_u, has_l, has_d, has_s].iter().filter(|&&x| x).count();
        if len_ok && class_count >= 3 {
            count_complex += 1;
        }
    }

    PolicyStats {
        min_8_chars: count_8 as f64 / total * 100.0,
        has_upper: count_upper as f64 / total * 100.0,
        has_lower: count_lower as f64 / total * 100.0,
        has_digit: count_digit as f64 / total * 100.0,
        has_special: count_special as f64 / total * 100.0,
        meets_complexity: count_complex as f64 / total * 100.0,
    }
}

pub fn render_html(report: &CrackReport) -> String {
    let mut html = String::new();

    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"UTF-8\">\n");
    html.push_str("<title>crack-ng Post-Crack Report</title>\n<style>\n");
    html.push_str(REPORT_CSS);
    html.push_str("\n</style>\n</head>\n<body>\n");

    // Header
    html.push_str("<div class=\"container\">\n");
    html.push_str("<h1>crack-ng Password Audit Report</h1>\n");
    html.push_str(&format!(
        "<p class=\"meta\">Generated: {} | Duration: {}s</p>\n",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        report.duration.as_secs()
    ));

    // Summary box
    html.push_str("<div class=\"summary\">\n");
    html.push_str(&format!(
        "<div class=\"stat\"><span class=\"num\">{}</span><br>Total Hashes</div>\n",
        report.total_hashes
    ));
    html.push_str(&format!(
        "<div class=\"stat\"><span class=\"num cracked\">{}</span><br>Cracked</div>\n",
        report.total_cracked
    ));
    html.push_str(&format!(
        "<div class=\"stat\"><span class=\"num\">{:.1}%</span><br>Crack Rate</div>\n",
        report.crack_rate
    ));
    html.push_str("</div>\n");

    // Algorithm breakdown
    html.push_str("<h2>Algorithm Breakdown</h2>\n<table>\n");
    html.push_str(
        "<tr><th>Algorithm</th><th>Total</th><th>Cracked</th><th>Rate</th><th>Bar</th></tr>\n",
    );
    for algo in &report.by_algorithm {
        let bar_width = (algo.rate * 2.0).min(200.0);
        html.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{:.1}%</td><td><div class=\"bar\" style=\"width:{}px\"></div></td></tr>\n",
            algo.name, algo.total, algo.cracked, algo.rate, bar_width));
    }
    html.push_str("</table>\n");

    // Password length distribution
    html.push_str("<h2>Password Length Distribution</h2>\n<div class=\"histogram\">\n");
    let max_count = report
        .length_distribution
        .iter()
        .map(|&(_, c)| c)
        .max()
        .unwrap_or(1);
    for &(len, count) in &report.length_distribution {
        let bar_height = (count as f64 / max_count as f64 * 150.0) as u32;
        html.push_str(&format!(
            "<div class=\"hist-col\"><div class=\"hist-bar\" style=\"height:{}px\"></div><div class=\"hist-label\">{}</div></div>\n",
            bar_height, len));
    }
    html.push_str("</div>\n");

    // Top base words
    html.push_str("<h2>Top Base Words</h2>\n<table>\n<tr><th>Word</th><th>Count</th></tr>\n");
    for (word, count) in &report.top_base_words {
        html.push_str(&format!("<tr><td>{}</td><td>{}</td></tr>\n", word, count));
    }
    html.push_str("</table>\n");

    // Top masks
    html.push_str(
        "<h2>Top Password Patterns (Masks)</h2>\n<table>\n<tr><th>Mask</th><th>Count</th></tr>\n",
    );
    for (mask, count) in &report.top_masks {
        html.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td></tr>\n",
            mask, count
        ));
    }
    html.push_str("</table>\n");

    // Policy compliance
    let p = &report.policy_compliance;
    html.push_str("<h2>Password Policy Compliance</h2>\n<table>\n");
    html.push_str("<tr><th>Criterion</th><th>Percentage</th><th>Bar</th></tr>\n");
    let policy_rows = [
        ("8+ Characters", p.min_8_chars),
        ("Has Uppercase", p.has_upper),
        ("Has Lowercase", p.has_lower),
        ("Has Digit", p.has_digit),
        ("Has Special Character", p.has_special),
        ("Meets 3-of-4 + 8 chars", p.meets_complexity),
    ];
    for (label, pct) in &policy_rows {
        let bar_width = (pct * 2.0).min(200.0);
        let color = if *pct >= 80.0 {
            "#c0392b"
        } else if *pct >= 50.0 {
            "#e67e22"
        } else {
            "#27ae60"
        };
        html.push_str(&format!(
            "<tr><td>{}</td><td>{:.1}%</td><td><div class=\"bar\" style=\"width:{}px;background:{}\"></div></td></tr>\n",
            label, pct, bar_width, color));
    }
    html.push_str("</table>\n");
    html.push_str("<p class=\"note\">Policy: Higher percentages indicate MORE passwords that are easily cracked despite meeting that criterion.</p>\n");

    html.push_str("</div>\n</body>\n</html>");
    html
}

pub fn render_text(report: &CrackReport) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "crack-ng Post-Crack Report\n{}\n\n",
        "=".repeat(40)
    ));
    out.push_str(&format!("Duration:      {}s\n", report.duration.as_secs()));
    out.push_str(&format!("Total Hashes:  {}\n", report.total_hashes));
    out.push_str(&format!("Cracked:       {}\n", report.total_cracked));
    out.push_str(&format!("Crack Rate:    {:.1}%\n\n", report.crack_rate));

    out.push_str(&format!("Algorithm Breakdown\n{}\n", "-".repeat(30)));
    for algo in &report.by_algorithm {
        out.push_str(&format!(
            "  {:25} {}/{} ({:.1}%)\n",
            algo.name, algo.cracked, algo.total, algo.rate
        ));
    }
    out.push('\n');

    out.push_str(&format!("Password Lengths\n{}\n", "-".repeat(30)));
    for &(len, count) in &report.length_distribution {
        let bar: String =
            "#".repeat((count as f64 / report.total_cracked.max(1) as f64 * 40.0) as usize);
        out.push_str(&format!("  {:>2} chars: {:>4}  {}\n", len, count, bar));
    }
    out.push('\n');

    out.push_str(&format!("Top Base Words\n{}\n", "-".repeat(30)));
    for (word, count) in &report.top_base_words {
        out.push_str(&format!("  {:20} {}\n", word, count));
    }
    out.push('\n');

    out.push_str(&format!("Top Masks\n{}\n", "-".repeat(30)));
    for (mask, count) in &report.top_masks {
        out.push_str(&format!("  {:30} {}\n", mask, count));
    }
    out.push('\n');

    let p = &report.policy_compliance;
    out.push_str(&format!("Policy Compliance\n{}\n", "-".repeat(30)));
    out.push_str(&format!("  8+ Characters:       {:.1}%\n", p.min_8_chars));
    out.push_str(&format!("  Has Uppercase:       {:.1}%\n", p.has_upper));
    out.push_str(&format!("  Has Lowercase:       {:.1}%\n", p.has_lower));
    out.push_str(&format!("  Has Digit:           {:.1}%\n", p.has_digit));
    out.push_str(&format!("  Has Special:         {:.1}%\n", p.has_special));
    out.push_str(&format!(
        "  Meets Complexity:    {:.1}%\n",
        p.meets_complexity
    ));

    out
}

const REPORT_CSS: &str = r#"
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #1a1a2e; color: #e0e0e0; }
.container { max-width: 900px; margin: 0 auto; padding: 30px; }
h1 { color: #e94560; margin-bottom: 5px; }
h2 { color: #e94560; margin: 25px 0 10px; border-bottom: 1px solid #333; padding-bottom: 5px; }
.meta { color: #888; margin-bottom: 20px; }
.summary { display: flex; gap: 30px; margin: 20px 0; }
.stat { background: #16213e; padding: 20px 30px; border-radius: 8px; text-align: center; flex: 1; }
.num { font-size: 2em; font-weight: bold; color: #0f3460; }
.num.cracked { color: #e94560; }
table { width: 100%; border-collapse: collapse; margin: 10px 0; }
th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #2a2a3e; }
th { color: #e94560; font-weight: 600; }
code { background: #16213e; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }
.bar { height: 16px; background: #e94560; border-radius: 3px; min-width: 2px; }
.histogram { display: flex; align-items: flex-end; gap: 4px; height: 180px; padding: 10px 0; }
.hist-col { display: flex; flex-direction: column; align-items: center; flex: 1; }
.hist-bar { background: #e94560; width: 100%; min-width: 12px; border-radius: 3px 3px 0 0; }
.hist-label { font-size: 0.8em; margin-top: 4px; color: #888; }
.note { font-size: 0.85em; color: #888; margin-top: 10px; font-style: italic; }
"#;
