use crate::cascade::{inject_dynamic_masks, CascadeConfig, CascadeStage};
use crate::mask::analyze_cracked_passwords;
use crate::session::save_session;
use crate::state::{Args, CrackState, ExportRecord};
use chrono::Local;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

/// Minimum interval (seconds) between session saves to avoid I/O storms.
const SAVE_DEBOUNCE_SECS: i64 = 5;

pub fn has_gpu() -> bool {
    std::process::Command::new("nvidia-smi")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Shared engine output parsing
// ---------------------------------------------------------------------------

/// Parse a single line of engine stdout and update state accordingly.
/// Returns true if a new hash was cracked on this line.
fn parse_engine_line(
    s: &mut CrackState,
    line: &str,
    is_hashcat: bool,
    job_idx: usize,
    algo_name: &str,
) -> bool {
    if is_hashcat {
        parse_hashcat_line(s, line, job_idx, algo_name)
    } else {
        parse_jtr_line(s, line, job_idx, algo_name)
    }
}

fn parse_hashcat_line(
    s: &mut CrackState,
    line: &str,
    job_idx: usize,
    algo_name: &str,
) -> bool {
    // Try JSON status first (--status-json output)
    if line.starts_with('{') && line.contains("\"status\"") {
        parse_hashcat_status_json(s, line, job_idx);
        return false;
    }

    // Legacy machine-readable status lines
    if line.starts_with("STATUS") || line.split('\t').count() > 3 {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() > 5 {
            s.jobs[job_idx].speed = format!("{} H/s", parts[4]);
        }
        return false;
    }

    // Cracked hash output: hash:plaintext
    if line.contains(':') {
        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() == 2 {
            let record = ExportRecord {
                hash: parts[0].to_string(),
                plaintext: parts[1].to_string(),
                algo: algo_name.to_string(),
                timestamp: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            };
            if s.insert_recovered(record) {
                s.jobs[job_idx].cracked += 1;
                return true;
            }
        }
        return false;
    }

    // Generic log line
    s.push_log(line.to_string());
    false
}

fn parse_hashcat_status_json(s: &mut CrackState, line: &str, job_idx: usize) {
    // Lightweight JSON parsing without pulling in a full JSON parser for status.
    // hashcat --status-json emits: {"session":"...","guess":{},"status":3,
    //   "target":"...","progress":[cur,total],"restore_point":...,
    //   "recovered_hashes":[cur,total],"recovered_salts":[cur,total],
    //   "rejected":0,"devices":[{"device_id":1,"speed":12345,...,"temp":65}],...
    //   "time_start":..., "estimated_stop":...}

    // Extract speed from devices array
    if let Some(speed) = extract_json_field(line, "\"speed\"") {
        s.jobs[job_idx].speed = format!("{} H/s", speed);
    }

    // Extract progress for ETA
    if let Some(est_stop) = extract_json_field(line, "\"estimated_stop\"") {
        if let Ok(ts) = est_stop.parse::<i64>() {
            let remaining = ts - Local::now().timestamp();
            if remaining > 0 {
                let h = remaining / 3600;
                let m = (remaining % 3600) / 60;
                let sec = remaining % 60;
                s.jobs[job_idx].eta = format!("{:02}:{:02}:{:02}", h, m, sec);
            } else {
                s.jobs[job_idx].eta = "00:00:00".to_string();
            }
        }
    }

    // Extract GPU temp from first device
    if let Some(temp) = extract_json_field(line, "\"temp\"") {
        s.jobs[job_idx].speed = format!("{} [{}C]", s.jobs[job_idx].speed, temp);
    }
}

/// Extract a numeric value after the given key from a JSON string.
/// Handles both `"key":123` and `"key": 123` patterns.
fn extract_json_field<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let pos = json.find(key)?;
    let after_key = &json[pos + key.len()..];
    // Skip ':' and whitespace
    let value_start = after_key.find(|c: char| c != ':' && c != ' ')?;
    let value_str = &after_key[value_start..];
    // Find end of numeric value
    let end = value_str
        .find(|c: char| !c.is_ascii_digit() && c != '.' && c != '-')
        .unwrap_or(value_str.len());
    if end == 0 {
        return None;
    }
    Some(&value_str[..end])
}

fn parse_jtr_line(
    s: &mut CrackState,
    line: &str,
    job_idx: usize,
    algo_name: &str,
) -> bool {
    // JtR status lines -- skip
    if line.contains("Loaded") || line.contains("remaining") {
        return false;
    }

    // Skip warning/info lines
    if line.contains("No password hashes") || line.contains("Warning") {
        return false;
    }

    // Cracked hash output: hash:plaintext
    if line.contains(':') {
        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() == 2 {
            let record = ExportRecord {
                hash: parts[0].to_string(),
                plaintext: parts[1].to_string(),
                algo: algo_name.to_string(),
                timestamp: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            };
            if s.insert_recovered(record) {
                s.jobs[job_idx].cracked += 1;
                return true;
            }
        }
        return false;
    }

    // Generic log line
    s.push_log(line.to_string());
    false
}

// ---------------------------------------------------------------------------
// Shared child process runner
// ---------------------------------------------------------------------------

/// Spawn stdout and stderr reader tasks, returning their JoinHandles.
fn spawn_output_readers(
    stdout: tokio::process::ChildStdout,
    stderr: tokio::process::ChildStderr,
    state: Arc<Mutex<CrackState>>,
    job_idx: usize,
    algo_name: String,
    session_name: Option<String>,
    is_hashcat: bool,
) -> (JoinHandle<()>, JoinHandle<()>) {
    let st_out = state.clone();
    let algo_out = algo_name;
    let session_out = session_name;

    let stdout_handle = tokio::spawn(async move {
        let mut reader = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            let mut s = st_out.lock().await;
            let cracked = parse_engine_line(&mut s, &line, is_hashcat, job_idx, &algo_out);

            if cracked {
                // Debounced session save
                if let Some(sn) = &session_out {
                    let now = Local::now().timestamp();
                    if now - s.last_save_time >= SAVE_DEBOUNCE_SECS {
                        let _ = save_session(sn, &s);
                        s.last_save_time = now;
                    }
                }
            }
        }
    });

    let st_err = state;
    let stderr_handle = tokio::spawn(async move {
        let mut reader = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            let mut s = st_err.lock().await;
            s.push_log(format!("[!] {}", line));
        }
    });

    (stdout_handle, stderr_handle)
}

/// Run a child process: spawn it, read output, wait for exit, join readers.
/// Returns the exit success status.
async fn run_child(
    mut cmd: Command,
    state: Arc<Mutex<CrackState>>,
    job_idx: usize,
    algo_name: String,
    session_name: Option<String>,
    is_hashcat: bool,
) -> Option<bool> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let mut s = state.lock().await;
            s.jobs[job_idx].status = "Failed".to_string();
            s.push_log(format!("[!] Engine spawn failed: {}", e));
            return None;
        }
    };

    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();

    let (stdout_handle, stderr_handle) = spawn_output_readers(
        stdout,
        stderr,
        state.clone(),
        job_idx,
        algo_name,
        session_name.clone(),
        is_hashcat,
    );

    let status = child.wait().await.unwrap_or_default();

    // Wait for readers to drain all buffered output before proceeding
    let _ = stdout_handle.await;
    let _ = stderr_handle.await;

    // Final session save after child exits (catches anything debounced)
    if let Some(sn) = &session_name {
        let s = state.lock().await;
        let _ = save_session(sn, &s);
    }

    Some(status.success())
}

// ---------------------------------------------------------------------------
// Standard orchestrator
// ---------------------------------------------------------------------------

pub async fn run_orchestrator(args: &Args, state: Arc<Mutex<CrackState>>) {
    let num_jobs = state.lock().await.jobs.len();
    let use_gpu = if args.force_gpu {
        true
    } else if args.force_cpu {
        false
    } else {
        has_gpu()
    };

    for i in 0..num_jobs {
        {
            let mut s = state.lock().await;
            if s.jobs[i].status == "Complete"
                || s.jobs[i].status == "Exhausted"
                || s.jobs[i].status.contains("Skipped")
            {
                continue;
            }
            s.active_job_idx = Some(i);
            s.jobs[i].status = "Cracking".to_string();
            let algo = s.jobs[i].algo_name.clone();
            s.push_log(format!(
                "[*] Starting batch job {}/{} ({})",
                i + 1, num_jobs, algo
            ));

            if use_gpu && s.jobs[i].hashcat_mode.is_some() {
                s.jobs[i].engine_used = "Hashcat GPU".to_string();
            } else if s.jobs[i].jtr_format.is_some() {
                s.jobs[i].engine_used = "Jumbo John".to_string();
            } else {
                s.jobs[i].status = "Skipped (No Engine)".to_string();
                continue;
            }
        }

        let job = state.lock().await.jobs[i].clone();

        let (cmd, is_hashcat) = if use_gpu && job.hashcat_mode.is_some() {
            let mut c = Command::new("hashcat");
            c.arg("-m").arg(job.hashcat_mode.as_ref().unwrap());
            if let Some(a) = &args.attack_mode {
                c.arg("-a").arg(a);
            } else if args.wordlist.is_some() {
                c.arg("-a").arg("0");
            } else {
                c.arg("-a").arg("3");
                c.arg("?a?a?a?a?a?a");
            }
            c.arg(&job.hash_file_path);
            if let Some(w) = &args.wordlist {
                c.arg(w);
            }
            c.arg("--status-json").arg("--status-timer=5").arg("--quiet");
            for a in &args.passthrough {
                c.arg(a);
            }
            (c, true)
        } else {
            let mut c = Command::new("john");
            if let Some(fmt) = &job.jtr_format {
                c.arg(format!("--format={}", fmt));
            }
            if let Some(w) = &args.wordlist {
                c.arg(format!("--wordlist={}", w.display()));
            }
            for a in &args.passthrough {
                c.arg(a);
            }
            c.arg(&job.hash_file_path);
            (c, false)
        };

        let success = run_child(
            cmd,
            state.clone(),
            i,
            job.algo_name.clone(),
            args.session.clone(),
            is_hashcat,
        )
        .await;

        if let Some(ok) = success {
            let mut s = state.lock().await;
            s.jobs[i].status = if ok {
                "Complete".to_string()
            } else {
                "Exhausted".to_string()
            };
            s.push_log(format!("[*] Batch job {} finished.", i + 1));
        }
    }

    let mut s = state.lock().await;
    s.overall_status = "Finished".to_string();
    s.active_job_idx = None;
    if let Some(sn) = &args.session {
        let _ = save_session(sn, &s);
    }
}

// ---------------------------------------------------------------------------
// Cascade orchestrator with live adaptive mask injection
// ---------------------------------------------------------------------------

pub async fn run_cascade_orchestrator(
    args: &Args,
    state: Arc<Mutex<CrackState>>,
    mut config: CascadeConfig,
) {
    let num_jobs = state.lock().await.jobs.len();
    let use_gpu = if args.force_gpu {
        true
    } else if args.force_cpu {
        false
    } else {
        has_gpu()
    };

    let mut stage_idx = 0;
    while stage_idx < config.stages.len() {
        let stage = config.stages[stage_idx].clone();

        {
            let mut s = state.lock().await;
            let label = describe_stage(&stage);
            s.cascade_stage = Some(format!(
                "Stage {}/{}: {}",
                stage_idx + 1,
                config.stages.len(),
                label
            ));
            s.push_log(format!(
                "[*] Cascade stage {}/{}: {}",
                stage_idx + 1,
                config.stages.len(),
                label
            ));
        }

        if matches!(stage, CascadeStage::PotfileCheck) {
            stage_idx += 1;
            continue;
        }

        for i in 0..num_jobs {
            {
                let s = state.lock().await;
                if s.jobs[i].cracked >= s.jobs[i].total_hashes {
                    continue;
                }
                if s.jobs[i].status.contains("Skipped") {
                    continue;
                }
            }

            let attacks = {
                let s = state.lock().await;
                let job = &s.jobs[i];
                build_stage_attacks(job, &stage, use_gpu)
            };

            for (mut cmd, is_hashcat, attack_label) in attacks {
                {
                    let mut s = state.lock().await;
                    s.active_job_idx = Some(i);
                    s.jobs[i].status = format!("Cascade: {}", attack_label);
                    s.jobs[i].engine_used = if is_hashcat {
                        "Hashcat GPU".to_string()
                    } else {
                        "Jumbo John".to_string()
                    };
                }

                // Add passthrough args
                let passthrough_args: Vec<String> = args.passthrough.clone();
                for a in &passthrough_args {
                    cmd.arg(a);
                }

                let algo_name = state.lock().await.jobs[i].algo_name.clone();

                let success = run_child(
                    cmd,
                    state.clone(),
                    i,
                    algo_name,
                    args.session.clone(),
                    is_hashcat,
                )
                .await;

                if let Some(ok) = success {
                    if !ok {
                        let mut s = state.lock().await;
                        s.push_log(format!(
                            "[*] Attack '{}' exhausted for job {}",
                            attack_label,
                            i + 1
                        ));
                    }
                }

                // If all hashes in this job are cracked, skip remaining attacks
                let s = state.lock().await;
                if s.jobs[i].cracked >= s.jobs[i].total_hashes {
                    break;
                }
            }
        }

        // --- Live Adaptive Cascade: inject dynamic masks between stages ---
        {
            let s = state.lock().await;
            let plaintexts: Vec<String> =
                s.recovered.iter().map(|r| r.plaintext.clone()).collect();
            if !plaintexts.is_empty() {
                let dynamic_masks = analyze_cracked_passwords(&plaintexts);
                if !dynamic_masks.is_empty() {
                    let new_count = dynamic_masks.len();
                    drop(s); // release lock before mutating config
                    inject_dynamic_masks(&mut config, dynamic_masks);
                    let mut s = state.lock().await;
                    s.push_log(format!(
                        "[+] Adaptive cascade: injected {} dynamic mask patterns from cracked passwords",
                        new_count
                    ));
                }
            }
        }

        // Check if all jobs fully cracked
        let all_done = {
            let s = state.lock().await;
            s.jobs
                .iter()
                .all(|j| j.cracked >= j.total_hashes || j.status.contains("Skipped"))
        };
        if all_done {
            let mut s = state.lock().await;
            s.push_log(
                "[+] All hashes cracked! Skipping remaining cascade stages.".to_string(),
            );
            break;
        }

        stage_idx += 1;
    }

    let mut s = state.lock().await;
    for job in &mut s.jobs {
        if job.status.starts_with("Cascade:") {
            job.status = if job.cracked >= job.total_hashes {
                "Complete".to_string()
            } else {
                "Exhausted".to_string()
            };
        }
    }
    s.overall_status = "Finished".to_string();
    s.active_job_idx = None;
    s.cascade_stage = None;
    if let Some(sn) = &args.session {
        let _ = save_session(sn, &s);
    }
}

fn describe_stage(stage: &CascadeStage) -> String {
    match stage {
        CascadeStage::PotfileCheck => "Potfile lookup".to_string(),
        CascadeStage::WordlistAttack { wordlist, rules } => {
            let wl_name = wordlist.file_name().unwrap_or_default().to_string_lossy();
            match rules {
                Some(r) => format!(
                    "Wordlist ({}) + Rules ({})",
                    wl_name,
                    r.file_name().unwrap_or_default().to_string_lossy()
                ),
                None => format!("Wordlist ({})", wl_name),
            }
        }
        CascadeStage::MaskAttack { masks } => format!("Mask attack ({} patterns)", masks.len()),
        CascadeStage::IncrementalBrute {
            min_len,
            max_len,
            charset,
        } => {
            format!("Brute force {}-{} chars ({})", min_len, max_len, charset)
        }
    }
}

// ---------------------------------------------------------------------------
// Hash-type-aware cascade attack builder
// ---------------------------------------------------------------------------

/// Hash modes considered "slow" (< 100kH/s). Skip heavy rules, prefer targeted attacks.
const SLOW_HASH_MODES: &[&str] = &[
    "3200",  // bcrypt
    "1800",  // sha512crypt
    "7400",  // sha256crypt
    "10000", // PBKDF2-SHA256
    "500",   // md5crypt
];

fn is_slow_hash(hashcat_mode: Option<&str>) -> bool {
    hashcat_mode.map_or(false, |m| SLOW_HASH_MODES.contains(&m))
}

fn build_stage_attacks(
    job: &crate::state::Job,
    stage: &CascadeStage,
    use_gpu: bool,
) -> Vec<(Command, bool, String)> {
    let mut attacks = Vec::new();

    let hashcat_mode = job.hashcat_mode.as_deref();
    let jtr_format = job.jtr_format.as_deref();

    // Need at least one engine mode to proceed
    if hashcat_mode.is_none() && jtr_format.is_none() {
        return attacks;
    }

    let slow = is_slow_hash(hashcat_mode);

    match stage {
        CascadeStage::PotfileCheck => {}
        CascadeStage::WordlistAttack { wordlist, rules } => {
            // For slow hashes, skip heavy rule files (keep only fast rules)
            let skip_rules = slow
                && rules.as_ref().map_or(false, |r| {
                    let name = r.file_name().unwrap_or_default().to_string_lossy();
                    // Skip dive.rule, rockyou-30000.rule, etc. for slow hashes
                    name.contains("dive") || name.contains("30000") || name.contains("d3ad0ne")
                });

            if use_gpu && hashcat_mode.is_some() {
                let mode = hashcat_mode.unwrap();
                let mut c = Command::new("hashcat");
                c.arg("-m").arg(mode);
                c.arg("-a").arg("0");
                c.arg(&job.hash_file_path);
                c.arg(wordlist);
                if !skip_rules {
                    if let Some(r) = rules {
                        c.arg("-r").arg(r);
                    }
                }
                c.arg("--status-json").arg("--status-timer=5").arg("--quiet");
                let label = if skip_rules {
                    "Wordlist (no rules, slow hash)".to_string()
                } else {
                    "Wordlist+Rules".to_string()
                };
                attacks.push((c, true, label));
            } else if let Some(fmt) = jtr_format {
                let mut c = Command::new("john");
                c.arg(format!("--format={}", fmt));
                c.arg(format!("--wordlist={}", wordlist.display()));
                if !skip_rules {
                    if let Some(r) = rules {
                        c.arg(format!("--rules={}", r.display()));
                    }
                }
                c.arg(&job.hash_file_path);
                let label = if skip_rules {
                    "Wordlist (no rules, slow hash) (JtR)".to_string()
                } else {
                    "Wordlist+Rules (JtR)".to_string()
                };
                attacks.push((c, false, label));
            }
        }
        CascadeStage::MaskAttack { masks } => {
            if use_gpu && hashcat_mode.is_some() {
                let mode = hashcat_mode.unwrap();
                // For slow hashes, limit mask count to avoid days-long runs
                let effective_masks = if slow { &masks[..masks.len().min(3)] } else { masks };
                for mask in effective_masks {
                    let mut c = Command::new("hashcat");
                    c.arg("-m").arg(mode);
                    c.arg("-a").arg("3");
                    c.arg(&job.hash_file_path);
                    c.arg(mask);
                    c.arg("--status-json").arg("--status-timer=5").arg("--quiet");
                    attacks.push((c, true, format!("Mask: {}", mask)));
                }
            }
        }
        CascadeStage::IncrementalBrute {
            min_len,
            max_len,
            charset,
        } => {
            // For slow hashes, cap brute force at 6 characters
            let effective_max = if slow { (*max_len).min(6) } else { *max_len };

            if use_gpu && hashcat_mode.is_some() {
                let mode = hashcat_mode.unwrap();
                let mask: String = std::iter::repeat(charset.as_str())
                    .take(effective_max as usize)
                    .collect();
                let mut c = Command::new("hashcat");
                c.arg("-m").arg(mode);
                c.arg("-a").arg("3");
                c.arg(&job.hash_file_path);
                c.arg(&mask);
                c.arg("--increment");
                c.arg(format!("--increment-min={}", min_len));
                c.arg(format!("--increment-max={}", effective_max));
                c.arg("--status-json").arg("--status-timer=5").arg("--quiet");
                attacks.push((c, true, format!("Brute {}-{}", min_len, effective_max)));
            } else if let Some(fmt) = jtr_format {
                let mut c = Command::new("john");
                c.arg(format!("--format={}", fmt));
                c.arg("--incremental");
                c.arg(format!("--min-length={}", min_len));
                c.arg(format!("--max-length={}", effective_max));
                c.arg(&job.hash_file_path);
                attacks.push((c, false, "Incremental (JtR)".to_string()));
            }
        }
    }

    attacks
}
