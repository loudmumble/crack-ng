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

/// Separator character for hashcat output. Using tab avoids ambiguity with
/// colon-containing hash formats (NetNTLMv2, LM:NT pairs, etc.).
const HASHCAT_SEPARATOR: char = '\t';

// ---------------------------------------------------------------------------
// Hardware detection and optimization
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct HardwareProfile {
    pub has_gpu: bool,
    pub gpu_name: String,
    pub gpu_memory_mb: u64,
    /// Hashcat workload profile (1=low, 2=default, 3=high, 4=nightmare)
    pub workload_profile: u8,
    /// Whether to enable -O (optimized kernels, limits passwords to 32 chars)
    pub use_optimized_kernels: bool,
}

pub fn detect_hardware() -> HardwareProfile {
    let (has_gpu, gpu_name, gpu_memory) = match std::process::Command::new("nvidia-smi")
        .arg("--query-gpu=name,memory.total")
        .arg("--format=csv,noheader,nounits")
        .output()
    {
        Ok(out) if out.status.success() => {
            let output = String::from_utf8_lossy(&out.stdout);
            let line = output.lines().next().unwrap_or("").trim().to_string();
            let parts: Vec<&str> = line.split(", ").collect();
            let name = parts.first().unwrap_or(&"Unknown GPU").to_string();
            let mem: u64 = parts
                .get(1)
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0);
            (true, name, mem)
        }
        _ => (false, String::new(), 0),
    };

    // Workload profile based on VRAM:
    //   8GB+ (RTX 3070+, RTX 4090, etc.) -> 4 (nightmare, max throughput)
    //   4-8GB (GTX 1070, RTX 2060, etc.) -> 3 (high)
    //   <4GB -> 2 (default)
    let workload_profile = if gpu_memory >= 8000 {
        4
    } else if gpu_memory >= 4000 {
        3
    } else {
        2
    };

    HardwareProfile {
        has_gpu,
        gpu_name,
        gpu_memory_mb: gpu_memory,
        workload_profile,
        use_optimized_kernels: has_gpu,
    }
}

/// Apply auto-tuned optimization flags to a hashcat command.
/// These are added BEFORE passthrough args so the user can override (hashcat uses last-wins).
fn apply_hashcat_optimizations(cmd: &mut Command, hw: &HardwareProfile) {
    cmd.arg("-w").arg(hw.workload_profile.to_string());
    if hw.use_optimized_kernels {
        cmd.arg("-O");
    }
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

    // Skip known hashcat informational lines that contain colons
    if line.starts_with("Session")
        || line.starts_with("Status")
        || line.starts_with("Time")
        || line.starts_with("Speed")
        || line.starts_with("Recovered")
        || line.starts_with("Progress")
        || line.starts_with("Rejected")
        || line.starts_with("Restore")
        || line.starts_with("Candidates")
        || line.starts_with("HWMon")
        || line.starts_with("Device")
        || line.starts_with("Watchdog")
        || line.starts_with("Hash.")
        || line.starts_with("Guess.")
    {
        return false;
    }

    // Cracked hash output: hash<TAB>plaintext (using custom --separator)
    if line.contains(HASHCAT_SEPARATOR) {
        let parts: Vec<&str> = line.splitn(2, HASHCAT_SEPARATOR).collect();
        if parts.len() == 2 && !parts[0].is_empty() {
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

    false
}

/// Format a hash speed into human-readable units (H/s, kH/s, MH/s, GH/s, TH/s).
fn format_speed(hashes_per_sec: u64) -> String {
    if hashes_per_sec >= 1_000_000_000_000 {
        format!("{:.1} TH/s", hashes_per_sec as f64 / 1_000_000_000_000.0)
    } else if hashes_per_sec >= 1_000_000_000 {
        format!("{:.1} GH/s", hashes_per_sec as f64 / 1_000_000_000.0)
    } else if hashes_per_sec >= 1_000_000 {
        format!("{:.1} MH/s", hashes_per_sec as f64 / 1_000_000.0)
    } else if hashes_per_sec >= 1_000 {
        format!("{:.1} kH/s", hashes_per_sec as f64 / 1_000.0)
    } else {
        format!("{} H/s", hashes_per_sec)
    }
}

fn parse_hashcat_status_json(s: &mut CrackState, line: &str, job_idx: usize) {
    // Lightweight JSON parsing without pulling in a full JSON parser for status.
    // hashcat --status-json emits: {"session":"...","guess":{},"status":3,
    //   "target":"...","progress":[cur,total],"restore_point":...,
    //   "recovered_hashes":[cur,total],"recovered_salts":[cur,total],
    //   "rejected":0,"devices":[{"device_id":1,"speed":12345,...,"temp":65}],...
    //   "time_start":..., "estimated_stop":...}

    // Extract aggregate speed from all devices (sum) and max temp
    let total_speed: u64 = extract_all_json_fields(line, "\"speed\"")
        .iter()
        .filter_map(|s| s.parse::<u64>().ok())
        .sum();
    if total_speed > 0 {
        s.jobs[job_idx].speed = format_speed(total_speed);
    }

    // Compute ETA from progress[current,total] and speed. Single code path.
    if total_speed > 0 {
        if let Some(prog_start) = line.find("\"progress\"") {
            let after = &line[prog_start..];
            if let Some(bracket) = after.find('[') {
                let inner = &after[bracket + 1..];
                if let Some(bracket_end) = inner.find(']') {
                    let nums: Vec<&str> = inner[..bracket_end].split(',').collect();
                    if nums.len() == 2 {
                        if let (Ok(cur), Ok(tot)) = (
                            nums[0].trim().parse::<u64>(),
                            nums[1].trim().parse::<u64>(),
                        ) {
                            if tot > 0 && cur < tot {
                                let remaining_secs = (tot - cur) / total_speed;
                                s.jobs[job_idx].eta_seconds = remaining_secs as i64;
                                let h = remaining_secs / 3600;
                                let m = (remaining_secs % 3600) / 60;
                                let sec = remaining_secs % 60;
                                s.jobs[job_idx].eta = format!("{:02}:{:02}:{:02}", h, m, sec);
                            } else {
                                s.jobs[job_idx].eta_seconds = 0;
                                s.jobs[job_idx].eta = "<1s".to_string();
                            }
                        }
                    }
                }
            }
        }
    }

    // Extract max GPU temp across all devices
    let max_temp: Option<u64> = extract_all_json_fields(line, "\"temp\"")
        .iter()
        .filter_map(|s| s.parse::<u64>().ok())
        .max();
    if let Some(temp) = max_temp {
        s.jobs[job_idx].speed = format!("{} [{}C]", s.jobs[job_idx].speed, temp);
    }
}

fn extract_json_field_at<'a>(json: &'a str, key: &str, start: usize) -> Option<&'a str> {
    let search_str = &json[start..];
    let pos = search_str.find(key)?;
    let after_key = &search_str[pos + key.len()..];
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

/// Extract ALL occurrences of a numeric field from a JSON string.
/// Used for multi-device arrays where "speed" and "temp" appear per GPU.
fn extract_all_json_fields<'a>(json: &'a str, key: &str) -> Vec<&'a str> {
    let mut results = Vec::new();
    let mut offset = 0;
    while offset < json.len() {
        if let Some(pos) = json[offset..].find(key) {
            let abs_pos = offset + pos;
            if let Some(val) = extract_json_field_at(json, key, abs_pos) {
                results.push(val);
            }
            offset = abs_pos + key.len();
        } else {
            break;
        }
    }
    results
}

fn parse_jtr_line(
    s: &mut CrackState,
    line: &str,
    _job_idx: usize,
    _algo_name: &str,
) -> bool {
    // Skip JtR informational/status lines
    if line.contains("Loaded")
        || line.contains("remaining")
        || line.contains("No password hashes")
        || line.contains("Warning")
        || line.starts_with("Using ")
        || line.starts_with("Press ")
        || line.starts_with("Session ")
        || line.starts_with("Proceeding ")
        || line.starts_with("Node ")
        || line.contains("guesses:")
        || line.contains(" p/s")
    {
        return false;
    }

    // JtR real-time cracked output: "password     (username)" or just "password"
    // The password is left-aligned, optionally followed by spaces and (username).
    // We detect this by looking for the (username) suffix pattern.
    // Note: JtR's real-time output doesn't include the hash, so we record a
    // placeholder. The definitive results are harvested via `john --show` after
    // the child process exits (see harvest_jtr_results).
    if line.ends_with(')') {
        if let Some(paren_start) = line.rfind('(') {
            let password = line[..paren_start].trim_end();
            if !password.is_empty() && !password.contains("DONE") && !password.contains("Session") {
                // This is a real-time crack notification; log it but don't add to
                // recovered -- harvest_jtr_results will capture the definitive
                // hash:password mapping after JtR exits.
                s.push_log(format!("[+] JtR cracked: {} ({})", password, &line[paren_start + 1..line.len() - 1]));
                return false;
            }
        }
    }

    // Generic log line (skip empty lines and lines that look like status summaries)
    if !line.trim().is_empty() {
        s.push_log(line.to_string());
    }
    false
}

/// Harvest cracked results from JtR by running `john --show` after execution.
/// This is the definitive way to get hash:password mappings from JtR, since its
/// real-time stdout format doesn't include the original hash.
fn harvest_jtr_results(
    s: &mut CrackState,
    job_idx: usize,
    hash_file: &str,
    jtr_format: Option<&str>,
    algo_name: &str,
) {
    let mut cmd = std::process::Command::new("john");
    if let Some(fmt) = jtr_format {
        cmd.arg(format!("--format={}", fmt));
    }
    cmd.arg("--show");
    cmd.arg(hash_file);

    let output = match cmd.output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            s.push_log(format!("[!] JtR --show failed: {}", stderr.lines().next().unwrap_or("")));
            return;
        }
        Err(e) => {
            s.push_log(format!("[!] JtR --show exec failed: {}", e));
            return;
        }
    };

    let before = s.jobs[job_idx].cracked;
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Skip JtR summary line: "N password hashes cracked, M left"
        if line.contains("password hash") {
            continue;
        }
        // JtR --show format: the password is the LAST colon-separated field.
        // Use rfind to handle hashes that contain colons.
        if let Some(sep_pos) = line.rfind(':') {
            let hash_part = &line[..sep_pos];
            let plain_part = &line[sep_pos + 1..];
            if !hash_part.is_empty() && !plain_part.is_empty() {
                let record = ExportRecord {
                    hash: hash_part.to_string(),
                    plaintext: plain_part.to_string(),
                    algo: algo_name.to_string(),
                    timestamp: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                };
                if s.insert_recovered(record) {
                    s.jobs[job_idx].cracked += 1;
                }
            }
        }
    }
    let harvested = s.jobs[job_idx].cracked - before;
    if harvested > 0 {
        s.push_log(format!(
            "[+] Harvested {} cracked hashes from JtR for {}",
            harvested, algo_name
        ));
    }
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
            let save_needed = {
                let mut s = st_out.lock().await;
                let cracked = parse_engine_line(&mut s, &line, is_hashcat, job_idx, &algo_out);
                if cracked {
                    if let Some(sn) = &session_out {
                        let now = Local::now().timestamp();
                        if now - s.last_save_time >= SAVE_DEBOUNCE_SECS {
                            s.last_save_time = now;
                            Some(sn.clone())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            }; // lock dropped here
            // Perform file I/O outside the lock scope
            if let Some(sn) = save_needed {
                let s = st_out.lock().await;
                let _ = save_session(&sn, &s);
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
) -> Option<i32> {
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

    // Store child PID so TUI can signal termination on quit
    {
        let mut s = state.lock().await;
        s.active_child_pid = child.id();
    }

    let stdout = child.stdout.take().expect("stdout must be piped");
    let stderr = child.stderr.take().expect("stderr must be piped");

    let (stdout_handle, stderr_handle) = spawn_output_readers(
        stdout,
        stderr,
        state.clone(),
        job_idx,
        algo_name,
        session_name.clone(),
        is_hashcat,
    );

    let status = match child.wait().await {
        Ok(s) => s,
        Err(e) => {
            let mut s = state.lock().await;
            s.push_log(format!("[!] Failed to wait on child process: {}", e));
            return Some(-1);
        }
    };

    // Clear active PID
    {
        let mut s = state.lock().await;
        s.active_child_pid = None;
    }

    // Wait for readers to drain all buffered output before proceeding
    let _ = stdout_handle.await;
    let _ = stderr_handle.await;

    // Final session save after child exits (catches anything debounced)
    if let Some(sn) = &session_name {
        let s = state.lock().await;
        let _ = save_session(sn, &s);
    }

    Some(status.code().unwrap_or(-1))
}

/// Spin-wait while `is_paused` is true. Checks every 250ms.
/// Updates overall_status to "Paused" while waiting, restores `prev_status` on resume.
async fn wait_if_paused(state: &Arc<Mutex<CrackState>>) {
    let is_paused = { state.lock().await.is_paused };
    if !is_paused {
        return;
    }
    let prev_status = {
        let mut s = state.lock().await;
        let prev = s.overall_status.clone();
        s.overall_status = "Paused".to_string();
        prev
    };
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        let s = state.lock().await;
        if !s.is_paused {
            break;
        }
    }
    {
        let mut s = state.lock().await;
        s.overall_status = prev_status;
    }
}

// ---------------------------------------------------------------------------
// Standard orchestrator
// ---------------------------------------------------------------------------

pub async fn run_orchestrator(args: &Args, state: Arc<Mutex<CrackState>>) {
    let num_jobs = state.lock().await.jobs.len();
    let hw = detect_hardware();
    let use_gpu = if args.force_gpu {
        true
    } else if args.force_cpu {
        false
    } else {
        hw.has_gpu
    };

    if hw.has_gpu {
        let mut s = state.lock().await;
        s.push_log(format!(
            "[*] GPU: {} ({} MB) -- workload: {}, optimized kernels: on",
            hw.gpu_name, hw.gpu_memory_mb, hw.workload_profile
        ));
    }

    {
        let mut s = state.lock().await;
        s.overall_status = "Cracking".to_string();
    }

    for i in 0..num_jobs {
        if state.lock().await.quit_requested { break; }
        wait_if_paused(&state).await;
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

        let (cmd, is_hashcat) = if let (true, Some(mode)) = (use_gpu, &job.hashcat_mode) {
            let mut c = Command::new("hashcat");
            c.arg("-m").arg(mode);
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
            c.arg("--status").arg("--status-json").arg("--status-timer=5").arg("--quiet");
            c.arg("--separator").arg(format!("{}", HASHCAT_SEPARATOR));
            apply_hashcat_optimizations(&mut c, &hw);
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

        if let Some(exit_code) = success {
            let mut s = state.lock().await;
            // Harvest JtR results via --show (JtR doesn't emit hash:password in real-time)
            if !is_hashcat {
                harvest_jtr_results(
                    &mut s,
                    i,
                    &job.hash_file_path,
                    job.jtr_format.as_deref(),
                    &job.algo_name,
                );
            }
            s.jobs[i].status = if is_hashcat {
                // Hashcat exit codes: 0=cracked, 1=exhausted, 2=aborted, other=error
                match exit_code {
                    0 => "Complete".to_string(),
                    1 => "Exhausted".to_string(),
                    _ => format!("Failed (exit {})", exit_code),
                }
            } else {
                // JtR exit codes: 0=success (cracked or exhausted), 1+=error
                match exit_code {
                    0 => if s.jobs[i].cracked > 0 {
                        "Complete".to_string()
                    } else {
                        "Exhausted".to_string()
                    },
                    _ => format!("Failed (exit {})", exit_code),
                }
            };
            s.push_log(format!("[*] Batch job {} finished.", i + 1));
        }
    }

    let mut s = state.lock().await;
    s.overall_status = "Finished".to_string();
    s.end_time = Some(Local::now().timestamp());
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
    let hw = detect_hardware();
    let use_gpu = if args.force_gpu {
        true
    } else if args.force_cpu {
        false
    } else {
        hw.has_gpu
    };

    if hw.has_gpu {
        let mut s = state.lock().await;
        s.push_log(format!(
            "[*] GPU: {} ({} MB) -- workload: {}, optimized kernels: on",
            hw.gpu_name, hw.gpu_memory_mb, hw.workload_profile
        ));
    }

    {
        let mut s = state.lock().await;
        s.overall_status = "Cascade Running".to_string();
    }

    // Resume from the last completed stage if restoring a session
    let resume_from = {
        let s = state.lock().await;
        s.cascade_completed_idx
    };
    let mut stage_idx = resume_from;
    if stage_idx > 0 {
        let mut s = state.lock().await;
        s.push_log(format!(
            "[*] Cascade: resuming from stage {} (skipping {} completed)",
            stage_idx + 1,
            stage_idx
        ));
    }
    while stage_idx < config.stages.len() {
        // Early exit: check if all non-skipped jobs are done before entering next stage
        let (all_done, any_cracked) = {
            let s = state.lock().await;
            let non_skipped: Vec<&crate::state::Job> = s.jobs.iter().filter(|j| !j.status.contains("Skipped")).collect();
            if non_skipped.is_empty() {
                (true, false)
            } else {
                let done = non_skipped.iter().all(|j| j.cracked >= j.total_hashes);
                let cracked = non_skipped.iter().any(|j| j.cracked > 0);
                (done, cracked)
            }
        };
        if all_done {
            let mut s = state.lock().await;
            if any_cracked {
                s.push_log("[+] All hashes cracked! Skipping remaining cascade stages.".to_string());
            } else {
                s.push_log("[*] No actionable jobs remaining. Ending cascade.".to_string());
            }
            break;
        }

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
            // Record stage start time
            while s.stage_times.len() <= stage_idx {
                s.stage_times.push((0, None));
            }
            s.stage_times[stage_idx] = (Local::now().timestamp(), None);
            s.skip_stage_requested = false;
            s.stage_attack_progress = (0, 0, 0);
        }

        if matches!(stage, CascadeStage::PotfileCheck) {
            // Run --show for each job to recover previously-cracked hashes from potfile
            for i in 0..num_jobs {
                let (hc_mode, jtr_fmt, hash_file, algo_name) = {
                    let s = state.lock().await;
                    let job = &s.jobs[i];
                    if job.status.contains("Skipped") {
                        continue;
                    }
                    (
                        job.hashcat_mode.clone(),
                        job.jtr_format.clone(),
                        job.hash_file_path.clone(),
                        job.algo_name.clone(),
                    )
                };

                // Try hashcat --show first (GPU path), then JtR --show as fallback
                // Each engine uses a different separator for unambiguous parsing.
                let sep_str = format!("{}", HASHCAT_SEPARATOR);
                let show_output = if use_gpu {
                    if let Some(mode) = &hc_mode {
                        std::process::Command::new("hashcat")
                            .arg("-m").arg(mode)
                            .arg(&hash_file)
                            .arg("--show")
                            .arg("--quiet")
                            .arg("--separator").arg(&sep_str)
                            .output()
                            .ok()
                            .filter(|o| o.status.success())
                            .map(|o| (String::from_utf8_lossy(&o.stdout).to_string(), HASHCAT_SEPARATOR))
                    } else {
                        None
                    }
                } else {
                    None
                };

                let show_output = show_output.or_else(|| {
                    if let Some(fmt) = &jtr_fmt {
                        std::process::Command::new("john")
                            .arg(format!("--format={}", fmt))
                            .arg("--show")
                            .arg(&hash_file)
                            .output()
                            .ok()
                            .filter(|o| o.status.success())
                            .map(|o| (String::from_utf8_lossy(&o.stdout).to_string(), ':'))
                    } else {
                        None
                    }
                });

                if let Some((text, sep)) = show_output {
                    let mut s = state.lock().await;
                    let before = s.jobs[i].cracked;
                    for line in text.lines() {
                        let line = line.trim();
                        if line.is_empty() {
                            continue;
                        }
                        // Skip JtR summary line: "N password hashes cracked, M left"
                        if line.contains("password hash") {
                            continue;
                        }
                        if !line.contains(sep) {
                            continue;
                        }
                        // Hashcat uses tab separator (unambiguous). JtR uses ':' where
                        // the password is the LAST field -- use rfind to handle
                        // hashes that contain colons (NetNTLMv2, shadow, etc.).
                        let (hash_part, plain_part) = if sep == HASHCAT_SEPARATOR {
                            let parts: Vec<&str> = line.splitn(2, sep).collect();
                            if parts.len() == 2 { (parts[0], parts[1]) } else { continue }
                        } else {
                            if let Some(pos) = line.rfind(sep) {
                                (&line[..pos], &line[pos + 1..])
                            } else {
                                continue
                            }
                        };
                        if !hash_part.is_empty() {
                            let record = ExportRecord {
                                hash: hash_part.to_string(),
                                plaintext: plain_part.to_string(),
                                algo: algo_name.clone(),
                                timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                            };
                            if s.insert_recovered(record) {
                                s.jobs[i].cracked += 1;
                            }
                        }
                    }
                    let stage_recovered = s.jobs[i].cracked - before;
                    let engine_name = if sep == HASHCAT_SEPARATOR { "hashcat" } else { "john" };
                    if stage_recovered > 0 {
                        s.push_log(format!(
                            "[+] Potfile: recovered {} hashes for {} via {} --show",
                            stage_recovered, algo_name, engine_name
                        ));
                    }
                }
            }
            // Record completed stage for session resume
            {
                let mut s = state.lock().await;
                s.cascade_completed_idx = stage_idx + 1;
                if let Some(t) = s.stage_times.get_mut(stage_idx) {
                    t.1 = Some(Local::now().timestamp());
                }
            }
            stage_idx += 1;
            continue;
        }

        let mut stage_skipped = false;
        for i in 0..num_jobs {
            // Check if user requested stage skip
            {
                let s = state.lock().await;
                if s.skip_stage_requested {
                    stage_skipped = true;
                    break;
                }
            }

            // Single lock: check skip conditions + build attacks + get algo_name
            let (attacks, algo_name) = {
                let mut s = state.lock().await;
                if s.jobs[i].cracked >= s.jobs[i].total_hashes
                    || s.jobs[i].status.contains("Skipped")
                {
                    continue;
                }
                let job = &s.jobs[i];
                let a = build_stage_attacks(job, &stage, use_gpu, &hw);
                let name = job.algo_name.clone();
                // Accumulate total attack count for this stage across all jobs
                s.stage_attack_progress.1 += a.len();
                (a, name)
            };

            for (mut cmd, is_hashcat, attack_label) in attacks {
                // Wait if paused, check skip/quit before each attack
                wait_if_paused(&state).await;
                {
                    let s = state.lock().await;
                    if s.quit_requested {
                        stage_skipped = true;
                        break;
                    }
                    if s.skip_stage_requested {
                        stage_skipped = true;
                        break;
                    }
                }

                // Single lock: set active job + status + engine
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

                for a in &args.passthrough {
                    cmd.arg(a);
                }

                let success = run_child(
                    cmd,
                    state.clone(),
                    i,
                    algo_name.clone(),
                    args.session.clone(),
                    is_hashcat,
                )
                .await;

                // Single lock: harvest JtR results + log + check if fully cracked or skipped
                let should_break = {
                    let mut s = state.lock().await;
                    // Harvest JtR results via --show (JtR doesn't emit hash:password in real-time)
                    if !is_hashcat {
                        let hash_file = s.jobs[i].hash_file_path.clone();
                        let jtr_fmt = s.jobs[i].jtr_format.clone();
                        harvest_jtr_results(
                            &mut s,
                            i,
                            &hash_file,
                            jtr_fmt.as_deref(),
                            &algo_name,
                        );
                    }
                    if let Some(exit_code) = success {
                        if is_hashcat {
                            match exit_code {
                                0 => {} // cracked successfully
                                1 => s.push_log(format!(
                                    "[*] Attack '{}' exhausted for job {}",
                                    attack_label, i + 1
                                )),
                                _ => s.push_log(format!(
                                    "[!] Attack '{}' failed (exit {}) for job {}",
                                    attack_label, exit_code, i + 1
                                )),
                            }
                        } else {
                            // JtR: 0=success, 1+=error
                            if exit_code != 0 {
                                s.push_log(format!(
                                    "[!] Attack '{}' failed (exit {}) for job {}",
                                    attack_label, exit_code, i + 1
                                ));
                            }
                        }
                    }
                    s.stage_attack_progress.0 += 1;
                    s.stage_attack_progress.2 = Local::now().timestamp();
                    s.jobs[i].cracked >= s.jobs[i].total_hashes || s.skip_stage_requested
                };
                if should_break {
                    if state.lock().await.skip_stage_requested {
                        stage_skipped = true;
                    }
                    break;
                }
            }
            if stage_skipped {
                break;
            }
        }

        if stage_skipped {
            let mut s = state.lock().await;
            s.push_log(format!(
                "[*] Stage {} skipped by user.",
                stage_idx + 1
            ));
            s.skip_stage_requested = false;
        }

        // --- Live Adaptive Cascade: inject dynamic masks between stages ---
        // Collect plaintexts under lock, then release before CPU-bound analysis
        let plaintexts = {
            let s = state.lock().await;
            s.recovered.iter().map(|r| r.plaintext.clone()).collect::<Vec<_>>()
        };
        if !plaintexts.is_empty() {
            let dynamic_masks = analyze_cracked_passwords(&plaintexts);
            if !dynamic_masks.is_empty() {
                let new_count = dynamic_masks.len();
                inject_dynamic_masks(&mut config, dynamic_masks, stage_idx);
                let mut s = state.lock().await;
                s.push_log(format!(
                    "[+] Adaptive cascade: injected {} dynamic mask patterns from cracked passwords",
                    new_count
                ));
                // Rebuild cascade plan to reflect injected stages in Strategy tab
                s.cascade_plan = config
                    .stages
                    .iter()
                    .enumerate()
                    .map(|(i, stage)| format!("Stage {}: {}", i + 1, describe_stage(stage)))
                    .collect();
                // Update cascade_stage total to match new stage count
                if let Some(ref mut cs) = s.cascade_stage {
                    let current_label = describe_stage(&config.stages[stage_idx]);
                    *cs = format!(
                        "Stage {}/{}: {}",
                        stage_idx + 1,
                        config.stages.len(),
                        current_label
                    );
                }
            }
        }

        // Record completed stage for session resume and stage end time
        {
            let mut s = state.lock().await;
            s.cascade_completed_idx = stage_idx + 1;
            if let Some(t) = s.stage_times.get_mut(stage_idx) {
                t.1 = Some(Local::now().timestamp());
            }
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
    s.end_time = Some(Local::now().timestamp());
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
    "400",   // phpass
    "9200",  // Cisco Type 8
    "9300",  // Cisco Type 9
    "2100",  // DCC2
    "8900",  // scrypt
    "7200",  // GRUB PBKDF2
    "13400", // KeePass
    "14600", // LUKS
    "22100", // BitLocker
    "16700", // FileVault 2
];

fn is_slow_hash(hashcat_mode: Option<&str>) -> bool {
    hashcat_mode.is_some_and(|m| SLOW_HASH_MODES.contains(&m))
}

fn build_stage_attacks(
    job: &crate::state::Job,
    stage: &CascadeStage,
    use_gpu: bool,
    hw: &HardwareProfile,
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
                && rules.as_ref().is_some_and(|r| {
                    let name = r.file_name().unwrap_or_default().to_string_lossy();
                    // Skip dive.rule, rockyou-30000.rule, etc. for slow hashes
                    name.contains("dive") || name.contains("30000") || name.contains("d3ad0ne")
                });

            if let (true, Some(mode)) = (use_gpu, hashcat_mode) {
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
                c.arg("--status").arg("--status-json").arg("--status-timer=5").arg("--quiet");
                c.arg("--separator").arg(format!("{}", HASHCAT_SEPARATOR));
                apply_hashcat_optimizations(&mut c, hw);
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
                // JtR --rules expects a section name (e.g. --rules=Wordlist), not a file path.
                // Hashcat .rule files are incompatible with JtR, so we use JtR's built-in rules.
                if !skip_rules && rules.is_some() {
                    c.arg("--rules=Wordlist");
                }
                c.arg(&job.hash_file_path);
                let label = if skip_rules {
                    "Wordlist (no rules, slow hash) (JtR)".to_string()
                } else if rules.is_some() {
                    "Wordlist+Rules (JtR)".to_string()
                } else {
                    "Wordlist (JtR)".to_string()
                };
                attacks.push((c, false, label));
            }
        }
        CascadeStage::MaskAttack { masks } => {
            if let (true, Some(mode)) = (use_gpu, hashcat_mode) {
                // For slow hashes, limit mask count to avoid days-long runs
                let effective_masks = if slow { &masks[..masks.len().min(3)] } else { masks };
                for mask in effective_masks {
                    let mut c = Command::new("hashcat");
                    c.arg("-m").arg(mode);
                    c.arg("-a").arg("3");
                    c.arg(&job.hash_file_path);
                    c.arg(mask);
                    c.arg("--status").arg("--status-json").arg("--status-timer=5").arg("--quiet");
                    c.arg("--separator").arg(format!("{}", HASHCAT_SEPARATOR));
                    apply_hashcat_optimizations(&mut c, hw);
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

            if let (true, Some(mode)) = (use_gpu, hashcat_mode) {
                let mask: String = charset.as_str().repeat(effective_max as usize);
                let mut c = Command::new("hashcat");
                c.arg("-m").arg(mode);
                c.arg("-a").arg("3");
                c.arg(&job.hash_file_path);
                c.arg(&mask);
                c.arg("--increment");
                c.arg(format!("--increment-min={}", min_len));
                c.arg(format!("--increment-max={}", effective_max));
                c.arg("--status").arg("--status-json").arg("--status-timer=5").arg("--quiet");
                c.arg("--separator").arg(format!("{}", HASHCAT_SEPARATOR));
                apply_hashcat_optimizations(&mut c, hw);
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
