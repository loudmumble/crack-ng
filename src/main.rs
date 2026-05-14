use clap::Parser;
use anyhow::{Context, Result};
use std::fs;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::HashMap;
use std::io::Write;
use tempfile::NamedTempFile;
use chrono::Local;
use ratatui::{
    backend::CrosstermBackend,
    Terminal,
};
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

use std::collections::VecDeque;
use std::io::Read as _;
use std::path::Path;

use crack_ng::state::{Args, CrackState, ExportRecord, Job, SIGNATURES};
use crack_ng::session::{load_session, save_session};
use crack_ng::engine::{run_orchestrator, run_cascade_orchestrator};
use crack_ng::tui::{draw_main_ui, run_db_viewer};
use crack_ng::export::export_results;
use crack_ng::potfile;
use crack_ng::parser;
use crack_ng::wordlist;
use crack_ng::cascade;
use crack_ng::mask;
use crack_ng::report;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = Args::parse();

    // Merge positional arguments into flag fields.
    // Positionals fill hashes first, then wordlist, only if the corresponding flag wasn't used.
    {
        let mut pos_iter = args.positional.iter();
        if args.hashes.is_none() {
            args.hashes = pos_iter.next().cloned();
        }
        if args.wordlist.is_none() {
            args.wordlist = pos_iter.next().cloned();
        }
    }

    // Direct hash input: if the first arg doesn't exist as a file but looks like a hash
    // string, write it to a temp file and use that. Supports:
    //   crack-ng '$2a$10$...' rockyou.txt
    //   crack-ng --identify 5f4dcc3b5aa765d61d8327deb882cf99
    if let Some(hash_path) = &args.hashes {
        let path_str = hash_path.to_string_lossy();
        if !hash_path.exists() && looks_like_hash(&path_str) {
            let mut tmp = NamedTempFile::new()?;
            writeln!(tmp, "{}", path_str)?;
            let kept = tmp.into_temp_path().keep()?;
            args.hashes = Some(kept.to_path_buf());
        }
    }

    // --list-modes: print all supported hash types and exit
    if args.list_modes {
        println!("[*] crack-ng -- Supported Hash Types ({} signatures)\n", SIGNATURES.len());
        println!("{:<45} {:>8}  {:<20}", "Hash Type", "Hashcat", "John the Ripper");
        println!("{}", "-".repeat(78));
        for sig in SIGNATURES.iter() {
            let hc = sig.hashcat_mode.map(|m| format!("-m {}", m)).unwrap_or_else(|| "--".to_string());
            let jtr = sig.jtr_format.unwrap_or("--");
            println!("{:<45} {:>8}  {:<20}", sig.name, hc, jtr);
        }
        println!("{}", "-".repeat(78));
        println!("{} signatures total.\n", SIGNATURES.len());
        println!("Ambiguous hex hashes default to the most common algorithm.");
        println!("Use -m <mode> to override. Common overrides:");
        println!("  -m 1000  NTLM (instead of MD5 for 32-char hex)");
        println!("  -m 900   MD4");
        println!("  -m 3000  LM");
        println!("  -m 1100  Domain Cached Credentials v1");
        println!("  -m 17400 SHA3-256 (instead of SHA-256 for 64-char hex)");
        println!("  -m 17600 SHA3-512 (instead of SHA-512 for 128-char hex)");
        println!("  -m 6100  Whirlpool (instead of SHA-512 for 128-char hex)");
        println!("  -m 6000  RIPEMD-160 (instead of SHA-1 for 40-char hex)");
        return Ok(());
    }

    // --discover-wordlists: print wordlists and exit
    if args.discover_wordlists {
        let wls = wordlist::discover_wordlists(&args.wordlist_dir);
        let rules = wordlist::find_rules();
        println!("[*] Discovered {} wordlists:\n", wls.len());
        println!("  {:<35} {:>10}  Path", "Name", "Size");
        println!("  {}", "-".repeat(75));
        for wl in &wls {
            let flag = if wl.compressed { " [compressed]" } else { "" };
            println!("  {:<35} {:>10}  {}{}", wl.name, format_size(wl.size_bytes), wl.path.display(), flag);
        }
        println!("\n[*] Discovered {} rule files:\n", rules.len());
        for r in &rules {
            let name = r.file_name().unwrap_or_default().to_string_lossy();
            let size = r.metadata().map(|m| format_size(m.len())).unwrap_or_else(|_| "?".into());
            println!("  {:<35} {:>10}  {}", name, size, r.display());
        }
        println!("\n[*] Search directories (scanned recursively):");
        println!("  Default: ~/wordlists, ~/SecLists, /usr/share/wordlists, /usr/share/seclists, /opt/wordlists");
        if !args.wordlist_dir.is_empty() {
            for d in &args.wordlist_dir {
                println!("  --wordlist-dir: {}", d.display());
            }
        }
        if let Ok(env_dirs) = std::env::var("CRACK_NG_WORDLIST_DIRS") {
            println!("  CRACK_NG_WORDLIST_DIRS: {}", env_dirs);
        }
        println!("\n  Add custom dirs: --wordlist-dir /path/to/dir (repeatable)");
        println!("  Or set:          export CRACK_NG_WORDLIST_DIRS=/path1:/path2");
        return Ok(());
    }

    // Check for binary / non-hash files BEFORE --identify or cracking
    if let Some(hash_file_path) = &args.hashes {
        if let Some(guidance) = detect_binary_input(hash_file_path) {
            println!("{}", guidance);
            return Ok(());
        }
    }

    // --identify: detect hash types and exit (no cracking)
    if args.identify {
        let hash_file_path = args.hashes.as_ref()
            .ok_or_else(|| anyhow::anyhow!("--identify requires a hash file (positional or -H)"))?;
        let content = fs::read_to_string(hash_file_path)
            .context("Failed to read hash file")?;

        let format = if args.format == "auto" {
            parser::detect_format(&content)
        } else {
            parser::parse_format_arg(&args.format)
        };

        // For structured formats, parse to extract actual hash fields.
        // For raw hashes, scan lines directly against SIGNATURES.
        let parsed_hashes = if format != parser::InputFormat::RawHashes {
            parser::parse_input(&content, format.clone())
        } else {
            Vec::new()
        };

        let hash_lines: Vec<String> = if !parsed_hashes.is_empty() {
            // Use parsed hash fields (e.g. NTLM extracted from secretsdump lines)
            parsed_hashes.iter().map(|ph| ph.hash.clone()).collect()
        } else {
            content.lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect()
        };

        let total_lines = content.lines().filter(|l| !l.trim().is_empty()).count();
        println!("[*] Hash file: {} ({} lines)", hash_file_path.display(), total_lines);

        if format != parser::InputFormat::RawHashes {
            println!("[*] Detected input format: {:?} (use --format to override)", format);
            if !parsed_hashes.is_empty() {
                println!("[*] Extracted {} hashes from structured input", hash_lines.len());
            }
        }

        let mut counts: HashMap<&str, (usize, Option<&str>, Option<&str>)> = HashMap::new();
        let mut forced_count: HashMap<&str, usize> = HashMap::new();
        let mut unknown_count = 0usize;

        for (i, h) in hash_lines.iter().enumerate() {
            // Check forced algo from parsed format first
            if let Some(ph) = parsed_hashes.get(i) {
                if let Some((algo_name, hc_mode, jtr_fmt)) = ph.forced_algo {
                    let entry = counts.entry(algo_name).or_insert((0, Some(hc_mode), Some(jtr_fmt)));
                    entry.0 += 1;
                    *forced_count.entry(algo_name).or_insert(0) += 1;
                    continue;
                }
            }
            if let Some(sig) = SIGNATURES.iter().find(|s| s.regex.is_match(h)) {
                let entry = counts.entry(sig.name).or_insert((0, sig.hashcat_mode, sig.jtr_format));
                entry.0 += 1;
            } else {
                unknown_count += 1;
            }
        }

        println!("\n[*] Hash type breakdown:");
        let mut sorted: Vec<_> = counts.iter().collect();
        sorted.sort_by(|a, b| b.1.0.cmp(&a.1.0));
        for (name, (count, hc_mode, jtr_fmt)) in &sorted {
            let hc = hc_mode.map(|m| format!("hashcat -m {}", m)).unwrap_or_else(|| "no hashcat mode".to_string());
            let jtr = jtr_fmt.map(|f| format!("john --format={}", f)).unwrap_or_else(|| "no JtR format".to_string());
            println!("  {:40} {:>5} hashes  ({} / {})", name, count, hc, jtr);
        }
        if unknown_count > 0 {
            println!("  {:40} {:>5} hashes  (use -m to specify)", "Unknown", unknown_count);
        }

        let hw = crack_ng::engine::detect_hardware();
        println!("\n[*] Hardware:");
        if hw.has_gpu {
            println!("  GPU: {} ({} MB VRAM)", hw.gpu_name, hw.gpu_memory_mb);
            println!("  Auto-tuning: workload profile {}, optimized kernels: on", hw.workload_profile);
        } else {
            println!("  No NVIDIA GPU detected -- will use John the Ripper (CPU)");
        }

        println!("\n[*] Recommendations:");
        if hash_lines.len() > 5 {
            println!("  Use --cascade for automated multi-stage attack");
        }
        if unknown_count > 0 {
            println!("  Use -m <mode> to specify hash type for {} unknown hashes", unknown_count);
        }

        return Ok(());
    }

    let mut initial_state = CrackState {
        overall_status: "Initializing".to_string(),
        start_time: Some(Local::now().timestamp()),
        log: VecDeque::from(vec!["[*] crack-ng v1.0.0 Started".to_string()]),
        ..Default::default()
    };

    // Read potfiles on startup to pre-populate recovered list
    let potfile_entries = potfile::read_potfiles();
    if !potfile_entries.is_empty() {
        initial_state.push_log(format!("[*] Loaded {} entries from potfiles", potfile_entries.len()));
    }

    if let Some(session_name) = &args.resume {
        println!("[*] Resuming session: {}", session_name);
        initial_state = load_session(session_name)?;
        initial_state.rebuild_recovered_set();
        initial_state.push_log(format!("[*] Successfully restored session '{}'", session_name));
        initial_state.overall_status = "Resumed Orchestrator".to_string();
    } else {

    if args.hashes.is_none() {
        println!("[*] crack-ng - Starting in Database Viewer Mode...");
        run_db_viewer(args.no_tui, &args.export).await?;
        return Ok(());
    }

    let hash_file_path = args.hashes.as_ref().unwrap();
    let content = fs::read_to_string(hash_file_path).context("Failed to read hash file")?;

    // Detect and parse input format
    let format = if args.format == "auto" {
        parser::detect_format(&content)
    } else {
        parser::parse_format_arg(&args.format)
    };

    let parsed_hashes = if format == parser::InputFormat::RawHashes {
        Vec::new()
    } else {
        let parsed = parser::parse_input(&content, format);
        initial_state.push_log(format!("[*] Parsed {} hashes from structured input", parsed.len()));
        parsed
    };

    // Build hash list and collect format-aware hints
    let mut forced_hints: HashMap<String, (&str, &str, &str)> = HashMap::new();

    let hash_lines: Vec<String> = if !parsed_hashes.is_empty() {
        for ph in &parsed_hashes {
            if let Some(user) = &ph.username {
                let domain_str = ph.domain.as_deref().unwrap_or("");
                if !domain_str.is_empty() {
                    initial_state.push_log(format!("[*] {}\\{} -> {}", domain_str, user, &ph.hash[..ph.hash.len().min(16)]));
                }
            }
            if let Some(hint) = ph.forced_algo {
                forced_hints.insert(ph.hash.clone(), hint);
            }
        }
        parsed_hashes.iter().map(|ph| ph.hash.clone()).collect()
    } else {
        content.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty() && !l.starts_with('#')).collect()
    };

    if hash_lines.is_empty() {
        eprintln!("[!] No hashes extracted from input file (empty or all comments)");
        initial_state.push_log("[!] No hashes extracted from input file (empty or all comments)".to_string());
    }

    let (remaining_hashes, already_cracked) = potfile::filter_known_hashes(&hash_lines, &potfile_entries);
    if !already_cracked.is_empty() {
        initial_state.push_log(format!("[+] {} hashes already cracked (from potfiles)", already_cracked.len()));
        for ac in &already_cracked {
            initial_state.insert_recovered(ExportRecord {
                hash: ac.hash.clone(),
                plaintext: ac.plaintext.clone(),
                algo: "Potfile".to_string(),
                timestamp: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            });
        }
    }

        let mut categorized_hashes: HashMap<String, Vec<String>> = HashMap::new();
        let mut forced_modes: HashMap<String, (String, String)> = HashMap::new();
        let mut unknown_hashes: Vec<String> = Vec::new();

        for h in &remaining_hashes {
            let h = h.trim();
            if h.is_empty() { continue; }
            if let Some((algo_name, hc_mode, jtr_fmt)) = forced_hints.get(h) {
                categorized_hashes.entry(algo_name.to_string()).or_default().push(h.to_string());
                forced_modes.insert(algo_name.to_string(), (hc_mode.to_string(), jtr_fmt.to_string()));
            } else if let Some(sig) = SIGNATURES.iter().find(|s| s.regex.is_match(h)) {
                categorized_hashes.entry(sig.name.to_string()).or_default().push(h.to_string());
            } else {
                unknown_hashes.push(h.to_string());
            }
        }

        let mut job_counter = 0;

        for (algo, hashes) in &mut categorized_hashes {
            let before = hashes.len();
            let mut seen = std::collections::HashSet::new();
            hashes.retain(|h| seen.insert(h.clone()));
            if hashes.len() < before {
                initial_state.push_log(format!("[*] Deduped {} -> {} hashes for {}", before, hashes.len(), algo));
            }
        }

        // Sort by algorithm name for deterministic job ordering across runs
        let mut sorted_algos: Vec<(String, Vec<String>)> = categorized_hashes.into_iter().collect();
        sorted_algos.sort_by(|a, b| a.0.cmp(&b.0));

        for (algo, hashes) in sorted_algos {
            let (hc_mode, jtr_fmt) = if let Some((hc, jtr)) = forced_modes.get(&algo) {
                (Some(hc.clone()), Some(jtr.clone()))
            } else if let Some(sig) = SIGNATURES.iter().find(|s| s.name == algo) {
                (sig.hashcat_mode.map(|s| s.to_string()), sig.jtr_format.map(|s| s.to_string()))
            } else {
                (None, None)
            };

            let mut tmp = NamedTempFile::new()?;
            for h in &hashes { writeln!(tmp, "{}", h)?; }
            let path = tmp.into_temp_path().keep()?;

            initial_state.jobs.push(Job {
                id: job_counter,
                algo_name: algo.clone(),
                hashcat_mode: hc_mode,
                jtr_format: jtr_fmt,
                hash_file_path: path.to_string_lossy().to_string(),
                total_hashes: hashes.len(),
                status: "Pending".to_string(),
                speed: "-".to_string(),
                eta: "-".to_string(),
                eta_seconds: 0,
                cracked: 0,
                engine_used: "Pending".to_string(),
            });
            job_counter += 1;
        }

        {
            let before = unknown_hashes.len();
            let mut seen = std::collections::HashSet::new();
            unknown_hashes.retain(|h| seen.insert(h.clone()));
            if unknown_hashes.len() < before {
                initial_state.push_log(format!("[*] Deduped {} -> {} unknown hashes", before, unknown_hashes.len()));
            }
        }

        if !unknown_hashes.is_empty() {
            let mut tmp = NamedTempFile::new()?;
            for h in &unknown_hashes { writeln!(tmp, "{}", h)?; }
            let path = tmp.into_temp_path().keep()?;

            let mut hc_mode = None;
            let mut jt_fmt = None;

            if let Some(m) = &args.mode {
                hc_mode = Some(m.clone());
                // Look up the JtR format from SIGNATURES by hashcat mode number.
                // JtR format names differ from hashcat mode numbers.
                jt_fmt = SIGNATURES.iter()
                    .find(|s| s.hashcat_mode == Some(m.as_str()))
                    .and_then(|s| s.jtr_format.map(|f| f.to_string()));
            }

            initial_state.jobs.push(Job {
                id: job_counter,
                algo_name: match &args.mode { Some(m) => format!("Fallback Mode: {}", m), None => "Unknown (Skipped)".to_string() },
                hashcat_mode: hc_mode,
                jtr_format: jt_fmt,
                hash_file_path: path.to_string_lossy().to_string(),
                total_hashes: unknown_hashes.len(),
                status: if args.mode.is_some() { "Pending".to_string() } else { "Skipped".to_string() },
                speed: "-".to_string(),
                eta: "-".to_string(),
                eta_seconds: 0,
                cracked: 0,
                engine_used: "None".to_string(),
            });
        }

        initial_state.push_log(format!("[*] Loaded {} jobs across algorithms", initial_state.jobs.len()));
    }

    // Discover wordlists if cascade mode
    let cascade_config = if args.cascade {
        let mut wls = wordlist::discover_wordlists(&args.wordlist_dir);
        let rules = wordlist::find_rules();
        let compressed_count = wls.iter().filter(|w| w.compressed).count();
        initial_state.push_log(format!("[*] Cascade: discovered {} wordlists, {} rule files", wls.len(), rules.len()));

        // Decompress any compressed wordlists (e.g. rockyou.txt.gz) so engines can read them
        if compressed_count > 0 {
            initial_state.push_log(format!("[*] Decompressing {} compressed wordlists...", compressed_count));
            for wl in &mut wls {
                if wl.compressed {
                    if let Some(decompressed) = wordlist::decompress_wordlist(wl) {
                        let size = decompressed.metadata().map(|m| m.len()).unwrap_or(0);
                        initial_state.push_log(format!("[+] Decompressed {} -> {} ({})", wl.name, decompressed.display(), format_size(size)));
                        wl.path = decompressed;
                        wl.size_bytes = size;
                        wl.compressed = false;
                    } else {
                        initial_state.push_log(format!("[!] Failed to decompress {}, skipping", wl.name));
                    }
                }
            }
            // Re-sort after decompression changed sizes
            wls.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));
            // Remove still-compressed entries (failed decompression)
            wls.retain(|w| !w.compressed);
        }
        let config = cascade::build_default_cascade(args.wordlist.as_ref(), &wls, &rules);
        // Build structured cascade plan for the Strategy tab
        initial_state.cascade_plan = config.stages.iter().enumerate().map(|(i, stage)| {
            let label = match stage {
                cascade::CascadeStage::PotfileCheck => "Potfile recovery (hashcat --show / john --show)".to_string(),
                cascade::CascadeStage::WordlistAttack { wordlist, rules } => {
                    let wl_name = wordlist.file_name().unwrap_or_default().to_string_lossy();
                    let wl_size = wordlist.metadata().map(|m| format_size(m.len())).unwrap_or_else(|_| "?".into());
                    match rules {
                        Some(r) => format!("Wordlist: {} ({}) + Rules: {}", wl_name, wl_size, r.file_name().unwrap_or_default().to_string_lossy()),
                        None => format!("Wordlist: {} ({})", wl_name, wl_size),
                    }
                }
                cascade::CascadeStage::MaskAttack { masks } => format!("Mask attack ({} patterns)", masks.len()),
                cascade::CascadeStage::IncrementalBrute { min_len, max_len, charset } => {
                    format!("Brute force {}-{} chars ({})", min_len, max_len, charset)
                }
            };
            format!("Stage {}: {}", i + 1, label)
        }).collect();
        Some(config)
    } else {
        None
    };

    let state = Arc::new(Mutex::new(initial_state));

    if args.no_tui {
        println!("[*] crack-ng - Running in standard CLI batch mode...");
        if let Some(config) = cascade_config {
            run_cascade_orchestrator(&args, state.clone(), config).await;
        } else {
            run_orchestrator(&args, state.clone()).await;
        }

        // Post-cascade: analyze cracked passwords for mask heuristics
        if args.cascade {
            let s = state.lock().await;
            let plaintexts: Vec<String> = s.recovered.iter().map(|r| r.plaintext.clone()).collect();
            let dynamic_masks = mask::analyze_cracked_passwords(&plaintexts);
            if !dynamic_masks.is_empty() {
                println!("[*] Discovered {} password mask patterns", dynamic_masks.len());
            }
        }

        let s = state.lock().await;
        println!("\n[*] Recovered {} hashes", s.recovered.len());
        for r in &s.recovered { println!("{}: {}", r.hash, r.plaintext); }
        if let Some(export_path) = &args.export { export_results(export_path, &s.recovered)?; }

        if let Some(report_path) = &args.report {
            let rpt = report::generate_report(&s);
            let html = report::render_html(&rpt);
            fs::write(report_path, html)?;
            println!("[+] Report written to {}", report_path.display());
        }

        return Ok(());
    }

    // TUI Setup -- install panic hook to restore terminal on crash
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(std::io::stdout(), LeaveAlternateScreen);
        original_hook(info);
    }));

    enable_raw_mode()?;

    // RAII guard: restores terminal on any early exit (? propagation, break, etc.)
    struct TermGuard(bool);
    impl Drop for TermGuard {
        fn drop(&mut self) {
            if !self.0 {
                let _ = disable_raw_mode();
                let _ = execute!(std::io::stdout(), LeaveAlternateScreen);
            }
        }
    }
    let mut _term_guard = TermGuard(false);

    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let state_bg = state.clone();
    let args_clone = args.clone();

    tokio::spawn(async move {
        if let Some(config) = cascade_config {
            run_cascade_orchestrator(&args_clone, state_bg, config).await;
        } else {
            run_orchestrator(&args_clone, state_bg).await;
        }
    });

    loop {
        let s = {
            let mut st = state.lock().await;
            // Regenerate report when viewing tab 3. This is cheap (vector
            // iteration + math) and ensures duration/stats stay in sync with
            // the Dashboard uptime and other live fields.
            if st.active_tab == 3 {
                let current_count = st.recovered.len();
                let rpt = report::generate_report(&st);
                let text = report::render_text(&rpt);
                st.cached_report_text = Some((current_count, text));
            }
            st.clone()
        };
        terminal.draw(|f| {
            draw_main_ui(f, &s, &args.session);
        })?;

        if event::poll(std::time::Duration::from_millis(150))? {
            if let Event::Key(key) = event::read()? {
                let mut st = state.lock().await;

                // Search input mode: capture chars for the search query
                if st.search_active {
                    match key.code {
                        KeyCode::Esc => {
                            st.search_active = false;
                            st.search_query.clear();
                        }
                        KeyCode::Enter => {
                            st.search_active = false;
                        }
                        KeyCode::Backspace => {
                            st.search_query.pop();
                        }
                        KeyCode::Char(c) => {
                            st.search_query.push(c);
                        }
                        _ => {}
                    }
                    continue;
                }

                match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') => {
                        st.quit_requested = true;
                        if let Some(pid) = st.active_child_pid {
                            unsafe { libc::kill(pid as i32, libc::SIGTERM); }
                        }
                        break;
                    }
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        st.quit_requested = true;
                        if let Some(pid) = st.active_child_pid {
                            unsafe { libc::kill(pid as i32, libc::SIGTERM); }
                        }
                        break;
                    }
                    KeyCode::Char('1') => st.active_tab = 0,
                    KeyCode::Char('2') => st.active_tab = 1,
                    KeyCode::Char('3') => st.active_tab = 2,
                    KeyCode::Char('4') => st.active_tab = 3,
                    KeyCode::Char('5') => st.active_tab = 4,
                    KeyCode::Tab => {
                        let max_tab = 4;
                        st.active_tab = if st.active_tab >= max_tab { 0 } else { st.active_tab + 1 };
                    }
                    KeyCode::BackTab => {
                        let max_tab = 4;
                        st.active_tab = if st.active_tab == 0 { max_tab } else { st.active_tab - 1 };
                    }
                    KeyCode::Char('/') if st.active_tab == 2 => {
                        st.search_active = true;
                        st.search_query.clear();
                    }
                    KeyCode::Esc if !st.search_query.is_empty() => {
                        st.search_query.clear();
                    }
                    KeyCode::Char('e') | KeyCode::Char('E') => {
                        let export_path = std::path::PathBuf::from("crack-ng-export.csv");
                        let count = st.recovered.len();
                        match export_results(&export_path, &st.recovered) {
                            Ok(_) => st.push_log(format!("[+] Exported {} hashes to {}", count, export_path.display())),
                            Err(e) => st.push_log(format!("[!] Export failed: {}", e)),
                        }
                    }
                    KeyCode::Char('?') => st.show_help = !st.show_help,
                    KeyCode::Char('p') | KeyCode::Char('P') => {
                        if st.overall_status != "Finished" {
                            st.is_paused = !st.is_paused;
                            if st.is_paused {
                                st.push_log("[*] Paused -- press P to resume.".to_string());
                            } else {
                                st.push_log("[*] Resumed.".to_string());
                            }
                        }
                    }
                    KeyCode::Char('s') | KeyCode::Char('S') => {
                        if st.overall_status != "Finished" && st.cascade_stage.is_some() {
                            st.skip_stage_requested = true;
                            st.push_log("[*] Skip requested -- advancing to next cascade stage...".to_string());
                        } else if st.overall_status != "Finished" {
                            st.push_log("[!] Skip is only available in cascade mode.".to_string());
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    _term_guard.0 = true; // mark guard as handled -- normal cleanup follows
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    let s = state.lock().await;

    if let Some(session_name) = &args.session {
        if let Err(e) = save_session(session_name, &s) {
            println!("[-] Failed to auto-save session on exit: {}", e);
        } else {
            println!("[+] Session state automatically saved to '{}'", session_name);
        }
    }

    if let Some(export_path) = &args.export {
        export_results(export_path, &s.recovered)?;
        println!("[+] Exported {} hashes to {}", s.recovered.len(), export_path.display());
    }

    if let Some(report_path) = &args.report {
        let rpt = report::generate_report(&s);
        let html = report::render_html(&rpt);
        fs::write(report_path, html)?;
        println!("[+] Report written to {}", report_path.display());
    }

    Ok(())
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

/// Detect binary / non-hash input files and return extraction guidance.
/// Returns None if the file appears to be a text hash file.
fn detect_binary_input(path: &Path) -> Option<String> {
    // Check file extension first (fast path)
    let ext = path.extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    let guidance = match ext.as_str() {
        "pcap" | "pcapng" | "cap" => Some((
            "WPA/WPA2 capture file",
            "hcxpcapngtool -o hashes.22000",
            "crack-ng hashes.22000",
        )),
        "hccapx" => Some((
            "WPA/WPA2 capture (legacy format)",
            "hcxpcapngtool -o hashes.22000",
            "crack-ng hashes.22000",
        )),
        "kdbx" | "kdb" => Some((
            "KeePass database",
            "keepass2john",
            "crack-ng keepass_hash.txt",
        )),
        "docx" | "xlsx" | "pptx" => Some((
            "MS Office 2007+ document (encrypted)",
            "office2john.py",
            "crack-ng office_hash.txt",
        )),
        "doc" | "xls" | "ppt" => Some((
            "MS Office 97-2003 document (encrypted)",
            "office2john.py",
            "crack-ng office_hash.txt",
        )),
        "pdf" => {
            // Could be a hash file with .pdf extension, or an actual PDF
            // Check magic bytes
            if check_magic_bytes(path, b"%PDF") {
                Some((
                    "PDF document (encrypted)",
                    "pdf2john.py",
                    "crack-ng pdf_hash.txt",
                ))
            } else {
                None
            }
        }
        "rar" => Some((
            "RAR archive (encrypted)",
            "rar2john",
            "crack-ng rar_hash.txt",
        )),
        "zip" => Some((
            "ZIP archive (encrypted)",
            "zip2john",
            "crack-ng zip_hash.txt",
        )),
        "7z" => Some((
            "7-Zip archive (encrypted)",
            "7z2john.pl",
            "crack-ng 7z_hash.txt",
        )),
        "tc" => Some((
            "TrueCrypt volume",
            "truecrypt2hashcat.py (extracts header for hashcat -m 6211..6243)\n    OR: john --format=tc_aes_xts",
            "crack-ng truecrypt_hash.txt",
        )),
        "hc" => Some((
            "VeraCrypt volume",
            "veracrypt2hashcat.py (extracts header for hashcat -m 13711..13773)\n    OR: john --format=vc",
            "crack-ng veracrypt_hash.txt",
        )),
        _ => None,
    };

    if let Some((file_type, tool, crack_cmd)) = guidance {
        return Some(format!(
            "[!] {} appears to be a {}, not a hash file.\n    Extract hashes first:\n      {} {}\n    Then crack:\n      {}",
            path.display(), file_type, tool, path.display(), crack_cmd
        ));
    }

    // Fall back to magic byte detection for files without recognized extensions
    if check_magic_bytes(path, b"\x89PNG") || check_magic_bytes(path, b"\xff\xd8\xff") {
        return Some(format!(
            "[!] {} appears to be an image file, not a hash file.",
            path.display()
        ));
    }
    if check_magic_bytes(path, b"PK\x03\x04") {
        return Some(format!(
            "[!] {} appears to be a ZIP/Office archive.\n    If encrypted, extract hashes first:\n      zip2john {} > zip_hash.txt\n    Then crack:\n      crack-ng zip_hash.txt",
            path.display(), path.display()
        ));
    }
    if check_magic_bytes(path, b"\xd0\xcf\x11\xe0") {
        return Some(format!(
            "[!] {} appears to be an OLE2/MS Office file.\n    Extract hashes first:\n      office2john.py {} > office_hash.txt\n    Then crack:\n      crack-ng office_hash.txt",
            path.display(), path.display()
        ));
    }

    None
}

fn check_magic_bytes(path: &Path, magic: &[u8]) -> bool {
    let mut buf = vec![0u8; magic.len()];
    if let Ok(mut f) = std::fs::File::open(path) {
        if f.read_exact(&mut buf).is_ok() {
            return buf == magic;
        }
    }
    false
}

/// Check if a string looks like a hash rather than a file path.
/// Matches: hex strings (32-128 chars), $-prefixed hashes, {}-prefixed LDAP hashes,
/// colon-delimited structured hashes, and other known patterns.
fn looks_like_hash(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() || s.len() < 8 {
        return false;
    }
    // $-prefixed hash formats ($2a$, $6$, $krb5tgs$, $pdf$, etc.)
    if s.starts_with('$') {
        return true;
    }
    // {}-prefixed LDAP hashes ({SSHA}, {SHA256}, etc.)
    if s.starts_with('{') && s.contains('}') {
        return true;
    }
    // grub.pbkdf2.sha512 format
    if s.starts_with("grub.pbkdf2.") {
        return true;
    }
    // WPA*02* format
    if s.starts_with("WPA*") {
        return true;
    }
    // 0x-prefixed (MSSQL: 0x0100... or 0x0200...)
    if (s.starts_with("0x0100") || s.starts_with("0x0200")) && s.len() > 10 && s[6..].chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    // *hex40 (MySQL)
    if s.starts_with('*') && s.len() == 41 && s[1..].chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    // S:hex60 (Oracle 11g)
    if s.starts_with("S:") && s.len() == 62 && s[2..].chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    // Pure hex strings of common hash lengths (32=MD5, 40=SHA1, 64=SHA256, 96=SHA384, 128=SHA512)
    let hex_lengths = [32, 40, 64, 96, 128];
    if hex_lengths.contains(&s.len()) && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    // NetNTLM format: user::domain:challenge:hash:blob (must have :: and 5+ colons)
    if s.contains("::") && s.chars().filter(|&c| c == ':').count() >= 5 && s.len() > 30 {
        return true;
    }
    // LM:NT pair (hex32:hex32)
    if s.len() == 65 && s.chars().nth(32) == Some(':')
        && s[..32].chars().all(|c| c.is_ascii_hexdigit())
        && s[33..].chars().all(|c| c.is_ascii_hexdigit())
    {
        return true;
    }
    // pbkdf2_sha256$ (Django)
    if s.starts_with("pbkdf2_sha256$") {
        return true;
    }
    false
}
