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
    let args = Args::parse();

    // --discover-wordlists: print wordlists and exit
    if args.discover_wordlists {
        let wls = wordlist::discover_wordlists();
        let rules = wordlist::find_rules();
        println!("[*] Discovered {} wordlists:", wls.len());
        for wl in &wls {
            println!("  {} ({} bytes) - {}", wl.name, wl.size_bytes, wl.path.display());
        }
        println!("\n[*] Discovered {} rule files:", rules.len());
        for r in &rules {
            println!("  {}", r.display());
        }
        return Ok(());
    }

    let mut initial_state = CrackState {
        overall_status: "Initializing".to_string(),
        start_time: Some(Local::now().timestamp()),
        log: VecDeque::from(vec!["[*] crack-ng v2.0 Started".to_string()]),
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
    let hash_lines: Vec<String>;
    let mut forced_hints: HashMap<String, (&str, &str, &str)> = HashMap::new();

    if !parsed_hashes.is_empty() {
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
        hash_lines = parsed_hashes.iter().map(|ph| ph.hash.clone()).collect();
    } else {
        hash_lines = content.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
    };

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
        let mut temp_paths = Vec::new();

        for (algo, hashes) in &mut categorized_hashes {
            let before = hashes.len();
            let mut seen = std::collections::HashSet::new();
            hashes.retain(|h| seen.insert(h.clone()));
            if hashes.len() < before {
                initial_state.push_log(format!("[*] Deduped {} -> {} hashes for {}", before, hashes.len(), algo));
            }
        }

        for (algo, hashes) in categorized_hashes {
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
                cracked: 0,
                engine_used: "Pending".to_string(),
            });
            temp_paths.push(path);
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
                jt_fmt = Some(m.clone());
            }

            initial_state.jobs.push(Job {
                id: job_counter,
                algo_name: if args.mode.is_some() { format!("Fallback Mode: {}", args.mode.as_ref().unwrap()) } else { "Unknown (Skipped)".to_string() },
                hashcat_mode: hc_mode,
                jtr_format: jt_fmt,
                hash_file_path: path.to_string_lossy().to_string(),
                total_hashes: unknown_hashes.len(),
                status: if args.mode.is_some() { "Pending".to_string() } else { "Skipped".to_string() },
                speed: "-".to_string(),
                eta: "-".to_string(),
                cracked: 0,
                engine_used: "None".to_string(),
            });
        }

        initial_state.push_log(format!("[*] Loaded {} jobs across algorithms", initial_state.jobs.len()));
    }

    // Discover wordlists if cascade mode
    let cascade_config = if args.cascade {
        let wls = wordlist::discover_wordlists();
        let rules = wordlist::find_rules();
        initial_state.push_log(format!("[*] Cascade: discovered {} wordlists, {} rule files", wls.len(), rules.len()));
        initial_state.discovered_wordlists = wls.iter()
            .map(|wl| format!("{} ({} bytes) - {}", wl.name, wl.size_bytes, wl.path.display()))
            .collect();
        let config = cascade::build_default_cascade(&wls, &rules);
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

    // TUI Setup
    enable_raw_mode()?;
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
        let s = state.lock().await.clone();
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
                            if st.search_query.is_empty() {
                                st.search_active = false;
                            }
                        }
                        KeyCode::Char(c) => {
                            st.search_query.push(c);
                        }
                        _ => {}
                    }
                    continue;
                }

                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
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
                    KeyCode::Char('s') => {
                        if let Some(session_name) = &args.session {
                            if let Err(e) = save_session(session_name, &st) {
                                st.push_log(format!("[!] Session save failed: {}", e));
                            } else {
                                st.push_log(format!("[+] Session '{}' forcefully saved to disk.", session_name));
                            }
                        } else {
                            st.push_log("[!] Cannot save: No --session <name> argument provided at startup.".to_string());
                        }
                    }
                    _ => {}
                }
            }
        }
    }

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
