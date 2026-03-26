use crate::state::{CrackState, ExportRecord};
use crate::session::get_session_dir;
use crate::export::export_results;
use crate::report;
use ratatui::{
    widgets::{Block, Borders, Paragraph, List, ListItem, Clear, BorderType, Table, Row, Tabs},
    layout::{Layout, Constraint, Direction, Rect, Alignment},
    style::{Style, Color, Modifier},
    text::{Span, Line},
    Frame,
};
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use anyhow::Result;
use std::{fs, path::PathBuf};
use chrono::Local;

pub fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage((100 - percent_y) / 2), Constraint::Percentage(percent_y), Constraint::Percentage((100 - percent_y) / 2)].as_ref())
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage((100 - percent_x) / 2), Constraint::Percentage(percent_x), Constraint::Percentage((100 - percent_x) / 2)].as_ref())
        .split(popup_layout[1])[1]
}

pub fn draw_main_ui(f: &mut Frame, s: &CrackState, session_name: &Option<String>) {
    let size = f.size();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(10), Constraint::Length(1)].as_ref())
        .split(size);

    let session_txt = if let Some(sn) = session_name { format!(" [Session: {}] ", sn) } else { " [Ephemeral Session] ".to_string() };
    let titles = vec![" [1] Live Dashboard ", " [2] Job Queue ", " [3] Recovered ", " [4] Report ", " [5] Wordlists "];
    let tabs = Tabs::new(titles.iter().cloned().map(Line::from).collect::<Vec<_>>())
        .select(s.active_tab)
        .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded).title(format!(" crack-ng v2.0 - Ultimate Orchestrator{} ", session_txt)).title_alignment(Alignment::Center))
        .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
        .divider(Span::raw("|"));
    f.render_widget(tabs, chunks[0]);

    match s.active_tab {
        0 => {
            let dash_chunks = Layout::default().direction(Direction::Horizontal).constraints([Constraint::Percentage(70), Constraint::Percentage(30)].as_ref()).split(chunks[1]);

            let log_lines: Vec<ListItem> = s.log.iter().map(|l| {
                if l.contains("Error") || l.contains("Warning") || l.contains("[!]") { ListItem::new(l.clone()).style(Style::default().fg(Color::Red)) }
                else if l.starts_with("[+]") { ListItem::new(l.clone()).style(Style::default().fg(Color::Green)) }
                else { ListItem::new(l.clone()).style(Style::default().fg(Color::DarkGray)) }
            }).collect();
            let log_list = List::new(log_lines).block(Block::default().title(" Event Stream ").borders(Borders::ALL).border_type(BorderType::Rounded));
            f.render_widget(log_list, dash_chunks[0]);

            let mut active_job_txt = vec![Line::from(vec![Span::styled("Overall Status: ", Style::default().fg(Color::DarkGray)), Span::styled(&s.overall_status, Style::default().fg(if s.overall_status == "Finished" {Color::Green} else {Color::Cyan}))])];

            let uptime = if let Some(start) = s.start_time {
                let diff = Local::now().timestamp() - start;
                format!("{:02}:{:02}:{:02}", diff / 3600, (diff % 3600) / 60, diff % 60)
            } else { "00:00:00".to_string() };
            active_job_txt.push(Line::from(vec![Span::styled("Uptime:         ", Style::default().fg(Color::DarkGray)), Span::raw(uptime)]));
            active_job_txt.push(Line::from(""));

            if let Some(idx) = s.active_job_idx {
                let j = &s.jobs[idx];
                active_job_txt.push(Line::from(vec![Span::styled("Active Algo: ", Style::default().fg(Color::DarkGray)), Span::styled(&j.algo_name, Style::default().fg(Color::Magenta))]));
                active_job_txt.push(Line::from(vec![Span::styled("Engine:      ", Style::default().fg(Color::DarkGray)), Span::styled(&j.engine_used, Style::default().fg(Color::LightBlue))]));
                active_job_txt.push(Line::from(vec![Span::styled("Job Status:  ", Style::default().fg(Color::DarkGray)), Span::styled(&j.status, Style::default().fg(Color::Yellow))]));
                active_job_txt.push(Line::from(vec![Span::styled("Speed:       ", Style::default().fg(Color::DarkGray)), Span::raw(&j.speed)]));

                let pct = if j.total_hashes > 0 { (j.cracked as f64 / j.total_hashes as f64) * 100.0 } else { 0.0 };
                active_job_txt.push(Line::from(vec![Span::styled("Job Cracked: ", Style::default().fg(Color::DarkGray)), Span::raw(format!("{}/{} ({:.1}%)", j.cracked, j.total_hashes, pct))]));
                active_job_txt.push(Line::from(vec![Span::styled("Temp File:   ", Style::default().fg(Color::DarkGray)), Span::raw(&j.hash_file_path)]));
            } else {
                active_job_txt.push(Line::from("No active job running."));
            }
            active_job_txt.push(Line::from(""));
            active_job_txt.push(Line::from(vec![Span::styled("Global Recovered: ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)), Span::styled(format!("{}", s.recovered.len()), Style::default().fg(Color::Green))]));

            let stats = Paragraph::new(active_job_txt).block(Block::default().title(" Telemetry ").borders(Borders::ALL).border_type(BorderType::Rounded));
            f.render_widget(stats, dash_chunks[1]);
        },
        1 => {
            let rows: Vec<Row> = s.jobs.iter().map(|j| {
                let pct = if j.total_hashes > 0 { (j.cracked as f64 / j.total_hashes as f64) * 100.0 } else { 0.0 };
                Row::new(vec![
                    j.algo_name.clone(),
                    j.engine_used.clone(),
                    j.total_hashes.to_string(),
                    format!("{:.1}%", pct),
                    j.status.clone(),
                    j.speed.clone(),
                ]).style(if j.status == "Cracking" { Style::default().fg(Color::Yellow) } else if j.status == "Complete" { Style::default().fg(Color::Green) } else if j.status == "Exhausted" || j.status.contains("Skipped") { Style::default().fg(Color::DarkGray) } else { Style::default() })
            }).collect();
            let widths = [Constraint::Percentage(25), Constraint::Percentage(15), Constraint::Percentage(15), Constraint::Percentage(15), Constraint::Percentage(15), Constraint::Percentage(15)];
            let table = Table::new(rows, widths)
                .header(Row::new(vec!["Algorithm", "Engine", "Total Hashes", "Cracked", "Status", "Speed"]).style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)))
                .block(Block::default().title(format!(" Batch Queue ({} Jobs) ", s.jobs.len())).borders(Borders::ALL).border_type(BorderType::Rounded));
            f.render_widget(table, chunks[1]);
        },
        2 => {
            let content_area = if s.search_active || !s.search_query.is_empty() {
                let split = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Length(3), Constraint::Min(5)].as_ref())
                    .split(chunks[1]);
                let cursor_char = if s.search_active { "_" } else { "" };
                let search_bar = Paragraph::new(format!(" /{}{}", s.search_query, cursor_char))
                    .block(Block::default().title(" Search (Esc to clear) ").borders(Borders::ALL).border_type(BorderType::Rounded))
                    .style(Style::default().fg(if s.search_active { Color::Yellow } else { Color::DarkGray }));
                f.render_widget(search_bar, split[0]);
                split[1]
            } else {
                chunks[1]
            };

            // Newest first: iterate in reverse
            let filtered: Vec<&ExportRecord> = s.recovered.iter().rev().filter(|r| {
                if s.search_query.is_empty() {
                    return true;
                }
                let q = s.search_query.to_lowercase();
                r.hash.to_lowercase().contains(&q)
                    || r.plaintext.to_lowercase().contains(&q)
                    || r.algo.to_lowercase().contains(&q)
            }).collect();

            let rows: Vec<Row> = filtered.iter().map(|r| {
                Row::new(vec![r.timestamp.clone(), r.algo.clone(), r.hash.clone(), r.plaintext.clone()]).style(Style::default().fg(Color::Green))
            }).collect();
            let title = if s.search_query.is_empty() {
                format!(" Recovered Database ({}) -- newest first ", s.recovered.len())
            } else {
                format!(" Recovered Database ({}/{} matched) ", filtered.len(), s.recovered.len())
            };
            let widths = [Constraint::Percentage(15), Constraint::Percentage(15), Constraint::Percentage(35), Constraint::Percentage(35)];
            let table = Table::new(rows, widths)
                .header(Row::new(vec!["Timestamp", "Algorithm", "Hash", "Plaintext"]).style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)))
                .block(Block::default().title(title).borders(Borders::ALL).border_type(BorderType::Rounded));
            f.render_widget(table, content_area);
        },
        3 => {
            let rpt = report::generate_report(s);
            let mut text = report::render_text(&rpt);
            if s.overall_status != "Finished" {
                text.insert_str(0, &format!("[Cascade still running: {}]\n\n", s.cascade_stage.as_deref().unwrap_or(&s.overall_status)));
            }
            let paragraph = Paragraph::new(text)
                .block(Block::default().title(" Post-Crack Analysis ").borders(Borders::ALL).border_type(BorderType::Rounded))
                .style(Style::default().fg(Color::White));
            f.render_widget(paragraph, chunks[1]);
        },
        4 => {
            if s.discovered_wordlists.is_empty() {
                let msg = Paragraph::new("No wordlists discovered. Use --cascade or --discover-wordlists to scan.")
                    .block(Block::default().title(" Discovered Wordlists ").borders(Borders::ALL).border_type(BorderType::Rounded))
                    .style(Style::default().fg(Color::DarkGray));
                f.render_widget(msg, chunks[1]);
            } else {
                let rows: Vec<Row> = s.discovered_wordlists.iter().map(|entry| {
                    Row::new(vec![entry.clone()]).style(Style::default().fg(Color::Cyan))
                }).collect();
                let widths = [Constraint::Percentage(100)];
                let table = Table::new(rows, widths)
                    .header(Row::new(vec!["Wordlist Path (sorted by size)"]).style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)))
                    .block(Block::default().title(format!(" Discovered Wordlists ({}) ", s.discovered_wordlists.len())).borders(Borders::ALL).border_type(BorderType::Rounded));
                f.render_widget(table, chunks[1]);
            }
        },
        _ => {}
    }

    let footer = Paragraph::new(" [1-5/Tab/Shift-Tab] Tabs | [/] Search | [E] Export | [Q/Ctrl+C] Quit | [?] Help | [S] Save ")
        .style(Style::default().fg(Color::DarkGray)).alignment(Alignment::Center);
    f.render_widget(footer, chunks[2]);

    if s.show_help {
        let area = centered_rect(50, 40, size);
        f.render_widget(Clear, area);
        let help = Paragraph::new(vec![
            Line::from(Span::styled("Keyboard Shortcuts", Style::default().add_modifier(Modifier::BOLD))),
            Line::from(""),
            Line::from("Q / Ctrl+C : Gracefully terminate & exit"),
            Line::from("1-5        : Navigate interface tabs"),
            Line::from("Tab/S-Tab  : Cycle tabs forward/backward"),
            Line::from("/          : Search recovered hashes (on Recovered tab)"),
            Line::from("E          : Export recovered hashes to crack-ng-export.csv"),
            Line::from("S          : Force save current session to ~/.crack-ng/sessions/"),
            Line::from("?          : Toggle this help menu"),
            Line::from(""),
            Line::from(Span::styled("Advanced Features", Style::default().add_modifier(Modifier::BOLD))),
            Line::from("--session <name> : Saves job queue and cracked passwords to disk incrementally."),
            Line::from("--resume <name>  : Skips hash parsing and instantly resumes a saved queue."),
            Line::from("--export <file>  : Auto-dumps Recovered Database to JSON or CSV on exit."),
            Line::from("--mode <id>      : Universal fallback mode for unidentified hashes in your file."),
            Line::from("--cascade        : Smart attack cascade (wordlist -> rules -> masks -> brute)."),
            Line::from("--format <type>  : Input format: auto, ntds, shadow, kerberoast, asrep, responder."),
            Line::from("--report <path>  : Generate HTML post-crack report on exit."),
        ])
        .block(Block::default().title(" Help & Operations ").borders(Borders::ALL).border_type(BorderType::Double).style(Style::default().fg(Color::Yellow)));
        f.render_widget(help, area);
    }
}

struct SessionInfo {
    name: String,
    jobs: usize,
    recovered: usize,
    algos: String,
    path: PathBuf,
}

fn detect_tool(name: &str) -> (bool, String) {
    match std::process::Command::new("which").arg(name).output() {
        Ok(out) if out.status.success() => {
            let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
            (true, path)
        }
        _ => (false, "not found".to_string()),
    }
}

fn detect_gpu() -> String {
    match std::process::Command::new("nvidia-smi")
        .arg("--query-gpu=name,memory.total")
        .arg("--format=csv,noheader,nounits")
        .output()
    {
        Ok(out) if out.status.success() => {
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }
        _ => "No NVIDIA GPU detected".to_string(),
    }
}

fn load_sessions() -> Vec<SessionInfo> {
    let session_dir = get_session_dir();
    let mut sessions = Vec::new();
    if let Ok(entries) = fs::read_dir(&session_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            let json_path = if p.is_dir() {
                let candidate = p.join("session.json");
                if candidate.exists() { candidate } else { continue }
            } else if p.extension().unwrap_or_default() == "json" {
                p.clone()
            } else {
                continue
            };
            if let Ok(json) = fs::read_to_string(&json_path) {
                if let Ok(state) = serde_json::from_str::<CrackState>(&json) {
                    let name = if p.is_dir() {
                        p.file_name().unwrap_or_default().to_string_lossy().to_string()
                    } else {
                        p.file_stem().unwrap_or_default().to_string_lossy().to_string()
                    };
                    let algos: Vec<String> = state.jobs.iter().map(|j| j.algo_name.clone()).collect();
                    sessions.push(SessionInfo {
                        name,
                        jobs: state.jobs.len(),
                        recovered: state.recovered.len(),
                        algos: if algos.is_empty() { "-".into() } else { algos.join(", ") },
                        path: json_path,
                    });
                }
            }
        }
    }
    sessions
}

fn load_all_recovered() -> Vec<ExportRecord> {
    let mut all: Vec<ExportRecord> = Vec::new();
    for si in &load_sessions() {
        if let Ok(json) = fs::read_to_string(&si.path) {
            if let Ok(state) = serde_json::from_str::<CrackState>(&json) {
                for r in state.recovered {
                    if !all.iter().any(|e| e.hash == r.hash) {
                        all.push(r);
                    }
                }
            }
        }
    }
    all
}

pub async fn run_db_viewer(no_tui: bool, export_path: &Option<PathBuf>) -> Result<()> {
    let all_recovered = load_all_recovered();

    if no_tui {
        println!("[*] crack-ng - Dumping Global Recovered Database...");
        println!("[*] Recovered {} unique hashes.", all_recovered.len());
        for r in &all_recovered {
            println!("{}: {}", r.hash, r.plaintext);
        }
        if let Some(path) = export_path {
            export_results(path, &all_recovered)?;
            println!("[+] Exported to {}", path.display());
        }
        return Ok(());
    }

    let (has_hashcat, hashcat_path) = detect_tool("hashcat");
    let (has_john, john_path) = detect_tool("john");
    let gpu_info = detect_gpu();
    let sessions = load_sessions();

    let total_recovered = all_recovered.len();

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = ratatui::Terminal::new(backend)?;

    let mut active_tab: usize = 0; // 0=Home, 1=Sessions, 2=Recovered
    let mut session_idx: usize = 0;
    let mut recovered_scroll: usize = 0;
    let mut show_help = false;
    let mut search_query = String::new();
    let mut search_active = false;

    loop {
        terminal.draw(|f| {
            let size = f.size();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(3), Constraint::Min(10), Constraint::Length(1)].as_ref())
                .split(size);

            let tab_titles = vec![
                format!(" [1] Home "),
                format!(" [2] Sessions ({}) ", sessions.len()),
                format!(" [3] Recovered ({}) ", total_recovered),
            ];
            let tabs = Tabs::new(tab_titles.iter().cloned().map(Line::from).collect::<Vec<_>>())
                .select(active_tab)
                .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded)
                    .title(" crack-ng v2.0 -- Hash Cracking Orchestrator ")
                    .title_alignment(Alignment::Center))
                .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
                .divider(Span::raw("|"));
            f.render_widget(tabs, chunks[0]);

            match active_tab {
                0 => {
                    // HOME tab -- system status + quick start
                    let home_chunks = Layout::default()
                        .direction(Direction::Horizontal)
                        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
                        .split(chunks[1]);

                    let mut status_lines = vec![
                        Line::from(Span::styled("  System Status", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
                        Line::from(""),
                    ];

                    let hc_style = if has_hashcat { Style::default().fg(Color::Green) } else { Style::default().fg(Color::Red) };
                    status_lines.push(Line::from(vec![
                        Span::styled("  Hashcat:  ", Style::default().fg(Color::DarkGray)),
                        Span::styled(if has_hashcat { "Available" } else { "NOT FOUND" }, hc_style),
                        Span::styled(format!("  {}", hashcat_path), Style::default().fg(Color::DarkGray)),
                    ]));

                    let jtr_style = if has_john { Style::default().fg(Color::Green) } else { Style::default().fg(Color::DarkGray) };
                    status_lines.push(Line::from(vec![
                        Span::styled("  John:     ", Style::default().fg(Color::DarkGray)),
                        Span::styled(if has_john { "Available" } else { "Not found" }, jtr_style),
                        Span::styled(format!("  {}", john_path), Style::default().fg(Color::DarkGray)),
                    ]));

                    status_lines.push(Line::from(vec![
                        Span::styled("  GPU:      ", Style::default().fg(Color::DarkGray)),
                        Span::styled(&gpu_info, Style::default().fg(if gpu_info.contains("No NVIDIA") { Color::DarkGray } else { Color::Cyan })),
                    ]));

                    status_lines.push(Line::from(""));
                    status_lines.push(Line::from(vec![
                        Span::styled("  Sessions: ", Style::default().fg(Color::DarkGray)),
                        Span::raw(format!("{}", sessions.len())),
                    ]));
                    status_lines.push(Line::from(vec![
                        Span::styled("  Cracked:  ", Style::default().fg(Color::DarkGray)),
                        Span::styled(format!("{}", total_recovered), Style::default().fg(if total_recovered > 0 { Color::Green } else { Color::DarkGray })),
                    ]));

                    let status_panel = Paragraph::new(status_lines)
                        .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded));
                    f.render_widget(status_panel, home_chunks[0]);

                    let quickstart = vec![
                        Line::from(Span::styled("  Quick Start", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
                        Line::from(""),
                        Line::from(vec![Span::styled("  Crack a file:", Style::default().fg(Color::DarkGray))]),
                        Line::from(Span::styled("    crack-ng -H hashes.txt", Style::default().fg(Color::Cyan))),
                        Line::from(""),
                        Line::from(vec![Span::styled("  NTDS dump:", Style::default().fg(Color::DarkGray))]),
                        Line::from(Span::styled("    crack-ng -H ntds.txt --format ntds", Style::default().fg(Color::Cyan))),
                        Line::from(""),
                        Line::from(vec![Span::styled("  Smart cascade:", Style::default().fg(Color::DarkGray))]),
                        Line::from(Span::styled("    crack-ng -H hashes.txt --cascade", Style::default().fg(Color::Cyan))),
                        Line::from(""),
                        Line::from(vec![Span::styled("  Resume session:", Style::default().fg(Color::DarkGray))]),
                        Line::from(Span::styled("    crack-ng --resume <name>", Style::default().fg(Color::Cyan))),
                        Line::from(""),
                        Line::from(vec![Span::styled("  Find wordlists:", Style::default().fg(Color::DarkGray))]),
                        Line::from(Span::styled("    crack-ng --discover-wordlists", Style::default().fg(Color::Cyan))),
                    ];
                    let qs_panel = Paragraph::new(quickstart)
                        .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded));
                    f.render_widget(qs_panel, home_chunks[1]);
                }
                1 => {
                    // SESSIONS tab
                    if sessions.is_empty() {
                        let empty = Paragraph::new(vec![
                            Line::from(""),
                            Line::from(Span::styled("  No saved sessions.", Style::default().fg(Color::DarkGray))),
                            Line::from(""),
                            Line::from("  Run a crack with --session <name> to save one."),
                        ]).block(Block::default().title(" Sessions ").borders(Borders::ALL).border_type(BorderType::Rounded));
                        f.render_widget(empty, chunks[1]);
                    } else {
                        let rows: Vec<Row> = sessions.iter().enumerate().map(|(i, s)| {
                            let style = if i == session_idx {
                                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                            } else {
                                Style::default().fg(Color::White)
                            };
                            let indicator = if i == session_idx { "> " } else { "  " };
                            Row::new(vec![
                                format!("{}{}", indicator, s.name),
                                format!("{}", s.jobs),
                                format!("{}", s.recovered),
                                s.algos.clone(),
                            ]).style(style)
                        }).collect();
                        let widths = [Constraint::Percentage(30), Constraint::Percentage(10), Constraint::Percentage(15), Constraint::Percentage(45)];
                        let table = Table::new(rows, widths)
                            .header(Row::new(vec!["  Session", "Jobs", "Recovered", "Algorithms"])
                                .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)))
                            .block(Block::default()
                                .title(format!(" Sessions ({}) -- Up/Down to navigate, Enter to view ", sessions.len()))
                                .borders(Borders::ALL).border_type(BorderType::Rounded));
                        f.render_widget(table, chunks[1]);
                    }
                }
                2 => {
                    // RECOVERED tab -- newest first, with search
                    let content_area = if search_active || !search_query.is_empty() {
                        let split = Layout::default()
                            .direction(Direction::Vertical)
                            .constraints([Constraint::Length(3), Constraint::Min(5)].as_ref())
                            .split(chunks[1]);
                        let cursor_char = if search_active { "_" } else { "" };
                        let search_bar = Paragraph::new(format!(" /{}{}", search_query, cursor_char))
                            .block(Block::default().title(" Search (Esc to clear) ").borders(Borders::ALL).border_type(BorderType::Rounded))
                            .style(Style::default().fg(if search_active { Color::Yellow } else { Color::DarkGray }));
                        f.render_widget(search_bar, split[0]);
                        split[1]
                    } else {
                        chunks[1]
                    };

                    let filtered: Vec<&ExportRecord> = all_recovered.iter().rev().filter(|r| {
                        if search_query.is_empty() {
                            return true;
                        }
                        let q = search_query.to_lowercase();
                        r.hash.to_lowercase().contains(&q)
                            || r.plaintext.to_lowercase().contains(&q)
                            || r.algo.to_lowercase().contains(&q)
                    }).collect();

                    let page_height = (content_area.height as usize).saturating_sub(4);
                    let visible_start = recovered_scroll.min(filtered.len().saturating_sub(1));
                    let visible_end = (visible_start + page_height).min(filtered.len());
                    let rows: Vec<Row> = filtered[visible_start..visible_end].iter().map(|r| {
                        Row::new(vec![r.timestamp.clone(), r.algo.clone(), r.hash.clone(), r.plaintext.clone()])
                            .style(Style::default().fg(Color::Green))
                    }).collect();
                    let title = if search_query.is_empty() {
                        format!(" Recovered Credentials ({} unique) -- newest first ", total_recovered)
                    } else {
                        format!(" Recovered Credentials ({}/{} matched) ", filtered.len(), total_recovered)
                    };
                    let widths = [Constraint::Percentage(15), Constraint::Percentage(15), Constraint::Percentage(35), Constraint::Percentage(35)];
                    let table = Table::new(rows, widths)
                        .header(Row::new(vec!["Timestamp", "Algorithm", "Hash", "Plaintext"])
                            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)))
                        .block(Block::default()
                            .title(title)
                            .borders(Borders::ALL).border_type(BorderType::Rounded));
                    f.render_widget(table, content_area);
                }
                _ => {}
            }

            let footer = Paragraph::new(" [1-3/Tab/Shift-Tab] Tabs | [/] Search | [Up/Down] Navigate | [E] Export | [?] Help | [Q] Quit ")
                .style(Style::default().fg(Color::DarkGray)).alignment(Alignment::Center);
            f.render_widget(footer, chunks[2]);

            if show_help {
                let area = centered_rect(50, 45, size);
                f.render_widget(Clear, area);
                let help = Paragraph::new(vec![
                    Line::from(Span::styled("Keyboard Shortcuts", Style::default().add_modifier(Modifier::BOLD))),
                    Line::from(""),
                    Line::from("1-3        : Switch tabs (Home / Sessions / Recovered)"),
                    Line::from("Tab/S-Tab  : Cycle tabs forward/backward"),
                    Line::from("/          : Search recovered hashes (on Recovered tab)"),
                    Line::from("Up / Down  : Navigate session list or scroll recovered"),
                    Line::from("PgUp/PgDn  : Scroll recovered by page"),
                    Line::from("E          : Export all recovered to crack-ng-export.csv"),
                    Line::from("Q / Esc    : Exit"),
                    Line::from("?          : Toggle this help"),
                    Line::from(""),
                    Line::from(Span::styled("To start cracking, run:", Style::default().fg(Color::Yellow))),
                    Line::from("  crack-ng -H <hash_file>"),
                    Line::from("  crack-ng -H <hash_file> --cascade"),
                    Line::from("  crack-ng --resume <session_name>"),
                ])
                .block(Block::default().title(" Help ").borders(Borders::ALL).border_type(BorderType::Double)
                    .style(Style::default().fg(Color::Yellow)));
                f.render_widget(help, area);
            }
        })?;

        if event::poll(std::time::Duration::from_millis(150))? {
            if let Event::Key(key) = event::read()? {
                if show_help {
                    show_help = false;
                    continue;
                }

                // Search input mode
                if search_active {
                    match key.code {
                        KeyCode::Esc => {
                            search_active = false;
                            search_query.clear();
                            recovered_scroll = 0;
                        }
                        KeyCode::Enter => {
                            search_active = false;
                        }
                        KeyCode::Backspace => {
                            search_query.pop();
                            recovered_scroll = 0;
                            if search_query.is_empty() {
                                search_active = false;
                            }
                        }
                        KeyCode::Char(c) => {
                            search_query.push(c);
                            recovered_scroll = 0;
                        }
                        _ => {}
                    }
                    continue;
                }

                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Esc => {
                        if !search_query.is_empty() {
                            search_query.clear();
                            recovered_scroll = 0;
                        } else {
                            break;
                        }
                    }
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Char('?') => show_help = !show_help,
                    KeyCode::Tab => {
                        active_tab = if active_tab >= 2 { 0 } else { active_tab + 1 };
                    }
                    KeyCode::BackTab => {
                        active_tab = if active_tab == 0 { 2 } else { active_tab - 1 };
                    }
                    KeyCode::Char('/') if active_tab == 2 => {
                        search_active = true;
                        search_query.clear();
                        recovered_scroll = 0;
                    }
                    KeyCode::Char('1') => active_tab = 0,
                    KeyCode::Char('2') => active_tab = 1,
                    KeyCode::Char('3') => active_tab = 2,
                    KeyCode::Char('e') | KeyCode::Char('E') => {
                        let _ = export_results(&PathBuf::from("crack-ng-export.csv"), &all_recovered);
                    }
                    KeyCode::Up => {
                        if active_tab == 1 && session_idx > 0 { session_idx -= 1; }
                        if active_tab == 2 && recovered_scroll > 0 { recovered_scroll -= 1; }
                    }
                    KeyCode::Down => {
                        if active_tab == 1 && !sessions.is_empty() && session_idx < sessions.len() - 1 { session_idx += 1; }
                        if active_tab == 2 && recovered_scroll + 1 < all_recovered.len() { recovered_scroll += 1; }
                    }
                    KeyCode::PageUp => {
                        if active_tab == 2 { recovered_scroll = recovered_scroll.saturating_sub(20); }
                    }
                    KeyCode::PageDown => {
                        if active_tab == 2 { recovered_scroll = (recovered_scroll + 20).min(all_recovered.len().saturating_sub(1)); }
                    }
                    _ => {}
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
