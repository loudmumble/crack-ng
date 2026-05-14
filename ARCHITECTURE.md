# crack-ng Architecture

crack-ng is an intelligent hash-cracking orchestrator that provides a unified interface for Hashcat and John the Ripper.

## Design Goals

1. **Hardware Agnostic**: Automatically detect GPU/CPU availability and choose the best engine.
2. **Format Intelligent**: Automated identification of 62+ hash types without manual user selection.
3. **Adaptive Attack**: Use recovered passwords to generate new candidate masks in real-time (Cascade mode).
4. **Resilient**: Atomic session management allows resuming complex multi-stage jobs.

## Core Modules

### 1. Engine Orchestrator (`engine.rs`)
- **Process Management**: Asynchronous execution of sub-processes with real-time status parsing.
- **Hardware Tuning**: Detects VRAM and compute units to set optimal workload profiles (`-w`, `-O`).
- **Engine Selection**: Prioritizes Hashcat for GPU-supported hashes and JtR for complex/CPU-only formats.

### 2. Detection & State (`state.rs`)
- **Signature Engine**: Uses regex-based patterns to identify 62 distinct hash formats.
- **Job Queue**: Breaks down multi-hash files into optimized jobs grouped by algorithm.

### 3. Cascade Attack (`cascade.rs` & `mask.rs`)
- **Stage Progression**: Orchestrates the multi-stage attack from potfile lookup to incremental brute-force.
- **Dynamic Masking**: Analyzes cracked passwords to find common character patterns and injects them back into the attack.

### 4. Terminal Interface (`tui.rs`)
- Built with **ratatui**.
- Provides real-time dashboard, job management, and recovered credential browsing.

### 5. Export & Reporting (`export.rs` & `report.rs`)
- **Structured Data**: CSV/JSON export for tool integration.
- **Auditing**: Generates styled HTML reports with password policy compliance metrics.

## Data Flow

1. **Ingest**: CLI receives hash file or raw string.
2. **Identification**: `state.rs` identifies hash types and builds a job queue.
3. **Execution**: `engine.rs` starts the appropriate cracking engine.
4. **Monitoring**: TUI displays live progress by parsing engine status outputs.
5. **Recovery**: Recovered passwords are saved to the potfile and the internal session database.
6. **Adaptive Loop**: (In Cascade mode) Cracked passwords trigger new mask generation in `mask.rs`.
7. **Finalization**: User exports results or generates a report.
