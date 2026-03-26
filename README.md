# crack-ng

Intelligent hash-cracking orchestrator that wraps Hashcat and John the Ripper into a single workflow. Automatically identifies hash types from input files, dispatches jobs to the best available engine (GPU-accelerated Hashcat or CPU-based John the Ripper), and presents real-time progress through a polished terminal UI built with ratatui.

## Prerequisites

- **Rust toolchain** (1.70+ recommended) -- <https://rustup.rs>
- **Hashcat** -- GPU-accelerated cracking engine. Install via your package manager or <https://hashcat.net>.
- **John the Ripper (Jumbo)** -- CPU-based cracking engine. The community-enhanced "jumbo" build is required for extended format support. Install via your package manager or <https://www.openwall.com/john/>.
- A wordlist (e.g. `rockyou.txt`) for dictionary attacks, or let crack-ng default to brute-force mode.

## Installation

```bash
git clone https://github.com/loudmumble/crack-ng.git
cd crack-ng
cargo build --release
```

The binary is produced at `target/release/crack-ng`.

## Usage

### Single hash file (auto-detect types)

```bash
./target/release/crack-ng -H hashes.txt -w /path/to/rockyou.txt
```

crack-ng reads every line, matches it against known signatures, splits hashes by algorithm into separate jobs, and cracks each batch with the appropriate engine.

### Mixed hash files

Files containing multiple hash types (e.g. MD5 + bcrypt + SHA256) are handled automatically. Each type gets its own job in the queue.

### Headless / batch mode

```bash
./target/release/crack-ng -H hashes.txt -w wordlist.txt --no-tui
```

Runs without the terminal UI. Progress and results are printed to stdout.

### Session management

Save progress so you can resume after interruption:

```bash
# Start with a named session
./target/release/crack-ng -H hashes.txt -w wordlist.txt --session myrun

# Resume later
./target/release/crack-ng --resume myrun -w wordlist.txt
```

Sessions are stored in `~/.crack-ng/sessions/<name>/` and include copies of the hash files so they survive reboots and /tmp cleanup.

### Database viewer

Launch without `-H` to browse all previously recovered credentials across all sessions:

```bash
./target/release/crack-ng
```

Or dump them non-interactively:

```bash
./target/release/crack-ng --no-tui
```

### Export results

```bash
# CSV export
./target/release/crack-ng -H hashes.txt -w wordlist.txt --export results.csv

# JSON export
./target/release/crack-ng -H hashes.txt -w wordlist.txt --export results.json
```

Export also works with the database viewer:

```bash
./target/release/crack-ng --no-tui --export all_results.csv
```

## Supported Hash Types

| Name | Example Pattern | Hashcat Mode | JtR Format |
|------|----------------|-------------|------------|
| Bcrypt ($2*) | `$2a$10$...` | 3200 | bcrypt |
| Linux SHA-512 crypt | `$6$salt$hash` | 1800 | sha512crypt |
| Linux SHA-256 crypt | `$5$salt$hash` | 7400 | sha256crypt |
| Linux yescrypt | `$y$params$salt$hash` | -- | yescrypt |
| Cisco IOS Type 5 | `$1$XXXX$hash` (4-char salt) | 500 | md5crypt |
| MD5 Crypt | `$1$salt$hash` (1-8 char salt) | 500 | md5crypt |
| Django PBKDF2-SHA256 | `pbkdf2_sha256$...` | 10000 | PBKDF2-HMAC-SHA256 |
| Kerberos 5 TGS-REP | `$krb5tgs$...` | 13100 | krb5tgs |
| Kerberos 5 AS-REP | `$krb5asrep$...` | 19600 | krb5asrep |
| NetNTLMv2 | `user::domain:challenge:hash:blob` | 5600 | netntlmv2 |
| NetNTLMv1 | `user::domain:lm:nt:blob` | 5500 | netntlm |
| WPA/WPA2 (EAPOL) | `hex:mac:mac:hex` | 22000 | wpapsk |
| MSSQL 2012+ | `0x0200...` | 1731 | mssql12 |
| MySQL 4.1+ | `*hex40` | 300 | mysql-sha1 |
| DES Crypt | 13-char alphanumeric | 1500 | descrypt |
| SHA-512 | 128-char hex | 1700 | raw-sha512 |
| SHA-256 | 64-char hex | 1400 | raw-sha256 |
| SHA-1 | 40-char hex | 100 | raw-sha1 |
| MD5 | 32-char hex | 0 | raw-md5 |

Unrecognized hashes are grouped into an "Unknown" job. Use `--mode <hashcat_mode>` to provide a fallback mode for these.

## Configuration

All persistent data is stored under `~/.crack-ng/`:

```
~/.crack-ng/
  sessions/
    <session-name>/
      session.json        # Serialized job queue + recovered hashes
      job_0.hashes        # Persisted hash file for job 0
      job_1.hashes        # Persisted hash file for job 1
      ...
```

Legacy sessions (flat `<name>.json` files in the sessions directory) are still readable for backward compatibility.

## Architecture

crack-ng is a single-binary Rust application. All code lives in `src/`.

- **Hash identification** -- Regex-based signature matching via a priority-ordered table. Specific patterns (prefixed formats like `$6$`, `$krb5tgs$`) are checked before generic hex patterns to avoid ambiguity.
- **Job orchestrator** -- Iterates the job queue sequentially. For each job, selects Hashcat (if GPU available and mode known) or John the Ripper as fallback. Streams stdout/stderr asynchronously via tokio.
- **TUI** -- Built with ratatui + crossterm. Five tabs: Live Dashboard, Job Queue, Recovered Plaintexts, Report, and Wordlists. Non-blocking event loop polls at 150ms.
- **Session persistence** -- JSON serialization via serde. Hash files are copied into the session directory so sessions survive /tmp cleanup and reboots.
- **Export** -- CSV or JSON output of recovered credentials.

## Advanced Usage

### Passthrough arguments

Extra arguments after `--` are forwarded directly to the cracking engine:

```bash
./target/release/crack-ng -H hashes.txt -w wordlist.txt -- --rules=best64
```

### Attack modes

```bash
# Dictionary attack (default when wordlist provided)
./target/release/crack-ng -H hashes.txt -w wordlist.txt -a 0

# Brute-force (default for Hashcat when no wordlist)
./target/release/crack-ng -H hashes.txt -a 3
```

### Force CPU or GPU

```bash
# Force Hashcat (GPU) even if detection is unreliable
./target/release/crack-ng -H hashes.txt -w wordlist.txt --force-gpu

# Force John the Ripper (CPU) for all jobs
./target/release/crack-ng -H hashes.txt -w wordlist.txt --force-cpu
```

### Universal fallback mode

For hashes that crack-ng cannot auto-identify:

```bash
./target/release/crack-ng -H hashes.txt -w wordlist.txt -m 1000
```

This applies Hashcat mode 1000 (NTLM) to any "Unknown" hashes in the file.

## Uninstallation

```bash
# Remove the binary
rm target/release/crack-ng
# Or remove the entire project
rm -rf /path/to/crack-ng

# Remove session data
rm -rf ~/.crack-ng
```

## License

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE).
