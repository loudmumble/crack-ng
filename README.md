# crack-ng

Intelligent hash-cracking orchestrator that wraps Hashcat and John the Ripper into a single workflow. Automatically identifies 62 hash types from input files, detects GPU hardware to apply optimal cracking parameters, dispatches jobs to the best available engine, and presents real-time progress through a terminal UI built with ratatui.

## Prerequisites

- **Rust toolchain** (1.70+ recommended) -- <https://rustup.rs>
- **Hashcat** -- GPU-accelerated cracking engine. Install via your package manager or <https://hashcat.net>.
- **John the Ripper (Jumbo)** -- CPU-based cracking engine. The community-enhanced "jumbo" build is required for extended format support. Install via your package manager or <https://www.openwall.com/john/>.
- A wordlist (e.g. `rockyou.txt`) for dictionary attacks, or let crack-ng default to brute-force mode.

## Installation

### From source

```bash
git clone https://github.com/loudmumble/crack-ng.git
cd crack-ng
cargo build --release
```

The binary is produced at `target/release/crack-ng`.

### Pre-built binaries

Download pre-built binaries from the [Releases](https://github.com/loudmumble/crack-ng/releases) page for Linux (x86_64, aarch64) and Windows (x86_64).

## Usage

### Positional arguments (like hashcat)

```bash
# Crack a hash file with a wordlist
crack-ng hashes.txt /path/to/rockyou.txt

# Auto-detect hash types and crack with brute force
crack-ng hashes.txt
```

### Direct hash input

The first positional argument can be a raw hash string instead of a file path. If the argument doesn't exist as a file and looks like a hash, crack-ng treats it as a direct hash input:

```bash
# Identify a single hash
crack-ng --identify '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'

# Crack a single hash with a wordlist
crack-ng 5f4dcc3b5aa765d61d8327deb882cf99 rockyou.txt

# Works with any hash format
crack-ng '$krb5tgs$23$*user$DOMAIN$...' wordlist.txt --cascade
```

### Traditional flags (still supported)

```bash
crack-ng -H hashes.txt -w /path/to/rockyou.txt
```

Both styles can be mixed: `crack-ng -H hashes.txt rockyou.txt` or `crack-ng hashes.txt -w rockyou.txt`.

### List all supported hash types

```bash
crack-ng --list-modes
```

Prints all 62 auto-identified hash types with their hashcat mode numbers and JtR format names, plus common mode overrides for ambiguous hashes.

### Identify hash types (no cracking)

```bash
crack-ng --identify hashes.txt
```

Prints a breakdown of detected hash types, recommended engine commands, and hardware info:

```
[*] Hash file: hashes.txt (150 lines)
[*] Detected input format: SecretsDump

[*] Hash type breakdown:
  NTLM                                      120 hashes  (hashcat -m 1000 / john --format=nt)
  LM                                          25 hashes  (hashcat -m 3000 / john --format=lm)
  Unknown                                      5 hashes  (use -m to specify)

[*] Hardware:
  GPU: NVIDIA GeForce RTX 4090 (24564 MB VRAM)
  Auto-tuning: workload profile 4, optimized kernels: on
```

### Binary file detection

If you accidentally pass a binary file (pcap, KeePass database, encrypted archive, etc.) instead of a hash file, crack-ng detects it and prints the extraction command:

```
[!] capture.pcapng appears to be a WPA/WPA2 capture file, not a hash file.
    Extract hashes first:
      hcxpcapngtool -o hashes.22000 capture.pcapng
    Then crack:
      crack-ng hashes.22000
```

Supported binary detection: `.pcap`/`.pcapng`/`.cap` (WPA), `.kdbx` (KeePass), `.rar`/`.zip`/`.7z` (encrypted archives), `.pdf`/`.docx`/`.xlsx`/`.pptx` (encrypted documents), `.tc` (TrueCrypt), `.hc` (VeraCrypt), plus magic-byte detection for ZIP/OLE2 files without matching extensions.

### Mixed hash files

Files containing multiple hash types (e.g. MD5 + bcrypt + SHA256) are handled automatically. Each type gets its own job in the queue.

### Headless / batch mode

```bash
crack-ng hashes.txt wordlist.txt --no-tui
```

Runs without the terminal UI. Progress and results are printed to stdout.

### Smart cascade attack

```bash
crack-ng hashes.txt --cascade
```

Automatically discovers wordlists and rule files on the system, then runs a multi-stage attack:

1. Potfile lookup (instant wins from prior cracks)
2. Best wordlist + fast rules (best64.rule)
3. Best wordlist + deep rules (dive.rule)
4. Common password masks (e.g. `?u?l?l?l?l?l?d?d`)
5. Incremental brute force (1-8 chars)

Adaptive: after each stage, cracked passwords are analyzed to generate dynamic mask patterns that are injected into subsequent stages.

### Session management

```bash
# Start with a named session
crack-ng hashes.txt wordlist.txt --session myrun

# Resume later
crack-ng --resume myrun -w wordlist.txt

# Resume a cascade session (skips completed stages automatically)
crack-ng --resume myrun --cascade
```

Sessions are stored in `~/.crack-ng/sessions/<name>/` and include copies of the hash files so they survive reboots and /tmp cleanup. Cascade sessions track the last completed stage index, so resuming skips stages that already ran.

### Database viewer

Launch without a hash file to browse all previously recovered credentials across all sessions:

```bash
crack-ng
```

Or dump them non-interactively:

```bash
crack-ng --no-tui
```

### Export results

```bash
# CSV export
crack-ng hashes.txt wordlist.txt --export results.csv

# JSON export
crack-ng hashes.txt wordlist.txt --export results.json
```

Export also works with the database viewer:

```bash
crack-ng --no-tui --export all_results.csv
```

### HTML report

```bash
crack-ng hashes.txt wordlist.txt --report audit.html
```

Generates a styled HTML report with algorithm breakdown, password length distribution, top base words, mask frequency analysis, and password policy compliance stats.

## Hardware Auto-Optimization

crack-ng automatically detects your GPU via `nvidia-smi` and applies optimal Hashcat parameters:

| GPU VRAM | Workload Profile (`-w`) | Optimized Kernels (`-O`) |
|----------|------------------------|--------------------------|
| 8+ GB | 4 (nightmare) | Yes |
| 4-8 GB | 3 (high) | Yes |
| < 4 GB | 2 (default) | Yes |
| No GPU | N/A (uses JtR CPU) | N/A |

- **`-w` (workload profile)**: Controls GPU utilization. Higher values maximize throughput at the cost of system responsiveness.
- **`-O` (optimized kernels)**: Enables faster kernels that limit password candidates to 32 characters. Safe for virtually all real-world passwords.

Override via passthrough arguments (hashcat uses last-wins for duplicate flags):

```bash
crack-ng hashes.txt wordlist.txt -- -w 2    # Override to lower workload
```

## Supported Hash Types (62)

### Prefixed / Structured (unambiguous identification)

| Name | Hashcat Mode | JtR Format |
|------|-------------|------------|
| Bcrypt ($2a$, $2b$, $2x$, $2y$) | 3200 | bcrypt |
| Linux SHA-512 crypt ($6$) | 1800 | sha512crypt |
| Linux SHA-256 crypt ($5$) | 7400 | sha256crypt |
| Linux yescrypt ($y$) | -- | yescrypt |
| Argon2id | -- | argon2 |
| Argon2i | -- | argon2 |
| Argon2d | -- | argon2 |
| scrypt ($7$) | 8900 | scrypt |
| phpass / WordPress / Joomla ($P$/$H$) | 400 | phpass |
| Apache APR1 ($apr1$) | 1600 | md5apr1 |
| Django PBKDF2-SHA256 | 10000 | PBKDF2-HMAC-SHA256 |
| EPiServer | 141 | -- |
| Cisco IOS Type 5 / MD5 Crypt ($1$) | 500 | md5crypt |
| Cisco Type 8 PBKDF2-SHA256 ($8$) | 9200 | cisco8 |
| Cisco Type 9 scrypt ($9$) | 9300 | cisco9 |
| Kerberos 5 TGS-REP ($krb5tgs$) | 13100 | krb5tgs |
| Kerberos 5 AS-REP ($krb5asrep$) | 18200 | krb5asrep |
| Kerberos 5 Pre-Auth etype 23 ($krb5pa$) | 7500 | krb5pa-md5 |
| Domain Cached Credentials 2 ($DCC2$) | 2100 | mscach2 |
| LDAP SSHA512 | 1711 | ssha512 |
| LDAP SSHA256 | 1411 | ssha256 |
| LDAP SHA512 | 1700 | raw-sha512 |
| LDAP SHA256 | 1400 | raw-sha256 |
| LDAP SSHA | 111 | nsldaps |
| LDAP SHA | 101 | nsldap |
| GRUB PBKDF2-SHA512 | 7200 | -- |
| Bitcoin/Litecoin wallet ($bitcoin$) | 11300 | bitcoin |
| Blockchain.info wallet ($blockchain$) | 12700 | blockchain |
| Ethereum wallet ($ethereum$) | 15600 | ethereum |
| RAR3 ($RAR3$) | 12500 | rar |
| RAR5 ($RAR5$) | 13000 | rar5 |
| 7-Zip ($7z$) | 11600 | 7z |
| KeePass ($keepass$) | 13400 | -- |
| WinZip ($zip2$) | 13600 | ZIP |
| PKZIP ($pkzip$) | 17200 | pkzip |
| PDF ($pdf$) | 10500 | pdf |
| MS Office 2013+ | 9600 | office |
| MS Office 2010 | 9500 | office |
| MS Office 2007 | 9400 | office |
| MS Office 97-2003 ($oldoffice$) | 9700 | oldoffice |
| BitLocker ($bitlocker$) | 22100 | bitlocker |
| FileVault 2 ($fvde$) | 16700 | fvde2 |
| TrueCrypt ($truecrypt$) | -- | tc_aes_xts |
| VeraCrypt ($veracrypt$) | -- | vc |
| LUKS ($luks$) | 14600 | -- |
| GPG/PGP ($gpg$) | 17010 | gpg |
| Ansible Vault ($ansible$) | 16900 | ansible |

### Structured Colon-Delimited

| Name | Hashcat Mode | JtR Format |
|------|-------------|------------|
| NTLM (LM:NT pair) | -- (JtR only) | nt |
| NetNTLMv2 | 5600 | netntlmv2 |
| NetNTLMv1 | 5500 | netntlm |
| WPA/WPA2 (hashcat 22000 format) | 22000 | -- |

### Prefix-Identified Hex

| Name | Hashcat Mode | JtR Format |
|------|-------------|------------|
| MSSQL 2012+ (0x0200...) | 1731 | mssql12 |
| MSSQL 2005 (0x0100...) | 132 | mssql05 |
| MySQL 4.1+ (*hex40) | 300 | mysql-sha1 |
| Oracle 11g (S:hex60) | 112 | oracle11 |

### Generic Fixed-Length Hex (defaults to most common algorithm)

| Name | Length | Hashcat Mode | JtR Format | Also Could Be |
|------|--------|-------------|------------|---------------|
| DES Crypt | 13 chars | 1500 | descrypt | -- |
| SHA-512 | 128 hex | 1700 | raw-sha512 | SHA3-512 (17600), Whirlpool (6100) |
| SHA-384 | 96 hex | 10800 | raw-sha384 | SHA3-384 (17500) -- rare |
| SHA-256 | 64 hex | 1400 | raw-sha256 | SHA3-256 (17400), Keccak-256 (17800) |
| SHA-1 | 40 hex | 100 | raw-sha1 | RIPEMD-160 (6000), MySQL 3.2.3 (200) |
| MD5 | 32 hex | 0 | raw-md5 | NTLM (1000), MD4 (900), LM (3000), DCC1 (1100) |

Use `--mode (-m)` to override the default for ambiguous hex hashes when you know the source system.

### Hash Types That Cannot Be Auto-Identified

Some hash types produce output identical to other algorithms and require manual `--mode` specification:

- **32-char hex variants**: NTLM, MD4, LM, DCC1, half-MD5, HMAC-MD5, and ~20 more all produce 32-char hex identical to MD5
- **Salted hashes without prefix**: `hash:salt` formats from web applications (vBulletin, SMF, IPB, etc.) where the algorithm isn't embedded in the format
- **Binary/file-based formats**: WPA captures, TrueCrypt/VeraCrypt raw volumes, LUKS partitions -- these need extraction tools before cracking (crack-ng detects these and prints the extraction command)
- **HMAC variants**: Same output length as the base hash, different computation

## Advanced Usage

### Passthrough arguments

Extra arguments after `--` are forwarded directly to the cracking engine:

```bash
crack-ng hashes.txt wordlist.txt -- --rules=best64
```

### Attack modes

```bash
# Dictionary attack (default when wordlist provided)
crack-ng hashes.txt wordlist.txt -a 0

# Brute-force (default for Hashcat when no wordlist)
crack-ng hashes.txt -a 3
```

### Force CPU or GPU

```bash
# Force Hashcat (GPU) even if detection is unreliable
crack-ng hashes.txt wordlist.txt --force-gpu

# Force John the Ripper (CPU) for all jobs
crack-ng hashes.txt wordlist.txt --force-cpu
```

### Universal fallback mode

For hashes that crack-ng cannot auto-identify:

```bash
crack-ng hashes.txt wordlist.txt -m 1000
```

This applies Hashcat mode 1000 (NTLM) to any "Unknown" hashes in the file.

### Input format hints

```bash
# Secretsdump / NTDS output
crack-ng ntds.txt --format ntds --cascade

# /etc/shadow
crack-ng shadow.txt --format shadow

# Kerberoast output
crack-ng kerb.txt --format kerberoast

# Responder captures
crack-ng responder.txt --format responder
```

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

crack-ng is a single-binary Rust application split across focused modules:

- **`state.rs`** -- CLI argument parsing (clap), 62-type regex signature table, job/state structs
- **`engine.rs`** -- GPU hardware detection, optimized parameter tuning, Hashcat/JtR process orchestration with async streaming
- **`cascade.rs`** -- Multi-stage cascade attack configuration with live adaptive mask injection
- **`parser.rs`** -- Input format parsers for secretsdump, shadow, kerberoast, AS-REP, Responder output
- **`tui.rs`** -- ratatui + crossterm terminal UI (5 tabs: Dashboard, Jobs, Recovered, Report, Strategy) with panic-safe terminal restore
- **`session.rs`** -- Atomic session save/load with hash file persistence and path traversal prevention
- **`potfile.rs`** -- Streaming potfile reader (BufReader) for Hashcat/JtR potfiles
- **`wordlist.rs`** -- System wordlist and rule file discovery
- **`mask.rs`** -- Cracked password analysis for dynamic mask generation (ASCII-only)
- **`report.rs`** -- HTML/text post-crack report generation with XSS-safe escaping
- **`export.rs`** -- CSV/JSON export with restrictive file permissions (0600)

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
