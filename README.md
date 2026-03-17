# malcat

A fast, low-false-positive static analyzer for detecting malicious patterns in source code and compiled binaries. Built for scanning open-source projects you've cloned and want to trust before running, as well as deep analysis of suspicious PE executables.

## Installation

```bash
# Linux
curl -fsSL https://raw.githubusercontent.com/master-sauce/malcat/main/install.sh | bash

# Windows
irm https://raw.githubusercontent.com/master-sauce/malcat/main/install.ps1 | iex
```

Or build from source (requires Go 1.22+):

```bash
git clone https://github.com/master-sauce/malcat.git
cd malcat
go build -o malcat .
```

## Requirements

malcat itself has no runtime dependencies — it is a single static binary.

The `--bin`, `--all`, and `--urls`/`--ips` flags on non-PE binary files require the `strings` utility to be available on your `PATH`. This is the only external dependency.

### Installing `strings`

**Linux** — pre-installed on every distribution as part of GNU Binutils:
```bash
# Verify it's present
strings --version
```

**macOS** — pre-installed with Xcode Command Line Tools:
```bash
# Install if missing
xcode-select --install

# Verify
strings -v
```

**Windows** — not included with Windows by default. Two options that put `strings` on your PATH automatically:

Option 1 — winget (recommended):
```powershell
winget install Microsoft.Sysinternals.Strings
```

Option 2 — Microsoft Store (installs the full Sysinternals Suite):

open the Microsoft Store and search for **Sysinternals Suite**. Once installed, `strings.exe` is available on your PATH immediately — no manual configuration needed.

> **Note:** `--pe`, `--disasm`, `--rop`, and all PE analysis features work without `strings` — they parse the binary directly. Only the `--bin` string-extraction path requires it. If `strings` is not found, `--bin` returns no findings rather than crashing.

## Philosophy

Most scanners fire on every `exec()`, `eval()`, or backtick — generating hundreds of false positives in normal code. malcat takes the opposite approach: rules require **specific combinations** that are nearly impossible to explain as innocent code. A single `exec()` call never fires. A socket connection followed by a shell spawn does.

For compiled binaries, malcat goes further than string extraction: it parses PE structure directly, disassembles executable sections using a real x86/x86-64 disassembler, detects the compiler toolchain, and suppresses false positives that are normal behavior in Go, Rust, and GCC-compiled binaries.

## Detection categories

- **C2 communication** — reverse shells, download cradles, beacon patterns, DNS tunneling
- **Persistence** — cron writes, registry Run keys, systemd service drops, SSH backdoors, LD_PRELOAD
- **Evasion** — debugger detection, sandbox/VM fingerprinting, log wiping, direct syscalls (Hell's Gate)
- **Process injection** — Windows API triads, shellcode allocation, process hollowing, reflective DLL
- **Credential theft** — LSASS dumps, hardcoded secrets, credential file access, AWS key exposure
- **Destructive payloads** — disk wipes, ransomware patterns, fork bombs, recursive root deletion
- **LOLBins** — certutil, regsvr32, rundll32, WMIC, mshta, bitsadmin abuse
- **Runtime decryption** — XOR loops, AES/RC4 with hardcoded keys, polymorphic stubs
- **Obfuscated C2 construction** — strings built from char codes, byte arrays, hex escapes, and unicode escapes across Python, JavaScript, PowerShell, C/C++, Go, and Rust
- **PE structural anomalies** — packed sections, TLS callbacks, overlay data, W+X sections, import triads
- **Disassembly** — NOP sleds, ROP chains, CPUID/RDTSC evasion, PEB walks, direct syscall stubs

## Usage

```
malcat [flags] <file|directory> [<file|directory>...] [-o output]
```

### Flags

#### General

| Flag | Description |
|------|-------------|
| `-r`, `--recursive` | Scan directories recursively |
| `--severity` | Minimum severity to report: `low`, `medium`, `high`, `critical` (default: `low`) |
| `--depth int` | Max recursion depth, `-1` = unlimited (default: `-1`) |
| `-e`, `--ext` | Comma-separated file extensions to scan, e.g. `.py,.sh,.js`. Empty = all |
| `-o`, `--output` | Output file — format inferred from extension (`.json`, `.csv`, or plain text) |

#### Binary scanning

| Flag | Description |
|------|-------------|
| `--bin`, `--binaries` | String-extraction scan on binary files using the `strings` utility (see [Requirements](#requirements)) |

#### PE analysis (Windows executables)

| Flag | Description |
|------|-------------|
| `--pe` | Parse PE structure: sections, imports, exports, TLS callbacks, entropy, Rich header, overlay detection, compiler fingerprinting |
| `--disasm` | Disassemble all executable PE sections (implies `--pe`) |
| `--rop` | Detect ROP gadget chains in disassembly (implies `--disasm`) |
| `--disasm-depth N` | Max instructions to disassemble per section (default: `5000`) |
| `--entropy float` | Section entropy threshold to flag as packed/encrypted (default: `7.2`) |

#### All-in-one

| Flag | Description |
|------|-------------|
| `--all` | Enable every analysis layer: `--pe --disasm --rop --bin` combined |

#### Extraction

| Flag | Description |
|------|-------------|
| `--urls` | Extract and list all URLs found — works on text files, binaries, and PE files |
| `--ips` | Extract all public IP addresses — private/loopback/reserved ranges are filtered out |

Both flags auto-enable binary and PE scanning so nothing is missed. They can be combined (`--urls --ips`) and work with `-r` for recursive scans. Output is a clean deduplicated list rather than per-finding blocks.

### Examples

```bash
# Scan a single script
malcat suspicious.sh

# Recursively scan a cloned repo, show only high+ findings
malcat -r --severity high ./cloned-repo

# Scan only Python and shell files, save as JSON
malcat -r --ext .py,.sh ./cloned-repo -o report.json

# String-extraction scan on a compiled binary
malcat --bin suspicious.exe

# Full PE analysis: structure + imports + entropy
malcat --pe malware.exe

# Full PE analysis + disassembly + ROP detection
malcat --pe --disasm --rop dropper.exe -o analysis.json

# Lower entropy threshold to catch lightly packed samples
malcat --pe --entropy 6.5 packed.exe

# Everything at once — the recommended mode for unknown PE files
malcat --all malware.exe -o full_report.json

# Batch scan a samples directory
malcat -r --all ./samples --severity medium -o report.csv

# Extract all URLs from a suspicious binary
malcat --urls malware.exe

# Extract all public IPs from a binary
malcat --ips malware.exe

# Both at once, across a whole directory
malcat -r --urls --ips ./samples

# Save extracted IPs as JSON for SIEM ingestion
malcat --ips malware.exe -o iocs.json
```

## Output

Each finding shows the severity badge, finding source tag, rule name, location, category, a plain-English description, and a trimmed content window centred on the matched text.

```
╔══ ./dropper.exe ══
  x86-64 (AMD64)  ·  Windows CUI  ·  Unknown  ·  EP: 0x1000  ·  2 sections  ·  0 imports
  ⚠ Overlay: 14.2 KB at 0x8200
  Sections:  .text(XR)H=6.10  .packed(XR)H=7.60

 CRITICAL [pe] No imports    ctx=ImportTable
  Shellcode/Packing  ·  PE002
  PE has zero imports — manually resolves APIs at runtime

 CRITICAL [pe] High-entropy section    ctx=.packed
  Packing/Encryption  ·  PE001
  section ".packed" has entropy 7.60 (threshold 7.20) — likely packed or encrypted payload

 HIGH [disasm] NOP sled    RVA=0x1003  sect=.text
  Shellcode  ·  DIS002
  NOP sled of 20 bytes — classic shellcode alignment pad

 HIGH [disasm] Indirect dispatch chain    RVA=0x1021  sect=.text
  ROP/Shellcode  ·  DIS001
  3 indirect CALL/JMP through registers — ROP chain or shellcode dispatcher
╚═════════════════════════════════════════════════════════════════════
```

### Extraction output (`--urls` / `--ips`)

When using `--urls` or `--ips`, output switches from per-finding blocks to a clean deduplicated list:

```
── URLs (3 unique) ──
  http://evil.com/payload.sh   suspicious.exe:22041
  https://cdn.attacker.io/update.bin   suspicious.exe:31204
  http://malware.io/beacon   config.sh:6

── Public IPs (2 unique) ──
  8.8.8.8   config.sh:5
  104.21.33.44   suspicious.exe:19823

── Summary: 3 URL(s)  2 IP(s)  across 2 file(s) scanned ──
```

Private and reserved IP ranges (RFC 1918, loopback, link-local, documentation) are automatically filtered. Only publicly routable addresses are reported.

### Finding sources

| Tag | Meaning |
|-----|---------|
| `[text]` | Line-based scan of source code or scripts |
| `[strings]` | Strings extracted from a binary (false-positive filtered) |
| `[pe]` | PE structural analysis (sections, imports, TLS, entropy, anomalies) |
| `[disasm]` | Disassembly-level detection |

### Severity levels

| Level | Meaning |
|-------|---------|
| `CRITICAL` | Definitive malicious pattern — almost no legitimate use |
| `HIGH` | Strong indicator of malicious intent |
| `MEDIUM` | Suspicious, warrants investigation |
| `LOW` | Informational — context-dependent |

### Output formats

- **Text** (default) — colorized terminal output with highlighted matches
- **JSON** — structured output with all fields including RVA, source, and context
- **CSV** — flat export suitable for spreadsheet or SIEM ingestion

## PE analysis detail

When `--pe` is active, malcat displays a file header before findings:

```
╔══ .\malware.exe ══
  x86-64 (AMD64)  ·  Windows GUI  ·  MSVC  ·  EP: 0x12a0  ·  5 sections  ·  142 imports
  Sections:  .text(XR)H=6.10  .rdata(R)H=5.20  .data(WR)H=3.40  .rsrc(R)H=4.10  .reloc(R)H=5.80
```

This always shows — even for clean files, so you get structural context regardless of findings. Clean files show `✓ clean` in green next to the import count.

### Compiler detection

malcat fingerprints the toolchain and uses it to suppress false positives that are normal for that compiler:

| Compiler | Detection method | Suppression applied |
|----------|-----------------|---------------------|
| `Go` | `go:buildid` string, `runtime.main` symbol | High-entropy `/N` DWARF debug sections, CPUID/RDTSC downgraded to LOW |
| `GCC/MinGW` | 3+ `/N` slash sections (GNU binutils naming) | Same as Go |
| `Rust` | `.rustc` section | High-entropy debug sections |
| `MSVC` | Rich header present | No suppression needed (standard PE) |
| `.NET/CLR` | `BSJB` + `mscorlib`/`System.Runtime` | No import-table suppression |
| `Unknown` | None of the above | All rules apply at full severity |

For example, a Go binary compiled with `GOARCH=amd64 GOOS=windows` produces sections named `/4`, `/19`, `/32`, `/65` etc. — these are compressed DWARF debug sections with near-maximum entropy (7.9–8.0). malcat recognises them as benign and does not fire PE001. The same entropy in an `Unknown`-compiler binary with a section named `.packed` fires CRITICAL.

### PE structural rules

| Rule | Check | Severity |
|------|-------|----------|
| PE001 | High-entropy section (default threshold 7.2) | HIGH / CRITICAL if executable |
| PE002 | Zero imports — manual API resolution | CRITICAL |
| PE003 | TLS callbacks present — pre-entry execution | HIGH / CRITICAL |
| PE004 | Writable + executable section (W\|X) | CRITICAL |
| PE005 | Known packer section name (UPX, Themida, VMProtect…) | MEDIUM |
| PE006a–j | Malicious import combinations (injection triad, hollowing, keylogger, ransomware…) | HIGH / CRITICAL |
| PE007 | Overlay data — bytes appended after last section | MEDIUM / HIGH |
| PE008 | PE checksum mismatch | LOW |
| PE009 | Entry point outside all sections | HIGH |
| PE010 | Entry point in last section (packer stub pattern) | MEDIUM |
| PE011 | Only LoadLibrary/GetProcAddress/VirtualAlloc imports | HIGH |
| PE012 | No Rich header on unknown-compiler binary | LOW |

### Disassembly rules

| Rule | Check | Severity |
|------|-------|----------|
| DIS001 | Indirect CALL/JMP register chain ≥ 3 — ROP or shellcode dispatcher | HIGH |
| DIS002 | NOP sled ≥ 16 bytes | HIGH |
| DIS003 | `SYSCALL`/`SYSENTER` sequence or `int 0x2e` — direct kernel call, EDR bypass | CRITICAL |
| DIS004 | `CPUID` — VM/CPU fingerprinting | MEDIUM (LOW for GC compilers) |
| DIS005 | `RDTSC` — timing-based anti-debug | MEDIUM (LOW for GC compilers) |
| DIS006 | Self-referencing JMP — infinite loop / sandbox stalling | LOW |
| DIS007 | `FS:[0x30]` / `GS:[0x60]` access — PEB walk, manual API resolution | HIGH |

### Char-building / obfuscated string rules

Malware often constructs C2 addresses and shell commands at runtime from character codes so no string scanner sees `"/bin/sh"` or `"http://"` as a literal. malcat detects the **construction pattern** and the **numeric sequences** themselves.

| Rule | Pattern | Severity |
|------|---------|----------|
| CBP001 | Python `chr(99)+chr(109)+chr(100)` chain | CRITICAL |
| CBP002 | Python `bytes([47,98,...]).decode()` | CRITICAL |
| CBP003 | Python `''.join([chr(x) for x in [...]])` | CRITICAL |
| CBJ001 | JavaScript `String.fromCharCode(99,109,100,...)` | CRITICAL |
| CBJ002 | JavaScript `\x63\x6d\x64` hex escape string (6+ escapes) | HIGH |
| CBJ003 | JavaScript `\u0063\u006d\u0064` unicode escape string | HIGH |
| CBJ004 | JavaScript `[99,109,100].map(c=>String.fromCharCode(c)).join('')` | CRITICAL |
| CBPS001 | PowerShell `[char]99+[char]109+[char]100` chain | CRITICAL |
| CBPS002 | PowerShell `-join([char[]](99,109,100,...))` | CRITICAL |
| CBPS003 | PowerShell `[Encoding]::ASCII.GetString([byte[]](104,...))` | CRITICAL |
| CBC001 | C/C++ `char arr[] = {99,109,100,...}` (6+ values) | HIGH |
| CBC002 | C/C++ `WCHAR arr[] = {L'c',L'm',L'd',...}` | HIGH |
| CBG001 | Go `string([]byte{47,98,105,110,...})` | CRITICAL |
| CBG002 | Go `[]byte{99,109,100,...}` bare literal (6+ values) | HIGH |
| CBR001 | Rust `String::from_utf8(vec![99,109,100,...])` | CRITICAL |
| CBN001 | Byte sequence `47,98,105,110,47,115,104` → `/bin/sh` | CRITICAL |
| CBN002 | Byte sequence `47,98,105,110,47,98,97,115,104` → `/bin/bash` | CRITICAL |
| CBN003 | Byte sequence `99,109,100,46,101,120,101` → `cmd.exe` | CRITICAL |
| CBN004 | Byte sequence `112,111,119,101,114,...` → `powershell` | CRITICAL |
| CBN005 | Byte sequence `104,116,116,112,58,47,47` → `http://` | CRITICAL |
| CBN006 | Byte sequence `104,116,116,112,115,58,47,47` → `https://` | CRITICAL |
| CBN007 | Byte sequence `47,100,101,118,47,116,99,112,47` → `/dev/tcp/` | CRITICAL |
| CBN008–010 | Hex escape sequences for `/bin/sh`, `cmd.exe`, `http://` | CRITICAL |
| CBX001–002 | Dense numeric array (8+ values) adjacent to exec/network call | HIGH |

The CBN rules are language-agnostic — they fire on the raw byte values regardless of what language or construct surrounds them.

## False positive suppression

malcat applies several layers of automatic suppression, and exposes a simple API for adding your own.

### Automatic suppression layers

**Regex-artifact suppression** — when scanning compiled binaries with `--bin` or `--all`, `strings` extracts everything from the binary's read-only data — including any regex patterns or rule descriptions embedded in security tools, linters, or validators. malcat detects these by recognising regex syntax indicators (`(?i)`, `[\s\S]`, `{0,N}`) and suppresses them before they match.

**Compiler-aware suppression** — high-entropy debug sections, empty import tables, missing PE checksums, and missing Rich headers are all normal for Go/Rust/GCC-compiled binaries. malcat detects the compiler first and suppresses the rules that would produce FPs for that toolchain.

**Context-aware suppression** — short fragments like `\SAM` or `\SYSTEM` are only flagged as credential theft indicators when they appear with qualifying registry context (`HKLM`, `HKCU`, `config`, `System32`). Bare fragments without context are suppressed.

**Keyword-soup suppression** — compiled binaries pack adjacent string constants together in their read-only data section. A security tool's keyword arrays (`["vbox","qemu","vmware"...]`) get emitted as one concatenated blob. malcat detects when 4+ rule keyword atoms appear in a single extracted string and suppresses it.

**Deduplication** — identical `(ruleID, content)` pairs at adjacent binary offsets are collapsed to a single finding.

### Adding your own suppressions

All custom suppressions live in `analyzer/false_positive.go` in the `UserSuppressions` variable at the bottom of the file. No other files need to be changed. Rebuild after editing.

Each entry has three optional fields that are **ANDed** together. Multiple entries are **ORed**.

```go
var UserSuppressions = []struct {
    RuleID          string // match a specific rule ID, empty = any rule
    ContentContains string // match on the extracted string content, empty = any
    PathContains    string // match on the file path, empty = any
}{
    // Examples — uncomment and adapt as needed:

    // Suppress a known-good IP everywhere (e.g. your internal DNS server)
    // {RuleID: "IP001", ContentContains: "8.8.8.8"},

    // Suppress all findings inside vendored/third-party directories
    // {PathContains: "vendor/"},
    // {PathContains: "node_modules/"},
    // {PathContains: "third_party/"},

    // Suppress a specific rule only in test files
    // {RuleID: "CRED004", PathContains: "_test.go"},
    // {RuleID: "CRED004", PathContains: "testdata/"},

    // Suppress a URL that belongs to your own infrastructure
    // {RuleID: "URL001", ContentContains: "cdn.mycompany.com"},

    // Suppress a false positive on a specific known pattern in a binary
    // {RuleID: "BEVA002", ContentContains: "virtualbox_guest_additions"},
}
```

#### Common suppression patterns

**Known-good hosts in your codebase:**
```go
{RuleID: "IP001",  ContentContains: "192.0.2.1"},   // your staging server
{RuleID: "URL001", ContentContains: "telemetry.myapp.com"},
```

**Test and vendor directories:**
```go
{PathContains: "vendor/"},
{PathContains: "testdata/"},
{PathContains: "fixtures/"},
{PathContains: "_test."},
```

**Suppress a noisy rule entirely for a specific project:**
```go
{RuleID: "DIS004"},  // CPUID — suppress completely if you know the binary is benign
```

**Suppress a rule only in a specific file:**
```go
{RuleID: "CRED004", PathContains: "config.example."},  // example config with placeholder passwords
```

**Suppress a binary string scanner finding that is always a FP for your target:**
```go
{RuleID: "BEVA002", ContentContains: "vmware_tools_version"},  // legitimate VMware guest agent
```

#### Note on scope

Suppressions apply to all scan sources — `[text]`, `[strings]`, `[pe]`, and `[disasm]`. If you want to suppress only for binary string scans, pair the entry with a known binary extension or path pattern in `PathContains`.

#### Why not a config file?

Keeping suppressions in Go source means they are compiled in, version-controlled alongside your rules, and have zero parsing overhead. The tradeoff is that you rebuild after any change (`go build -o malcat .`), which takes under a second.

## Adding rules

Rules live in `analyzer/rules.go` (source code) and `analyzer/binary_rules.go` (binary string extraction). Each follows this signature:

```go
newRule("ID", "Name", "Category", Severity, "Details", `RegexPattern`, "keyword1", "keyword2")
```

Keywords are optional pre-filters — the regex only runs on lines containing at least one keyword (case-insensitive). This keeps scanning fast on large codebases.

For rules that need a post-match veto (e.g. to require a specific IP to be publicly routable):

```go
newRuleWithFilter("ID", "Name", "Category", Severity, "Details", `Pattern`, filterFunc, "keyword")
```

Rebuild after changes:

```bash
go build -o malcat .
```

## Limitations

- Static analysis only — cannot detect purely runtime behaviour or encrypted payloads that decode in memory
- Binary `--bin` mode requires the `strings` utility on PATH — see [Requirements](#requirements) for installation instructions. `--pe` and `--disasm` do not require it
- Disassembly (`--disasm`) uses linear sweep, not recursive descent — it can lose the instruction stream after indirect branches in heavily obfuscated code
- Compiler detection is heuristic — a stripped or deliberately mismatched binary may be misidentified, causing either missed findings or unexpected suppressions
- Results are leads to investigate, not definitive verdicts
