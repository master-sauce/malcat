# malcat

A fast, low-false-positive static analyzer for detecting malicious patterns in source code and compiled binaries. Built for scanning open-source projects you've cloned and want to trust before running, as well as deep analysis of suspicious PE executables.

## Installation

```bash
# Linux / macOS
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
| `--bin`, `--binaries` | String-extraction scan on binary files using `strings` |

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

## False positive suppression

malcat applies several layers of suppression to avoid crying wolf:

**Rule-artifact suppression** — when scanning compiled binaries with `--bin` or `--all`, the tool's own rule patterns (regex strings, rule names, keyword lists) are embedded in the binary's read-only data and will be extracted by `strings`. malcat detects these by recognising regex syntax indicators (`(?i)`, `[\s\S]`, `{0,N}`), rule detail phrases, and keyword-array concatenation blobs, and suppresses them before they match any rule.

**Compiler-aware suppression** — high-entropy debug sections, empty import tables, missing PE checksums, and missing Rich headers are all normal for Go/Rust/GCC-compiled binaries. malcat detects the compiler first and suppresses the rules that would produce FPs for that toolchain.

**Context-aware suppression** — short fragments like `\SAM` or `\SYSTEM` are only flagged as credential theft indicators when they appear with qualifying registry context (`HKLM`, `HKCU`, `config`, `System32`). Bare fragments that appear as substrings of source paths or rule keyword arrays are suppressed.

**Deduplication** — identical `(ruleID, content)` pairs at adjacent binary offsets are collapsed to a single finding.

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
- Binary `--bin` mode depends on the `strings` utility being on PATH (standard on Linux/macOS; available via Git for Windows or WSL on Windows)
- Disassembly (`--disasm`) uses linear sweep, not recursive descent — it can lose the instruction stream after indirect branches in heavily obfuscated code
- Compiler detection is heuristic — a stripped or deliberately mismatched binary may be misidentified, causing either missed findings or unexpected suppressions
- Results are leads to investigate, not definitive verdicts
