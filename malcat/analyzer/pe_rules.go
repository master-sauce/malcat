package analyzer

import (
	"fmt"
	"strings"

	"malcat/internal/peparser"
)

// PEFinding is a finding derived from PE structural analysis.
type PEFinding struct {
	File     string
	RuleID   string
	RuleName string
	Category string
	Severity Severity
	Details  string
	Context  string // e.g. section name, import name
}

// KnownBadImportCombos lists Windows API triads that together strongly indicate
// malicious behaviour. Each combo is a slice of lowercased "dll::func" pairs.
var knownBadImportCombos = []struct {
	RuleID  string
	Name    string
	Detail  string
	Sev     Severity
	Imports []string
}{
	{
		"PE006a", "Classic injection triad",
		"VirtualAllocEx + WriteProcessMemory + CreateRemoteThread — process injection",
		Critical,
		[]string{"kernel32.dll::virtualallocex", "kernel32.dll::writeprocessmemory", "kernel32.dll::createremotethread"},
	},
	{
		"PE006b", "Process hollowing API set",
		"CreateProcess(suspended) + NtUnmapViewOfSection — process hollowing",
		Critical,
		[]string{"kernel32.dll::createprocessa", "ntdll.dll::ntunmapviewofsection"},
	},
	{
		"PE006c", "Reflective DLL load pattern",
		"VirtualAlloc + VirtualProtect(RWX) + CreateThread — reflective DLL / shellcode runner",
		Critical,
		[]string{"kernel32.dll::virtualalloc", "kernel32.dll::virtualprotect", "kernel32.dll::createthread"},
	},
	{
		"PE006d", "Credential dump API set",
		"MiniDumpWriteDump targeting LSASS — credential extraction",
		Critical,
		[]string{"dbghelp.dll::minidumpwritedump", "kernel32.dll::openprocess"},
	},
	{
		"PE006e", "Keylogger API set",
		"SetWindowsHookEx + GetAsyncKeyState — keylogger",
		High,
		[]string{"user32.dll::setwindowshookexa", "user32.dll::getasynckeystate"},
	},
	{
		"PE006f", "Ransomware crypto API set",
		"CryptEncrypt + FindFirstFile + file enumeration — ransomware loop",
		Critical,
		[]string{"advapi32.dll::cryptencrypt", "kernel32.dll::findfirstfilea"},
	},
	{
		"PE006g", "Anti-debug API set",
		"IsDebuggerPresent + CheckRemoteDebuggerPresent — anti-analysis",
		High,
		[]string{"kernel32.dll::isdebuggerpresent", "kernel32.dll::checkremotedebuggerpresent"},
	},
	{
		"PE006h", "Dynamic API resolution",
		"LoadLibrary + GetProcAddress without matching imports — IAT hiding",
		High,
		[]string{"kernel32.dll::loadlibrarya", "kernel32.dll::getprocaddress"},
	},
	{
		"PE006i", "Screen capture / RAT",
		"GetDC + BitBlt — screen capture capability",
		Medium,
		[]string{"user32.dll::getdc", "gdi32.dll::bitblt"},
	},
	{
		"PE006j", "Token impersonation",
		"OpenProcessToken + AdjustTokenPrivileges — privilege escalation",
		High,
		[]string{"advapi32.dll::openprocesstoken", "advapi32.dll::adjusttokenprivileges"},
	},
}

// AnalyzePE runs all structural PE checks and returns findings.
func AnalyzePE(path string, pe *peparser.File, cfg Config) []PEFinding {
	var findings []PEFinding

	// Detect compiler so we can suppress FPs specific to GC-compiled binaries
	// (Go, Rust, GCC/MinGW all produce high-entropy debug sections and minimal
	// import tables that are completely normal and non-malicious)
	compiler := pe.Compiler
	isGCCompiler := compiler.IsGCCompiler()
	_ = isGCCompiler

	// ── PE001: High-entropy section (packed/encrypted) ──
	threshold := cfg.EntropyThreshold
	if threshold <= 0 {
		threshold = 7.2
	}
	for _, s := range pe.Sections {
		// GC compilers (Go/Rust/GCC) legitimately produce high-entropy debug
		// sections named /N (DWARF compressed), .gnu_debugdata, .rustc, etc.
		// Suppress entropy alerts on these known-benign debug section patterns.
		if isGCCompiler && isKnownDebugSection(s.Name) {
			continue
		}
		if s.Entropy >= threshold && s.RawSize >= 256 {
			sev := High
			if s.Executable {
				sev = Critical
			}
			findings = append(findings, PEFinding{
				File:     path,
				RuleID:   "PE001",
				RuleName: "High-entropy section",
				Category: "Packing/Encryption",
				Severity: sev,
				Details:  fmt.Sprintf("section %q has entropy %.2f (threshold %.2f) — likely packed, encrypted, or compressed payload", s.Name, s.Entropy, threshold),
				Context:  s.Name,
			})
		}
	}

	// ── PE002: No imports (shellcode-style PE / fully manual-mapped) ──
	// Go and Rust binaries legitimately have no or minimal imports — suppress.
	if len(pe.Imports) == 0 && !isGCCompiler {
		findings = append(findings, PEFinding{
			File:     path,
			RuleID:   "PE002",
			RuleName: "No imports",
			Category: "Shellcode/Packing",
			Severity: Critical,
			Details:  "PE has zero imports — manually resolves APIs at runtime (common in shellcode loaders, reflective DLLs, and packed malware)",
			Context:  "ImportTable",
		})
	}

	// ── PE003: TLS callbacks (pre-entry code) ──
	if pe.TLS.Present {
		sev := High
		ctx := "TLS directory present"
		if pe.TLS.CallbackCount > 0 {
			sev = Critical
			ctx = fmt.Sprintf("%d TLS callback(s) at RVAs: %s", pe.TLS.CallbackCount, formatRVAs(pe.TLS.CallbackRVAs))
		}
		findings = append(findings, PEFinding{
			File:     path,
			RuleID:   "PE003",
			RuleName: "TLS callback",
			Category: "Execution",
			Severity: sev,
			Details:  "TLS callbacks execute before the declared entry point — common anti-debug and loader technique",
			Context:  ctx,
		})
	}

	// ── PE004: Executable section with W+X (writable + executable) ──
	for _, s := range pe.Sections {
		if s.IsWX() {
			findings = append(findings, PEFinding{
				File:     path,
				RuleID:   "PE004",
				RuleName: "Writable+executable section",
				Category: "Shellcode/Injection",
				Severity: Critical,
				Details:  fmt.Sprintf("section %q is both writable and executable (W|X) — allows self-modification or shellcode staging", s.Name),
				Context:  s.Name,
			})
		}
	}

	// ── PE005: Known packer section names ──
	for _, s := range pe.Sections {
		if s.SuspiciousName {
			findings = append(findings, PEFinding{
				File:     path,
				RuleID:   "PE005",
				RuleName: "Packer section name",
				Category: "Packing",
				Severity: Medium,
				Details:  fmt.Sprintf("section name %q matches known packer/protector (UPX, Themida, VMProtect, etc.)", s.Name),
				Context:  s.Name,
			})
		}
	}

	// ── PE006: Malicious import combinations ──
	for _, combo := range knownBadImportCombos {
		if importComboPresent(pe.ImportSet, combo.Imports) {
			findings = append(findings, PEFinding{
				File:     path,
				RuleID:   combo.RuleID,
				RuleName: combo.Name,
				Category: "Malicious Imports",
				Severity: combo.Sev,
				Details:  combo.Detail,
				Context:  strings.Join(funcNames(combo.Imports), ", "),
			})
		}
	}

	// ── PE007: Overlay data ──
	if pe.Overlay.Present {
		sev := Medium
		if pe.Overlay.Size > 1024*1024 {
			sev = High // > 1 MB overlay is very suspicious
		}
		findings = append(findings, PEFinding{
			File:     path,
			RuleID:   "PE007",
			RuleName: "Overlay data",
			Category: "Hidden Payload",
			Severity: sev,
			Details:  fmt.Sprintf("%.1f KB of data appended after last section at offset 0x%x — could be embedded config, second stage, or certificate", float64(pe.Overlay.Size)/1024, pe.Overlay.Offset),
			Context:  fmt.Sprintf("offset=0x%x size=%d", pe.Overlay.Offset, pe.Overlay.Size),
		})
	}

	// ── PE008: Checksum mismatch ──
	// GC linkers (Go, Rust, MinGW) don't compute valid PE checksums by default.
	if !isGCCompiler {
	for _, a := range pe.Anomalies {
		if a.Field == "Checksum" {
			findings = append(findings, PEFinding{
				File:     path,
				RuleID:   "PE008",
				RuleName: "Checksum mismatch",
				Category: "Anomaly",
				Severity: Low,
				Details:  a.Message,
				Context:  "OptionalHeader.CheckSum",
			})
		}
		if a.Field == "EntryPoint" {
			findings = append(findings, PEFinding{
				File:     path,
				RuleID:   "PE009",
				RuleName: "Anomalous entry point",
				Category: "Anomaly",
				Severity: High,
				Details:  a.Message,
				Context:  fmt.Sprintf("EP=0x%x", pe.EntryPoint),
			})
		}
	}
	} // end !isGCCompiler checksum block

	// ── PE010: Entry point in last section (tail-call packer) ──
	if len(pe.Sections) > 0 {
		lastSec := pe.Sections[len(pe.Sections)-1]
		if pe.EntryPoint >= lastSec.VirtualAddress &&
			pe.EntryPoint < lastSec.VirtualAddress+lastSec.VirtualSize &&
			len(pe.Sections) > 1 {
			findings = append(findings, PEFinding{
				File:     path,
				RuleID:   "PE010",
				RuleName: "Entry point in last section",
				Category: "Packing",
				Severity: Medium,
				Details:  fmt.Sprintf("entry point (0x%x) falls in the last section %q — common packer pattern (unpacking stub executes last)", pe.EntryPoint, lastSec.Name),
				Context:  lastSec.Name,
			})
		}
	}

	// ── PE011: Suspicious import-only DLLs (no .text imports, only unusual ones) ──
	if hasOnlyShellImports(pe.ImportSet) && len(pe.Imports) < 6 && len(pe.Imports) > 0 {
		findings = append(findings, PEFinding{
			File:     path,
			RuleID:   "PE011",
			RuleName: "Minimal suspicious imports",
			Category: "Shellcode",
			Severity: High,
			Details:  fmt.Sprintf("only %d import(s), all suspicious (LoadLibrary/GetProcAddress/VirtualAlloc) — manual API resolution pattern", len(pe.Imports)),
			Context:  importList(pe.Imports, 8),
		})
	}

	// ── PE012: Rich header fingerprint ──
	// Go/Rust/GCC never emit a Rich header — only MSVC does.
	// Only flag this for unknown-compiler binaries where absence is suspicious.
	if !pe.HasRich && len(pe.Sections) > 0 && compiler == peparser.CompilerUnknown {
		findings = append(findings, PEFinding{
			File:     path,
			RuleID:   "PE012",
			RuleName: "No Rich header",
			Category: "Anomaly",
			Severity: Low,
			Details:  "PE has no Rich header — may indicate a hand-crafted binary, shellcode runner, or tampered file",
			Context:  "DosStub",
		})
	}

	// ── Filter by min severity ──
	var filtered []PEFinding
	for _, f := range findings {
		if f.Severity >= cfg.MinSeverity {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func importComboPresent(importSet map[string]bool, combo []string) bool {
	for _, imp := range combo {
		// Try exact match first
		if importSet[imp] {
			continue
		}
		// Try without DLL prefix (some binaries use forwarded imports)
		parts := strings.SplitN(imp, "::", 2)
		if len(parts) != 2 {
			return false
		}
		funcName := strings.ToLower(parts[1])
		found := false
		for k := range importSet {
			if strings.HasSuffix(k, "::"+funcName) {
				found = true
				break
			}
		}
		if !found {
			// Try with A/W suffix variants
			for k := range importSet {
				if strings.HasSuffix(k, "::"+funcName+"a") || strings.HasSuffix(k, "::"+funcName+"w") {
					found = true
					break
				}
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func funcNames(imports []string) []string {
	var names []string
	for _, imp := range imports {
		parts := strings.SplitN(imp, "::", 2)
		if len(parts) == 2 {
			names = append(names, parts[1])
		}
	}
	return names
}

func formatRVAs(rvas []uint32) string {
	var parts []string
	for _, r := range rvas {
		parts = append(parts, fmt.Sprintf("0x%x", r))
	}
	return strings.Join(parts, ", ")
}

var shellImports = map[string]bool{
	"kernel32.dll::loadlibrarya":  true,
	"kernel32.dll::loadlibraryw":  true,
	"kernel32.dll::getprocaddress": true,
	"kernel32.dll::virtualalloc":  true,
	"kernel32.dll::virtualprotect": true,
}

func hasOnlyShellImports(importSet map[string]bool) bool {
	for k := range importSet {
		if !shellImports[k] {
			return false
		}
	}
	return true
}

func importList(imports []peparser.Import, max int) string {
	var parts []string
	for i, imp := range imports {
		if i >= max {
			parts = append(parts, "...")
			break
		}
		parts = append(parts, imp.DLL+"::"+imp.Function)
	}
	return strings.Join(parts, ", ")
}

// ─── Compiler-aware helpers ───────────────────────────────────────────────────

// isKnownDebugSection returns true for section names that are legitimately
// high-entropy in GC-compiled binaries (Go, Rust, GCC/MinGW).
//
// /N sections: MinGW/GCC DWARF debug sections (compressed, always high entropy)
// .gnu_debugdata: compressed mini-debuginfo (GCC/LLVM)
// .rustc: Rust compiler metadata
// .debug_*: DWARF sections from various compilers
func isKnownDebugSection(name string) bool {
	if len(name) == 0 {
		return false
	}
	// MinGW/GCC numeric debug sections: /4, /19, /32, /46, /65 …
	if name[0] == '/' {
		allDigits := true
		for _, c := range name[1:] {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits && len(name) > 1 {
			return true
		}
	}
	lower := strings.ToLower(name)
	return lower == ".gnu_debugdata" ||
		lower == ".rustc" ||
		lower == ".rust_eh_frame" ||
		strings.HasPrefix(lower, ".debug_") ||
		lower == ".zdebug_info" ||
		lower == ".note.go.buildid" ||
		lower == ".go.buildid"
}
