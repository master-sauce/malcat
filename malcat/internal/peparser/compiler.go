package peparser

import (
	"bytes"
	"strings"
)

// Compiler represents the detected toolchain that produced a PE.
type Compiler int

const (
	CompilerUnknown   Compiler = iota
	CompilerMSVC
	CompilerGo
	CompilerRust
	CompilerGCC       // MinGW / Cygwin / GCC cross-compiler
	CompilerLLVM      // clang-cl or LLD-linked
	CompilerDelphiBCB
	CompilerNET       // .NET / CLR
)

func (c Compiler) String() string {
	switch c {
	case CompilerMSVC:
		return "MSVC"
	case CompilerGo:
		return "Go"
	case CompilerRust:
		return "Rust"
	case CompilerGCC:
		return "GCC/MinGW"
	case CompilerLLVM:
		return "LLVM/Clang"
	case CompilerDelphiBCB:
		return "Delphi/BCB"
	case CompilerNET:
		return ".NET/CLR"
	default:
		return "Unknown"
	}
}

// IsGCCompiler returns true for toolchains that legitimately produce
// high-entropy debug sections and empty/minimal PE import tables.
func (c Compiler) IsGCCompiler() bool {
	return c == CompilerGo || c == CompilerRust || c == CompilerGCC || c == CompilerLLVM
}

// DetectCompiler inspects a parsed PE and returns a best-guess toolchain.
//
// Detection order matters: stronger / more specific signals first.
// Go and GCC produce /N DWARF sections that contain arbitrary byte sequences
// including coincidental matches for .NET magic — so GC checks run before CLR.
func DetectCompiler(f *File) Compiler {
	if f == nil {
		return CompilerUnknown
	}

	// ── 1. Go (highest confidence: section name or build-ID string) ─────────
	for _, s := range f.Sections {
		lower := strings.ToLower(s.Name)
		if lower == ".go.buildid" || lower == "go.buildid" {
			return CompilerGo
		}
	}
	for _, s := range f.Sections {
		if len(s.Data) == 0 {
			continue
		}
		if bytes.Contains(s.Data, []byte("Go build ID:")) ||
			bytes.Contains(s.Data, []byte("go:buildid")) ||
			bytes.Contains(s.Data, []byte("runtime.main")) ||
			bytes.Contains(s.Data, []byte("runtime/internal")) {
			return CompilerGo
		}
	}

	// ── 2. /N sections → GCC/MinGW (or Go without build ID stripped) ────────
	// The /N naming is a COFF string-table offset convention used exclusively
	// by GNU binutils / MinGW. Three or more such sections is unambiguous.
	slashSections := 0
	for _, s := range f.Sections {
		if isSlashSection(s.Name) {
			slashSections++
		}
	}
	if slashSections >= 3 {
		return CompilerGCC
	}

	// ── 3. Rust ──────────────────────────────────────────────────────────────
	for _, s := range f.Sections {
		lower := strings.ToLower(s.Name)
		if lower == ".rustc" || lower == ".rust_eh_frame" {
			return CompilerRust
		}
		if len(s.Data) > 0 && bytes.Contains(s.Data, []byte("rustc version")) {
			return CompilerRust
		}
	}

	// ── 4. .NET / CLR ────────────────────────────────────────────────────────
	// Only check for BSJB *after* ruling out Go and GCC, because compressed
	// DWARF sections in Go binaries can contain accidental BSJB byte sequences.
	// Additionally require absence of /N sections (already checked above).
	for _, s := range f.Sections {
		if s.Name != ".text" || len(s.Data) < 4 {
			continue
		}
		// True .NET check: BSJB is the CLI metadata signature ("Magic" field
		// in ECMA-335 §II.24.2.1). It appears at a fixed offset inside the
		// metadata root, which is always pointed to by the CLR data directory.
		// As a heuristic without parsing the CLR dir, we require BSJB AND
		// the presence of a ".text" section with no executable non-text sections
		// (managed code compiles almost everything into .text).
		if bytes.Contains(s.Data, []byte("BSJB")) {
			// Extra confirmation: look for other .NET metadata strings
			if bytes.Contains(s.Data, []byte("mscorlib")) ||
				bytes.Contains(s.Data, []byte("System.Runtime")) ||
				bytes.Contains(s.Data, []byte(".ctor")) ||
				bytes.Contains(s.Data, []byte("WindowsBase")) {
				return CompilerNET
			}
		}
	}

	// ── 5. Delphi / BCB ──────────────────────────────────────────────────────
	for _, s := range f.Sections {
		lower := strings.ToLower(s.Name)
		if lower == "code" || lower == ".itext" || lower == "bss" {
			return CompilerDelphiBCB
		}
	}

	// ── 6. Rich header → MSVC ────────────────────────────────────────────────
	// MSVC linker always writes a Rich header; other toolchains never do.
	if f.HasRich && len(f.Rich) > 0 {
		for _, e := range f.Rich {
			if e.ProductID >= 0x0001 && e.ProductID <= 0x00ff {
				return CompilerMSVC
			}
		}
		// Rich header present but unknown product ID — still likely MSVC family
		return CompilerMSVC
	}

	// ── 7. LLVM / LLD ────────────────────────────────────────────────────────
	for _, s := range f.Sections {
		if s.Name == ".lld" {
			return CompilerLLVM
		}
	}

	// ── 8. Import table hints ────────────────────────────────────────────────
	for _, imp := range f.Imports {
		lower := strings.ToLower(imp.DLL)
		if strings.HasPrefix(lower, "vcruntime") ||
			lower == "msvcrt.dll" ||
			strings.HasPrefix(lower, "api-ms-win-crt") {
			return CompilerMSVC
		}
		if lower == "libgcc_s_seh-1.dll" || lower == "libstdc++-6.dll" ||
			strings.HasPrefix(lower, "libgcc") {
			return CompilerGCC
		}
	}

	return CompilerUnknown
}

// isSlashSection returns true for COFF /N string-table offset section names
// used by GNU binutils (e.g. "/4", "/19", "/112").
func isSlashSection(name string) bool {
	if len(name) < 2 || name[0] != '/' {
		return false
	}
	for _, c := range name[1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
