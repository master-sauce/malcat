package analyzer

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"malcat/internal/peparser"
)

// Severity levels
type Severity int

const (
	Low      Severity = iota
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Low:
		return "LOW"
	case Medium:
		return "MEDIUM"
	case High:
		return "HIGH"
	case Critical:
		return "CRITICAL"
	}
	return "UNKNOWN"
}

func ParseSeverity(s string) Severity {
	switch strings.ToLower(s) {
	case "medium":
		return Medium
	case "high":
		return High
	case "critical":
		return Critical
	default:
		return Low
	}
}

// Config holds scanner options
type Config struct {
	Recursive    bool
	MaxDepth     int
	Extensions   string
	MinSeverity  Severity
	ScanBinaries bool

	// PE / disasm options
	ParsePE          bool
	Disassemble      bool
	ROPDetection     bool
	DisasmDepth      int
	EntropyThreshold float64

	// All mode: enable every analysis layer
	All bool

	// Extraction-only modes: skip all other rules, just collect URLs/IPs
	ExtractURLs bool
	ExtractIPs   bool
}

func (c Config) allowedExtensions() map[string]bool {
	if c.Extensions == "" {
		return nil
	}
	m := make(map[string]bool)
	for _, ext := range strings.Split(c.Extensions, ",") {
		m[strings.TrimSpace(ext)] = true
	}
	return m
}

// FindingSource distinguishes how a finding was generated.
type FindingSource int

const (
	SourceText          FindingSource = iota
	SourceBinaryStrings
	SourcePEStruct
	SourceDisasm
)

func (s FindingSource) String() string {
	switch s {
	case SourceText:
		return "text"
	case SourceBinaryStrings:
		return "strings"
	case SourcePEStruct:
		return "pe"
	case SourceDisasm:
		return "disasm"
	}
	return "unknown"
}

// Finding represents a single detected issue
type Finding struct {
	File      string
	Line      int
	Column    int
	Content   string
	MatchText string
	RuleID    string
	RuleName  string
	Category  string
	Severity  Severity
	Details   string
	Source    FindingSource
	RVA       uint32
	Context   string
}

// FileResult groups findings per file
type FileResult struct {
	Suppressed int // count of suppressed false positives
	Path     string
	Findings []Finding
	Skipped  bool
	SkipMsg  string
	Error    error
	PE       *peparser.File
}

// ScanResult is the top-level result
type ScanResult struct {
	Targets []string
	Files   []FileResult
	Stats   Stats
}

type Stats struct {
	FilesScanned       int
	FilesSkipped       int
	FilesErrored       int
	TotalFindings      int
	SuppressedFindings int // false positives removed
	BySeverity         map[string]int
	BySource           map[string]int
}

func Scan(targets []string, cfg Config) (*ScanResult, error) {
	// --all enables every analysis layer
	if cfg.All {
		cfg.ScanBinaries = true
		cfg.ParsePE = true
		cfg.Disassemble = true
		cfg.ROPDetection = true
	}
	// --urls / --ips: scan everything (text + binary strings + PE strings)
	// but only run the URL/IP extraction rules.
	if cfg.ExtractURLs || cfg.ExtractIPs {
		cfg.ScanBinaries = true
		cfg.ParsePE = true
		// Override MinSeverity to Low so URL001/IP001 always pass the filter
		cfg.MinSeverity = Low
	}

	result := &ScanResult{
		Targets: targets,
		Stats: Stats{
			BySeverity: map[string]int{"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
			BySource:   map[string]int{"text": 0, "strings": 0, "pe": 0, "disasm": 0},
		},
	}

	allowedExts := cfg.allowedExtensions()

	var rules []Rule
	switch {
	case cfg.ExtractURLs || cfg.ExtractIPs:
		// Extraction mode: only the URL/IP rules, sourced from both rule sets
		// (they are identical in DefaultRules and DefaultBinaryRules)
		rules = extractionRules(cfg)
	case cfg.ScanBinaries:
		rules = DefaultBinaryRules()
	default:
		rules = DefaultRules()
	}

	for _, target := range targets {
		info, err := os.Stat(target)
		if err != nil {
			result.Files = append(result.Files, FileResult{Path: target, Error: err})
			result.Stats.FilesErrored++
			continue
		}
		if info.IsDir() {
			if cfg.Recursive {
				walkDir(target, 0, cfg, allowedExts, rules, result)
			} else {
				fmt.Fprintf(os.Stderr, "warning: %s is a directory, use -r to scan recursively\n", target)
			}
		} else {
			fr := scanFile(target, allowedExts, rules, cfg)
			updateStats(result, fr)
			result.Files = append(result.Files, fr)
		}
	}
	return result, nil
}

func walkDir(dir string, depth int, cfg Config, allowedExts map[string]bool, rules []Rule, result *ScanResult) {
	if cfg.MaxDepth >= 0 && depth > cfg.MaxDepth {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		result.Files = append(result.Files, FileResult{Path: dir, Error: err})
		result.Stats.FilesErrored++
		return
	}
	for _, entry := range entries {
		fullPath := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			walkDir(fullPath, depth+1, cfg, allowedExts, rules, result)
		} else {
			fr := scanFile(fullPath, allowedExts, rules, cfg)
			updateStats(result, fr)
			result.Files = append(result.Files, fr)
		}
	}
}

func updateStats(result *ScanResult, fr FileResult) {
	if fr.Skipped {
		result.Stats.FilesSkipped++
		return
	}
	if fr.Error != nil {
		result.Stats.FilesErrored++
		return
	}
	result.Stats.FilesScanned++
	for _, f := range fr.Findings {
		result.Stats.TotalFindings++
		result.Stats.BySeverity[f.Severity.String()]++
		result.Stats.BySource[f.Source.String()]++
	}
	result.Stats.SuppressedFindings += fr.Suppressed
}


func filterFindings(findings []Finding, cfg Config) ([]Finding, int) {
	var filtered []Finding
	suppressed := 0
	for _, f := range findings {
		if f.Category == "False Positive Filter" {
			suppressed++
			continue
		}
		if f.Severity < cfg.MinSeverity {
			suppressed++
			continue
		}
		// Suppress rule-artifact false positives in binary string scans
		if f.Source == SourceBinaryStrings && isRuleArtifact(f.Content) {
			suppressed++
			continue
		}
		filtered = append(filtered, f)
	}
	// Apply user-defined suppressions (rule ID, content, path)
	before := len(filtered)
	filtered = applyUserSuppressions(filtered)
	suppressed += before - len(filtered)
	// Deduplicate remaining findings
	before = len(filtered)
	filtered = deduplicateFindings(filtered)
	suppressed += before - len(filtered)
	return filtered, suppressed
}

// FileResult.suppressed is communicated back via a side channel on the struct.
// We add the field as an unexported int embedded tag trick — simpler: just add it.

func scanFile(path string, allowedExts map[string]bool, rules []Rule, cfg Config) FileResult {
	fr := FileResult{Path: path}

	if allowedExts != nil {
		ext := strings.ToLower(filepath.Ext(path))
		if !allowedExts[ext] {
			fr.Skipped = true
			fr.SkipMsg = "extension not in filter"
			return fr
		}
	}

	headerBytes := readHeader(path, 512)
	isPEFile := peparser.IsPE(headerBytes)
	isBin := isBinaryBytes(headerBytes)

	if isPEFile && cfg.ParsePE {
		return scanPE(path, rules, cfg)
	}

	if isBin {
		if cfg.ScanBinaries {
			return scanBinary(path, rules, cfg)
		}
		fr.Skipped = true
		fr.SkipMsg = "binary file (use --bin for string scan, --pe for PE analysis, --all for everything)"
		return fr
	}

	// Text scan
	f, err := os.Open(path)
	if err != nil {
		fr.Error = err
		return fr
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		for _, rule := range rules {
			if rule.Severity < cfg.MinSeverity {
				continue
			}
			col, matchText, matched := rule.Match(line)
			if matched {
				fr.Findings = append(fr.Findings, Finding{
					File:      path,
					Line:      lineNum,
					Column:    col,
					Content:   strings.TrimSpace(line),
					MatchText: matchText,
					RuleID:    rule.ID,
					RuleName:  rule.Name,
					Category:  rule.Category,
					Severity:  rule.Severity,
					Details:   rule.Details,
					Source:    SourceText,
				})
			}
		}
	}
	if err := scanner.Err(); err != nil {
		fr.Error = err
	}
	var sup int; fr.Findings, sup = filterFindings(fr.Findings, cfg); fr.Suppressed += sup
	return fr
}

func scanPE(path string, rules []Rule, cfg Config) FileResult {
	fr := FileResult{Path: path}

	pe, err := peparser.Parse(path)
	if err != nil {
		fr.Error = fmt.Errorf("PE parse error: %w", err)
		return fr
	}
	fr.PE = pe

	// In extraction mode (--urls / --ips) skip PE structural rules and disasm —
	// we only want strings from the binary, not structural findings.
	if cfg.ExtractURLs || cfg.ExtractIPs {
		for _, sf := range scanBinaryForRules(path, rules, cfg) {
			sf.Source = SourceBinaryStrings
			fr.Findings = append(fr.Findings, sf)
		}
		fr.Findings, _ = filterFindings(fr.Findings, cfg)
		return fr
	}

	// 1. PE structural rules
	for _, pf := range AnalyzePE(path, pe, cfg) {
		fr.Findings = append(fr.Findings, Finding{
			File:     path,
			RuleID:   pf.RuleID,
			RuleName: pf.RuleName,
			Category: pf.Category,
			Severity: pf.Severity,
			Details:  pf.Details,
			Context:  pf.Context,
			Source:   SourcePEStruct,
		})
	}

	// 2. Strings-level scan (with false-positive suppression)
	for _, sf := range scanBinaryForRules(path, DefaultBinaryRules(), cfg) {
		sf.Source = SourceBinaryStrings
		fr.Findings = append(fr.Findings, sf)
	}

	// 3. Disassembly
	if cfg.Disassemble {
		dCfg := DisasmConfig{
			MaxInstructions: cfg.DisasmDepth,
			ROPDetection:    cfg.ROPDetection,
		}
		for _, df := range DisassembleFile(pe, dCfg) {
			if df.Severity < cfg.MinSeverity {
				continue
			}
			sev := df.Severity
			details := df.Details
			// CPUID and RDTSC are expected in Go/Rust/GCC runtime startup code.
			// Downgrade to LOW and annotate so analysts aren't misled.
			if pe.Compiler.IsGCCompiler() && (df.RuleID == "DIS004" || df.RuleID == "DIS005") {
				sev = Low
				details = details + " (expected in " + pe.Compiler.String() + " runtime — likely benign)"
			}
			if sev < cfg.MinSeverity {
				continue
			}
			fr.Findings = append(fr.Findings, Finding{
				File:     path,
				RuleID:   df.RuleID,
				RuleName: df.RuleName,
				Category: df.Category,
				Severity: sev,
				Details:  details,
				Content:  fmt.Sprintf("%s %s", df.Mnemonic, df.Operands),
				RVA:      df.RVA,
				Context:  df.Section,
				Source:   SourceDisasm,
			})
		}
	}

	var sup int; fr.Findings, sup = filterFindings(fr.Findings, cfg); fr.Suppressed += sup
	return fr
}

func scanBinaryForRules(path string, rules []Rule, cfg Config) []Finding {
	cmd := exec.Command("strings", "-n", "4", path)
	output, err := cmd.Output()
	if err != nil {
		return nil
	}
	var findings []Finding
	for lineNum, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Pre-filter: skip lines that are obviously embedded rule text.
		// In extraction mode the user explicitly wants all URLs/IPs so we
		// skip this suppression — the deduplication step still runs.
		if !cfg.ExtractURLs && !cfg.ExtractIPs && isRuleArtifact(line) {
			continue
		}
		for _, rule := range rules {
			if rule.Severity < cfg.MinSeverity {
				continue
			}
			col, matchText, matched := rule.Match(line)
			if matched {
				findings = append(findings, Finding{
					File:      path,
					Line:      lineNum + 1,
					Column:    col,
					Content:   line,
					MatchText: matchText,
					RuleID:    rule.ID,
					RuleName:  rule.Name,
					Category:  rule.Category,
					Severity:  rule.Severity,
					Details:   rule.Details,
				})
			}
		}
	}
	return findings
}

func scanBinary(path string, rules []Rule, cfg Config) FileResult {
	fr := FileResult{Path: path}
	findings := scanBinaryForRules(path, rules, cfg)
	fr.Findings, _ = filterFindings(findings, cfg)
	return fr
}

func readHeader(path string, n int) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	buf := make([]byte, n)
	read, _ := f.Read(buf)
	return buf[:read]
}

func isBinaryBytes(buf []byte) bool {
	for _, b := range buf {
		if b == 0 {
			return true
		}
	}
	return false
}

func isBinary(path string) bool {
	return isBinaryBytes(readHeader(path, 512))
}

// extractionRules returns only the URL and/or IP rules based on config.
// These are pulled from the binary rule set (which covers both text and
// extracted binary strings) and filtered to just what was requested.
func extractionRules(cfg Config) []Rule {
	var rules []Rule
	for _, r := range DefaultBinaryRules() {
		switch r.ID {
		case "URL001":
			if cfg.ExtractURLs {
				rules = append(rules, r)
			}
		case "IP001":
			if cfg.ExtractIPs {
				rules = append(rules, r)
			}
		}
	}
	return rules
}
