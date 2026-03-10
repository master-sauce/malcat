package analyzer

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Severity levels
type Severity int

const (
	Low      Severity = iota // 0
	Medium                   // 1
	High                     // 2
	Critical                 // 3
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
	// Verbose      bool
	MaxDepth     int
	Extensions   string // comma-separated, empty = all
	MinSeverity  Severity
	ScanBinaries bool // Enable/disable binary scanning
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

// Finding represents a single detected issue
type Finding struct {
	File      string
	Line      int
	Column    int
	Content   string // the matched line
	MatchText string // the specific substring that triggered the rule
	RuleID    string
	RuleName  string
	Category  string
	Severity  Severity
	Details   string
}

// FileResult groups findings per file
type FileResult struct {
	Path     string
	Findings []Finding
	Skipped  bool
	SkipMsg  string
	Error    error
}

// ScanResult is the top-level result
type ScanResult struct {
	Targets []string
	Files   []FileResult
	Stats   Stats
}

type Stats struct {
	FilesScanned  int
	FilesSkipped  int
	FilesErrored  int
	TotalFindings int
	BySeverity    map[string]int
}

// Scan is the main entry point
func Scan(targets []string, cfg Config) (*ScanResult, error) {
	result := &ScanResult{
		Targets: targets,
		Stats: Stats{
			BySeverity: map[string]int{
				"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0,
			},
		},
	}

	allowedExts := cfg.allowedExtensions()

	// KEY CHANGE: Choose the rule set based on the ScanBinaries flag
	var rules []Rule
	if cfg.ScanBinaries {
		rules = DefaultBinaryRules() // Use the binary-specific ruleset
	} else {
		rules = DefaultRules() // Use the full text-based ruleset
	}

	for _, target := range targets {
		info, err := os.Stat(target)
		if err != nil {
			result.Files = append(result.Files, FileResult{
				Path:  target,
				Error: err,
			})
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
	}
}

// filterFindings filters out false positives and findings below minimum severity
func filterFindings(findings []Finding, cfg Config) []Finding {
	var filtered []Finding
	for _, f := range findings {
		// Skip findings from false positive filter category
		if f.Category == "False Positive Filter" {
			continue
		}
		
		// Skip findings below minimum severity
		if f.Severity < cfg.MinSeverity {
			continue
		}
		
		// Add additional filtering logic here if needed
		filtered = append(filtered, f)
	}
	return filtered
}

func scanFile(path string, allowedExts map[string]bool, rules []Rule, cfg Config) FileResult {
	fr := FileResult{Path: path}

	// Check extension filter
	if allowedExts != nil {
		ext := strings.ToLower(filepath.Ext(path))
		if !allowedExts[ext] {
			fr.Skipped = true
			fr.SkipMsg = "extension not in filter"
			return fr
		}
	}

	// Handle binary files based on config
	if isBinary(path) {
		if cfg.ScanBinaries {
			// Scan binary files using strings command
			return scanBinary(path, rules, cfg)
		} else {
			// Skip binary files
			fr.Skipped = true
			fr.SkipMsg = "binary file (scanning disabled)"
			return fr
		}
	}

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
				})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		fr.Error = err
	}

	// Filter the findings before returning
	fr.Findings = filterFindings(fr.Findings, cfg)
	return fr
}

// scanBinary analyzes binary files using strings command
func scanBinary(path string, rules []Rule, cfg Config) FileResult {
	fr := FileResult{Path: path}

	// Run strings command on the binary
	cmd := exec.Command("strings", "-n", "4", path) // Only include strings 4 chars or longer
	output, err := cmd.Output()
	if err != nil {
		fr.Error = fmt.Errorf("strings command failed: %v", err)
		return fr
	}

	// Convert output to lines for analysis
	lines := strings.Split(string(output), "\n")
	lineNum := 0

	for _, line := range lines {
		lineNum++
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

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

	// Filter the findings before returning
	fr.Findings = filterFindings(fr.Findings, cfg)
	return fr
}

// isBinary does a quick check by reading the first 512 bytes
func isBinary(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	buf := make([]byte, 512)
	n, err := f.Read(buf)
	if err != nil {
		return false
	}

	for _, b := range buf[:n] {
		if b == 0 {
			return true
		}
	}
	return false
}