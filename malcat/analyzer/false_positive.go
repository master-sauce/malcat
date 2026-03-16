package analyzer

import (
	"regexp"
	"strings"
)

// ─── False positive suppression ──────────────────────────────────────────────
//
// This file controls what gets filtered before a finding is reported.
// There are two places to add your own suppressions:
//
//  1. UserSuppressions (bottom of this file) — the main place to add
//     your own rules. Suppress by rule ID, keyword in the matched content,
//     or file path pattern.
//
//  2. isBareRegistryFragment — tune the context requirements for \\SAM,
//     \\SYSTEM, \\SECURITY detections if you get FPs from those.
//
// The general-purpose logic below handles cases that apply to any binary
// scanner regardless of what tool is being scanned.

// ─── Regex artifact detection ─────────────────────────────────────────────────
//
// When scanning compiled binaries with --bin or --all, strings(1) extracts
// printable sequences from the binary's read-only data. If the binary
// contains regex patterns as string literals (e.g. any security tool,
// linter, or validator), those patterns will match their own rules.
// We detect this by recognising regex syntax indicators.

var rePatternIndicators = []*regexp.Regexp{
	regexp.MustCompile(`\[\s*\\s\\S\s*\]`), // [\s\S]
	regexp.MustCompile(`\{0,\d+\}`),        // {0,200}
	regexp.MustCompile(`\(\?i\)`),          // (?i)
	regexp.MustCompile(`\(\?i\)\(`),        // (?i)(
	regexp.MustCompile(`\\b\(`),            // \b(
	regexp.MustCompile(`\[\^\\s\]`),        // [^\s]
	regexp.MustCompile(`\[\^;\]`),          // [^;]
	regexp.MustCompile(`\[0-9A-Z\]`),       // [0-9A-Z]
	regexp.MustCompile(`\[\s*\\n\s*\]`),    // [\n]
	regexp.MustCompile(`\\s\*\[`),          // \s*[
	regexp.MustCompile(`\)\[\\s`),          // )[\s
	regexp.MustCompile(`\|\\s\*\)`),        // |\s*)
}

// isRegexArtifact returns true when the content looks like regex source code
// rather than real malicious content extracted from a binary.
func isRegexArtifact(content string) bool {
	for _, re := range rePatternIndicators {
		if re.MatchString(content) {
			return true
		}
	}
	return false
}

// ─── Bare registry fragment detection ────────────────────────────────────────
//
// \SAM, \SYSTEM, \SECURITY only matter as credential theft indicators when
// they appear with registry context (HKLM, HKCU, config, System32).
// A bare short fragment like "\SAm" is almost always a path substring or
// a regex snippet, not a real SAM database access.

// isBareRegistryFragment returns true for short \SAM/\SYSTEM/\SECURITY strings
// without qualifying registry context.
func isBareRegistryFragment(content string) bool {
	lower := strings.ToLower(strings.TrimSpace(content))

	fragments  := []string{`\sam`, `\system`, `\security`}
	qualifiers := []string{"hklm", "hkcu", "hkey", "config", "system32", "windows", "reg "}

	for _, frag := range fragments {
		if strings.Contains(lower, frag) {
			for _, q := range qualifiers {
				if strings.Contains(lower, q) {
					return false // has context → real finding
				}
			}
			// No qualifying context and short → likely a path fragment or artifact
			if len(content) < 40 {
				return true
			}
		}
	}
	return false
}

// ─── Keyword soup detection ───────────────────────────────────────────────────
//
// Compiled binaries pack adjacent small string constants together in rodata.
// A security tool's keyword arrays (["vbox","qemu","vmware",...]) get emitted
// as one concatenated blob that matches the very rules those keywords belong to.
// We detect this by counting how many short rule-keyword atoms appear together.

var keywordSoupAtoms = []string{
	"vbox", "qemu", "vmware", "sandboxie", "cuckoo", "wireshark", "procmon",
	"lhost", "lport", "rhost", "rport",
	"histfile", "histsize", "bash_history",
	"ld_preload",
	"certutil", "regsvr32", "rundll32", "bitsadmin", "mshta",
	"atob", "fromcharcode", "unescape",
	"dup2", "execve", "lsass",
	"authorized_keys",
}

// isKeywordSoup returns true when 4+ rule keyword atoms appear in a single
// extracted string — a strong indicator of a packed keyword array, not payload.
func isKeywordSoup(content string) bool {
	lower := strings.ToLower(content)
	count := 0
	for _, kw := range keywordSoupAtoms {
		if strings.Contains(lower, kw) {
			count++
			if count >= 4 {
				return true
			}
		}
	}
	return false
}

// ─── Bare API keyword detection ───────────────────────────────────────────────
//
// Windows API names stored as rule keywords appear as bare isolated strings
// when extracted from compiled binaries. A real malicious binary would have
// these in its import table or surrounded by call context, not as lone tokens.

var bareAPIKeywords = []string{
	"virtualallocex",
	"writeprocessmemory",
	"createremotethread",
	"ntunmapviewofsection",
	"zwunmapviewofsection",
	"create_suspended",
	"minidumpwritedump",
	"isdebuggerpresent",
	"checkremotedebuggerpresent",
	"page_execute_readwrite",
}

// isBareAPIKeyword returns true for bare API name tokens with no surrounding
// legitimate call context (DLL name, hex address, module reference).
func isBareAPIKeyword(content string) bool {
	lower := strings.ToLower(strings.TrimSpace(content))
	for _, kw := range bareAPIKeywords {
		if lower == kw {
			return true
		}
		// Short content dominated by the keyword with no realistic context
		if len(content) <= 60 && strings.Contains(lower, kw) {
			if !strings.Contains(lower, "kernel32") &&
				!strings.Contains(lower, "ntdll") &&
				!strings.Contains(lower, "0x") &&
				!strings.Contains(lower, "proc ") &&
				!strings.Contains(lower, "module") {
				return true
			}
		}
	}
	return false
}

// ─── Master suppression check ─────────────────────────────────────────────────

// isRuleArtifact is the main entry point called by the scanner before
// recording a finding from binary string extraction.
// Returns true if the content should be suppressed as a false positive.
func isRuleArtifact(content string) bool {
	if isBareRegistryFragment(content) {
		return true
	}
	if isKeywordSoup(content) {
		return true
	}
	if isBareAPIKeyword(content) {
		return true
	}
	if isRegexArtifact(content) {
		return true
	}
	// Check user-defined suppressions
	return isUserSuppressed(content)
}

// ─── Deduplication ───────────────────────────────────────────────────────────

// deduplicateFindings collapses identical (ruleID, content, context) findings.
// Prevents the same string pattern matching at adjacent offsets in a binary's
// string table from flooding the output.
func deduplicateFindings(findings []Finding) []Finding {
	type key struct {
		ruleID  string
		content string
		context string
		rva     uint32
	}
	seen := make(map[key]bool)
	var out []Finding
	for _, f := range findings {
		k := key{
			ruleID:  f.RuleID,
			content: truncateKey(f.Content, 80),
			context: f.Context,
			rva:     f.RVA,
		}
		if !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	return out
}

func truncateKey(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// ═════════════════════════════════════════════════════════════════════════════
// USER SUPPRESSIONS
// Add your own false positive suppressions here.
// ═════════════════════════════════════════════════════════════════════════════

// UserSuppressions defines custom suppression rules.
// Three ways to suppress a finding:
//
//  1. By rule ID — suppress a specific rule entirely for your codebase:
//       {ruleID: "URL001"}
//
//  2. By content keyword — suppress when the matched content contains a string:
//       {contentContains: "cdn.mycompany.com"}
//
//  3. By file path pattern — suppress when the file path contains a string:
//       {pathContains: "vendor/"}
//
// Conditions within one entry are ANDed. Multiple entries are ORed.
//
// Examples:
//
//   {ruleID: "IP001", contentContains: "8.8.8.8"},       // known-good DNS server
//   {pathContains: "testdata/"},                          // suppress all in test dirs
//   {ruleID: "CRED004", pathContains: "test_"},           // only in test files
//   {ruleID: "URL001", contentContains: "localhost"},     // local dev URLs

var UserSuppressions = []struct {
	RuleID          string // empty = match any rule
	ContentContains string // empty = match any content
	PathContains    string // empty = match any path
}{}

// isUserSuppressed checks a finding's content against UserSuppressions.
// Call with the matched content string; path checking happens in filterFindings.
func isUserSuppressed(content string) bool {
	for _, sup := range UserSuppressions {
		if sup.PathContains != "" {
			// Path suppressions are checked at the finding level in filterFindings,
			// not here — skip them in the content-only check.
			continue
		}
		if sup.RuleID != "" {
			// Rule-ID suppressions without path need to be matched at finding level too.
			continue
		}
		if sup.ContentContains != "" {
			if strings.Contains(strings.ToLower(content), strings.ToLower(sup.ContentContains)) {
				return true
			}
		}
	}
	return false
}

// applyUserSuppressions filters findings against the full UserSuppressions list,
// including rule ID and path matching that requires the full Finding struct.
func applyUserSuppressions(findings []Finding) []Finding {
	if len(UserSuppressions) == 0 {
		return findings
	}
	var out []Finding
	for _, f := range findings {
		suppressed := false
		for _, sup := range UserSuppressions {
			ruleMatch := sup.RuleID == "" || sup.RuleID == f.RuleID
			contentMatch := sup.ContentContains == "" ||
				strings.Contains(strings.ToLower(f.Content), strings.ToLower(sup.ContentContains))
			pathMatch := sup.PathContains == "" ||
				strings.Contains(f.File, sup.PathContains)

			if ruleMatch && contentMatch && pathMatch {
				suppressed = true
				break
			}
		}
		if !suppressed {
			out = append(out, f)
		}
	}
	return out
}
