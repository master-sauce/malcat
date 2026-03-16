package analyzer

import (
	"regexp"
	"strings"
)

// ─── False positive suppression for binary string scans ──────────────────────
//
// When scanning compiled binaries (including malcat itself), the strings(1)
// extractor pulls out the tool's own embedded rule text: regex patterns, rule
// names, details strings, and category labels. These look exactly like the
// things they detect, producing 100% false positives.
//
// We suppress a finding when the matched content is clearly a rule artifact
// rather than an actual malicious payload string.

// rePatternIndicators matches strings that look like regex source code.
// Any string extracted from a binary that contains these is almost certainly
// an embedded regex, not actual malicious content.
var rePatternIndicators = []*regexp.Regexp{
	// Regex character class / quantifiers embedded in the content
	regexp.MustCompile(`\[\s*\\s\\S\s*\]`),        // [\s\S]
	regexp.MustCompile(`\{0,\d+\}`),               // {0,200}
	regexp.MustCompile(`\(\?i\)`),                 // (?i)
	regexp.MustCompile(`\(\?i\)\(`),               // (?i)(
	regexp.MustCompile(`\\b\(`),                   // \b(
	regexp.MustCompile(`\[\^\\s\]`),               // [^\s]
	regexp.MustCompile(`\[\^;\]`),                 // [^;]
	regexp.MustCompile(`\[0-9A-Z\]`),              // [0-9A-Z]
	regexp.MustCompile(`\[\s*\\n\s*\]`),           // [\n]
	regexp.MustCompile(`\\s\*\[`),                 // \s*[
	regexp.MustCompile(`\)\[\\\s`),                // )[\ s
	regexp.MustCompile(`\|\\s\*\)`),               // |\s*)
	regexp.MustCompile(`\?\s*:\s*\\s`),            // ?: \s
}

// ruleNamePhrases are substrings that only appear in rule detail/name text
// that malcat itself embeds — never in real malware payloads.
var ruleNamePhrases = []string{
	"— classic shellcode alignment pad",
	"— common malware",
	"— potential C2",
	"— credential extraction",
	"— execution bypass",
	"— AppLocker bypass",
	"— covering tracks",
	"— disk wipe",
	"— keyboard input capture",
	"potential SSH backdoor",
	"Cron path string with write intent",
	"Accessing /etc/shadow or SAM",
	"manual API resolution pattern",
	"Hardcoded public IPv4 address",
	"Metasploit-style LHOST/LPORT",
	"LSASS dump tooling strings",
	"XOR-based decryption loop with hardcoded key",
	"VirtualAllocEx + WriteProcessMemory or CreateRemoteThread",
	"CreateProcess(suspended) + NtUnmapViewOfSection",
	"VirtualAllocEx + WriteProcessMemory + CreateRemoteThread",
	"reflective DLL / shellcode runner",
	"PAGE_EXECUTE_READWRITE memory allocation",
	"IsDebuggerPresent or PEB.BeingDebugged",
	"VMware/VirtualBox/QEMU string checks",
	"MiniDumpWriteDump targeting LSASS",
	"WMIC process call create",
	"regsvr32 /s with scrobj",
	"Shell command clearing logs",
	"known ransomware family name",
	"Multiple decryption layers",
	"Self-modifying decryption routine",
	"Decrypting API function names",
	"RC4 decryption followed by",
	"Base64 decoding to executable memory",
	"Custom decryption function with",
	"Encrypted payload in resources",
	"Shellcode XOR decryption with single-byte",
	"Writing to cron via echo",
	"Dropping a systemd unit file",
	"Writing to Windows autorun registry",
	"Creating a scheduled task via",
	"Fetching remote content and piping",
	"PowerShell downloading and immediately",
	"-EncodedCommand used to hide",
	"Beacon/sleep loop with hardcoded",
	"Raw socket created then shell",
	"Data exfiltration or C2 via DNS",
	"Netcat spawning a shell",
	"Python socket connected then stdio",
	"Classic reverse shell redirecting",
	"Reading sensitive credential files",
	"Dumping LSASS process memory",
	"AWS access key ID hardcoded",
	"Secret, password, or token hardcoded",
	"Deleting root or critical system",
	"Writing zeros/random data directly",
	"Classic fork bomb",
	"Encrypting files in a loop",
	"certutil used to download or decode",
	"regsvr32 loading a remote scriptlet",
	"rundll32 loading from a UNC path",
	"mshta loading remote HTA",
	"WMIC used to create a process",
	"bitsadmin used to download",
	"Decoding base64 and immediately executing",
	"Building strings from character codes",
	"eval() wrapping an encoded",
	"URL found in file",
	"Hardcoded public IPv4 address",
	// Rule IDs appearing as context in embedded strings
	"BNET00", "BPER00", "BINJ00", "BEVA00", "BCRED00", "BLOL00", "BDST00",
	"DEC001", "DEC002", "DEC003", "DEC004", "DEC005", "DEC006",
	"DEC007", "DEC008", "DEC009", "DEC010",
	"NET001", "NET002", "NET003", "NET004", "NET005", "NET006",
	"PER001", "PER002", "PER003", "PER004",
	"INJ001", "INJ002", "INJ003",
	"CRED001", "CRED002", "CRED003", "CRED004",
	"DST001", "DST002", "DST003", "DST004",
	"LOL001", "LOL002", "LOL003", "LOL004", "LOL005", "LOL006",
	"OBF001", "OBF002", "OBF003",
	"PE001", "PE002", "PE003", "PE004", "PE005",
	"PE006a", "PE006b", "PE006c", "PE006d", "PE006e",
	"PE006f", "PE006g", "PE006h", "PE006i", "PE006j",
	"PE007", "PE008", "PE009", "PE010", "PE011", "PE012",
	"DIS001", "DIS002", "DIS003", "DIS004", "DIS005", "DIS006", "DIS007",
	"URL001", "IP001",
}

// isRuleArtifact returns true when the content string is clearly an embedded
// rule definition (regex pattern, rule detail text, or rule ID catalog) rather
// than real malicious content extracted from the target binary.
func isRuleArtifact(content string) bool {
	// Bare registry path fragment (\SAM, \SYSTEM without qualifying context)
	if isBareRegistryFragment(content) {
		return true
	}
	// Keyword soup: multiple rule keywords packed in one rodata blob
	if isKeywordSoup(content) {
		return true
	}
	// Bare API name from rule keyword table
	if isBareAPIKeyword(content) {
		return true
	}

	lower := strings.ToLower(content)

	// Check for regex pattern indicators
	for _, re := range rePatternIndicators {
		if re.MatchString(content) {
			return true
		}
	}

	// Check for rule name / detail phrases
	for _, phrase := range ruleNamePhrases {
		if strings.Contains(lower, strings.ToLower(phrase)) {
			return true
		}
	}

	// Strings that are concatenations of multiple rule IDs (the rule catalog)
	// e.g. "PE006ePE006fPE006gPE006h..."
	ruleIDCount := 0
	for _, id := range []string{
		"PE00", "NET00", "PER00", "INJ00", "CRED00", "DST00",
		"LOL00", "OBF00", "DEC00", "DIS00", "BNET0", "BPER0",
		"BINJ0", "BEVA0", "BCRED0", "BLOL0", "BDST0",
	} {
		if strings.Contains(content, id) {
			ruleIDCount++
		}
	}
	if ruleIDCount >= 3 {
		return true
	}

	return false
}

// deduplicateFindings removes duplicate findings that have identical
// (RuleID, Content/Context) fingerprints within the same file.
// This prevents the same string pattern matching multiple times at
// adjacent offsets within a binary's string table.
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
		// For text findings, deduplicate on exact (ruleID, line) — same line can
		// only produce one finding per rule.
		// For binary/PE findings, deduplicate on (ruleID, content snippet).
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

// truncateKey shortens a string for use as a dedup map key.
func truncateKey(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// apiNameOnlyPhrases are Windows API names that are stored as bare strings in
// malcat's own rule keyword lists. When extracted by strings(1) they appear
// in isolation or concatenated with other rule keywords — never as genuine
// API calls in a target binary (which would have import table entries instead).
//
// These are suppressed ONLY when the content is a short bare string or part of
// a rule-keyword concatenation — not when surrounded by realistic call context.
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
	"getprocaddress",
	"loadlibrarya",
	"virtualprotect",
	"openprocesstoken",
	"adjusttokenprivileges",
}

// ruleContextPhrases appear in strings that are rule-adjacent concatenations:
// the binary's rodata smears adjacent string literals together.
var ruleContextPhrases = []string{
	"Certutil abuse",
	"getprocaddressvirtualprotect",
	"currentversion\\run",
	"Regsvr32 scriptlet",
	"Runtime Decr",
	"Reverse shell string",
	"LD_PRELOAD injection",
	"High-entropy section",
	"Root deletion command",
	"TLS directory present",
	"False Positive Filter",
	"PE parse error",
	"-debug API set",
	"manual API resolution",
	"No importshypervisor",
	"NOP (sled)",
	"Sandbox",
	"shellcodeShellcode",
	"wiresharkDisk wip",
	"Disk wip",
	"C2/BackdoorPersistence",
	"DestructiveloadlibraryImportTable",
	"RDTSC ",
	"Credential TheftAKIA",
}

func init() {
	// Extend isRuleArtifact checks with these additional phrase lists.
	// We append them into ruleNamePhrases so the existing logic picks them up.
	ruleNamePhrases = append(ruleNamePhrases, ruleContextPhrases...)
}

// isBareAPIKeyword returns true if the content is just a bare API name from
// malcat's own rule keyword lists, with no surrounding legitimate call context.
func isBareAPIKeyword(content string) bool {
	lower := strings.ToLower(strings.TrimSpace(content))
	// Bare: the whole string IS the keyword, or the keyword fills most of it
	for _, kw := range bareAPIKeywords {
		if lower == kw {
			return true
		}
		// Short content (≤60 chars) that is mostly just the keyword + noise
		if len(content) <= 60 && strings.Contains(lower, kw) {
			// Check it's not surrounded by realistic context
			// Realistic context: preceded/followed by DLL name, "proc", "module", hex addr
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

// shortRuleKeywords are the brief keyword atoms malcat stores in its rule tables.
// When 4+ of these appear in the same extracted string, it's the binary's own
// keyword array being concatenated by strings(1), not real malicious content.
var shortRuleKeywords = []string{
	"vbox", "qemu", "vmware", "sandboxie", "cuckoo", "wireshark", "procmon",
	"lhost", "lport", "rhost", "rport",
	"akia",
	"histfile", "histsize", "bash_history",
	"ld_preload",
	"certutil", "regsvr32", "rundll32", "bitsadmin", "mshta",
	"atob", "fromcharcode", "unescape",
	"dup2", "execve",
	"/dev/tcp",
	"lsass",
	"authorized_keys",
	"HIGH-enc", // malcat's own keyword from binary_rules category names packed in rodata
}

func isKeywordSoup(content string) bool {
	lower := strings.ToLower(content)
	count := 0
	for _, kw := range shortRuleKeywords {
		if strings.Contains(lower, strings.ToLower(kw)) {
			count++
			if count >= 4 {
				return true
			}
		}
	}
	return false
}

// isBareRegistryFragment returns true when the content is just a short fragment
// of a registry path (like "\SAM", "\SYSTEM") without any qualifying prefix that
// would make it a real credential access indicator. These fragments appear when
// strings(1) extracts portions of malcat's own rule regex patterns.
//
// A real SAM access requires context like HKLM\SAM, config\SAM, or a full path.
// A bare "\SAM" or "\SAm" is just a regex fragment from the rule definition itself.
func isBareRegistryFragment(content string) bool {
	lower := strings.ToLower(strings.TrimSpace(content))

	// Bare SAM/SYSTEM/SECURITY fragments without registry context
	bareFragments := []string{`\sam`, `\system`, `\security`}
	qualifiers := []string{"hklm", "hkcu", "hkey", "config", "system32", "windows", "reg "}

	for _, frag := range bareFragments {
		if strings.Contains(lower, frag) {
			// Check if it has real registry context
			for _, q := range qualifiers {
				if strings.Contains(lower, q) {
					return false // has context → real finding
				}
			}
			// No context → likely a regex fragment or path artifact
			// Only suppress if the string is short (< 40 chars) — long strings
			// with \SAM but no qualifier are still worth investigating
			if len(content) < 40 {
				return true
			}
		}
	}
	return false
}
