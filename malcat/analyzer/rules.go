package analyzer

import (
	"regexp"
	"strings"
)

// Rule defines a single detection pattern
type Rule struct {
	ID       string
	Name     string
	Category string
	Severity Severity
	Details  string
	pattern  *regexp.Regexp
	keywords []string
	filter   func(matched string) bool // optional post-match veto
}

// Match returns (column, matchedText, matched) for a line
func (r Rule) Match(line string) (int, string, bool) {
	lower := strings.ToLower(line)

	if len(r.keywords) > 0 {
		found := false
		for _, kw := range r.keywords {
			if strings.Contains(lower, kw) {
				found = true
				break
			}
		}
		if !found {
			return 0, "", false
		}
	}

	if r.pattern != nil {
		loc := r.pattern.FindStringIndex(line)
		if loc == nil {
			return 0, "", false
		}
		matched := line[loc[0]:loc[1]]
		if r.filter != nil && !r.filter(matched) {
			return 0, "", false
		}
		return loc[0] + 1, matched, true
	}

	return 0, "", false
}

func newRule(id, name, category string, sev Severity, details, pattern string, keywords ...string) Rule {
	var re *regexp.Regexp
	if pattern != "" {
		re = regexp.MustCompile(pattern)
	}
	return Rule{
		ID:       id,
		Name:     name,
		Category: category,
		Severity: sev,
		Details:  details,
		pattern:  re,
		keywords: keywords,
	}
}

func newRuleWithFilter(id, name, category string, sev Severity, details, pattern string, filter func(string) bool, keywords ...string) Rule {
	r := newRule(id, name, category, sev, details, pattern, keywords...)
	r.filter = filter
	return r
}

func DefaultRules() []Rule {
	return baseRules()
}

func DefaultBinaryRules() []Rule {
	return BinaryRules()
}

// baseRules — focused on real malware behaviour in source code.
// Philosophy: only fire when the pattern is very specific to malicious intent,
// not general programming constructs. Every rule here should be nearly
// impossible to trigger from normal open-source code accidentally.
func baseRules() []Rule {
	return []Rule{

		newRule("URL001", "URL in file", "Network", Medium,
			"URL found in file",
			`(?i)https?://[^\s/$.?#].[^\s]*`,
			"http://", "https://"),

		newRuleWithFilter("IP001", "Public IP address", "Network", Medium,
			"Hardcoded public IPv4 address — potential C2 or exfil endpoint",
			`\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`,
			isPublicIPv4),

		// ─── C2 / NETWORK BACKDOOR ───────────────────────────────────────────
		// These require very specific combinations that legitimate code won't have.

		newRule("NET001", "Bash reverse shell", "C2/Backdoor", Critical,
			"Classic reverse shell redirecting bash stdio to a TCP socket",
			`bash\s+-i\s+>&?\s*/dev/tcp/[0-9a-zA-Z._-]+/\d+`,
			"/dev/tcp"),

		newRule("NET002", "Netcat reverse/bind shell", "C2/Backdoor", Critical,
			"Netcat spawning a shell — classic backdoor pattern",
			`(?i)\bnc(at)?\b.*(-e|-c)\s+(/bin/(ba)?sh|cmd(\.exe)?)`,
			"-e", "-c"),

		newRule("NET003", "Python socket reverse shell", "C2/Backdoor", Critical,
			"Python socket connected then stdio duplicated to it — reverse shell",
			`(?i)socket\.connect\s*\(.*\)[\s\S]{0,200}os\.(dup2|execve|system)`,
			"socket.connect", "dup2", "execve"),

		newRule("NET004", "curl/wget pipe to shell", "C2/Backdoor", Critical,
			"Fetching remote content and piping directly into a shell",
			`(?i)(curl|wget)\s+[^|#\n]+\|\s*(?:sudo\s+)?(ba)?sh`,
			"curl", "wget"),

		newRule("NET005", "PowerShell download cradle", "C2/Backdoor", Critical,
			"PowerShell downloading and immediately executing remote content",
			`(?i)(IEX|Invoke-Expression)\s*[\(\s]\s*(New-Object\s+Net\.WebClient|Invoke-WebRequest|\[Net\.WebClient\])`,
			"iex", "invoke-expression", "invoke-webrequest", "webclient"),

		newRule("NET006", "PowerShell encoded payload", "C2/Backdoor", Critical,
			"-EncodedCommand used to hide a PowerShell payload",
			`(?i)powershell(\.exe)?\s+.*(-enc\s+|-encodedcommand\s+)[A-Za-z0-9+/=]{30,}`,
			"-enc", "-encodedcommand"),

		newRule("NET007", "Hardcoded C2 beacon interval", "C2/Backdoor", High,
			"Beacon/sleep loop with hardcoded interval contacting a remote host — C2 pattern",
			`(?i)(sleep|time\.sleep|Thread\.sleep|setTimeout)\s*\(\s*\d+\s*\)[\s\S]{0,300}(http|socket|connect|send|recv|request)`,
			"sleep"),

		newRule("NET008", "Raw socket shell spawn", "C2/Backdoor", Critical,
			"Raw socket created then shell spawned — bind/reverse shell pattern",
			`(?i)(socket\.socket|net\.Listen|net\.Dial)[\s\S]{0,400}(exec\.Command|os\.exec|subprocess|/bin/sh|cmd\.exe)`,
			"socket", "listen", "dial"),

		newRule("NET009", "DNS tunneling", "C2/Backdoor", High,
			"Data exfiltration or C2 via DNS queries",
			`(?i)(nslookup|dig|host)\s+[^;\n]*\$[\w{(]`,
			"nslookup", "dig"),

		newRule("NET010", "LHOST/LPORT C2 variable", "C2/Backdoor", High,
			"Metasploit-style LHOST/LPORT variables — generated payload indicator",
			`(?i)\b(LHOST|LPORT|RHOST|RPORT)\s*[:=]\s*["\d]`,
			"lhost", "lport", "rhost", "rport"),

		// ─── PERSISTENCE ─────────────────────────────────────────────────────
		// Only fire on very specific persistence write patterns, not reads.

		newRule("PER001", "Cron persistence write", "Persistence", High,
			"Writing to cron via echo or tee — backdoor persistence",
			`(?i)(echo|printf)\s+[^;\n]*>>\s*/etc/cron(tab|\.d/[^;\n]+)`,
			"crontab", "/etc/cron"),

		newRule("PER002", "Systemd service install", "Persistence", High,
			"Dropping a systemd unit file programmatically for persistence",
			`(?i)(echo|printf|cat|tee)\s+[^;\n]*>\s*/etc/systemd/system/[^;\n]+\.service`,
			"systemd", ".service"),

		newRule("PER003", "Windows Run key write", "Persistence", High,
			"Writing to Windows autorun registry key for persistence",
			`(?i)(RegSetValueEx|reg\s+add)\s*[^;\n]*(CurrentVersion\\Run\b)`,
			"currentversion\\run", "regsetvalueex"),

		newRule("PER004", "Windows scheduled task creation", "Persistence", High,
			"Creating a scheduled task via schtasks for persistence",
			`(?i)schtasks\s+/create\s+[^;\n]*(cmd|powershell|wscript|cscript)`,
			"schtasks", "/create"),

		newRule("PER005", "SSH authorized_keys write", "Persistence", High,
			"Appending to authorized_keys — backdoor SSH access",
			`(?i)(echo|cat|tee)\s+[^;\n]*>>\s*[~\w/]*\.ssh/authorized_keys`,
			"authorized_keys"),

		newRule("PER006", "LD_PRELOAD hijack", "Persistence", High,
			"LD_PRELOAD set to inject a shared library into all processes",
			`(?i)(export\s+)?LD_PRELOAD\s*=\s*[^\s#;]+\.so`,
			"ld_preload"),

		// ─── EVASION ─────────────────────────────────────────────────────────
		// Only very explicit evasion — not generic use of these APIs.

		newRule("EVA001", "Debugger detection", "Evasion", High,
			"Explicitly checking for a debugger to alter execution",
			`(?i)(IsDebuggerPresent\s*\(\s*\)|CheckRemoteDebuggerPresent\s*\(|PEB\.BeingDebugged|ptrace\s*\(\s*PTRACE_TRACEME)`,
			"isdebuggerpresent", "beingdebugged", "ptrace_traceme"),

		newRule("EVA002", "Sandbox/VM detection", "Evasion", High,
			"Checking for sandbox or VM artifacts to evade analysis",
			`(?i)(Win32_ComputerSystem[\s\S]{0,100}(vmware|virtualbox|qemu|xen)|CPUID[\s\S]{0,50}hypervisor|registry.*HKLM.*vmware)`,
			"vmware", "virtualbox", "qemu", "hypervisor"),

		newRule("EVA003", "Process name self-check", "Evasion", Medium,
			"Malware checking its own process name to detect analysis tools",
			`(?i)(GetModuleFileName|argv\[0\]|process\.argv|sys\.argv\[0\])[\s\S]{0,100}(wireshark|procmon|fiddler|ollydbg|x64dbg|processhacker)`,
			"wireshark", "procmon", "fiddler", "ollydbg"),

		newRule("EVA004", "Anti-analysis sleep loop", "Evasion", Medium,
			"Long sleep used to delay execution past sandbox timeout",
			`(?i)(time\.sleep|Sleep|Thread\.sleep)\s*\(\s*[6-9]\d{4,}|[1-9]\d{5,}\s*\)`,
			"sleep"),

		newRule("EVA005", "Log/history tampering", "Evasion", High,
			"Clearing shell history or system logs to cover tracks",
			`(?i)(history\s+-c|>\s*/var/log/\w+\.log|unset\s+HISTFILE|HISTSIZE\s*=\s*0|rm\s+-f\s+[~\w/]*\.bash_history)`,
			"histfile", "histsize", "bash_history", "history -c"),

		// ─── PROCESS INJECTION ───────────────────────────────────────────────
		// Only combinations that indicate injection, not single API calls.

		newRule("INJ001", "Classic process injection sequence", "Process Injection", Critical,
			"OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread sequence",
			`(?i)(OpenProcess|VirtualAllocEx|WriteProcessMemory|CreateRemoteThread)`,
			"openprocess", "virtualallocex", "writeprocessmemory", "createremotethread"),

		newRule("INJ002", "Process hollowing", "Process Injection", Critical,
			"Creating a suspended process and replacing its image",
			`(?i)(CREATE_SUSPENDED|0x00000004)[\s\S]{0,300}(NtUnmapViewOfSection|ZwUnmapViewOfSection)`,
			"create_suspended", "ntunmapviewofsection", "zwunmapviewofsection"),

		newRule("INJ003", "Shellcode allocation RWX", "Process Injection", Critical,
			"Allocating RWX memory — classic shellcode staging",
			`(?i)(VirtualAlloc|mmap)\s*\([^)]{0,200}(PAGE_EXECUTE_READWRITE|PROT_READ\s*\|\s*PROT_WRITE\s*\|\s*PROT_EXEC|0x40\b)`,
			"page_execute_readwrite", "prot_exec", "virtualalloc"),

		// ─── CREDENTIAL THEFT ────────────────────────────────────────────────

		newRule("CRED001", "Credential file access", "Credential Theft", High,
			"Reading sensitive credential files",
			`(?i)(open|read|cat|get-content)\s+[^;\n]*(\/etc\/shadow|\/etc\/passwd|\.aws\/credentials|id_rsa\b|\.ssh\/[^;\n]*key)`,
			"/etc/shadow", "id_rsa", ".aws/credentials"),

		newRule("CRED002", "LSASS memory dump", "Credential Theft", Critical,
			"Dumping LSASS process memory — credential extraction",
			`(?i)(MiniDumpWriteDump[\s\S]{0,100}lsass|procdump[\s\S]{0,50}-ma[\s\S]{0,50}lsass|comsvcs[\s\S]{0,50}MiniDump)`,
			"lsass", "minidumpwritedump", "procdump"),

		newRule("CRED003", "Hardcoded AWS key", "Credential Theft", Critical,
			"AWS access key ID hardcoded in source",
			`AKIA[0-9A-Z]{16}`,
			"akia"),

		newRule("CRED004", "Hardcoded secret assignment", "Credential Theft", High,
			"Secret, password, or token hardcoded as a non-empty string literal",
			`(?i)(password|passwd|secret|api_key|apikey|auth_token)\s*[:=]\s*["'][^"'\s]{8,}["']`,
			"password", "passwd", "secret", "api_key", "auth_token"),

		// ─── DESTRUCTIVE ─────────────────────────────────────────────────────

		newRule("DST001", "Recursive root deletion", "Destructive", Critical,
			"Deleting root or critical system directories recursively",
			`(?i)rm\s+(-[rRf]+\s+){0,3}(/\s*$|/\*\s*$|/home\s|/etc\s|/var\s|/usr\s|/boot\s)`,
			"rm "),

		newRule("DST002", "Disk wipe", "Destructive", Critical,
			"Writing zeros/random data directly to a disk device",
			`(?i)dd\s+[^;\n]*of=/dev/(sd[a-z]|nvme\d|vd[a-z]|hd[a-z])\b`,
			"dd ", "/dev/sd", "/dev/nvme"),

		newRule("DST003", "Fork bomb", "Destructive", Critical,
			"Classic fork bomb that exhausts process table",
			`:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:`,
			":(){ :|:&};:"),

		newRule("DST004", "Ransomware file loop", "Destructive", Critical,
			"Encrypting files in a loop — ransomware pattern",
			`(?i)(for|foreach|find)\s+[^;\n]*(encrypt|openssl\s+enc|AES)[^;\n]*(\.jpg|\.doc|\.pdf|\*\.\*)`,
			"encrypt", "openssl enc"),

		// ─── LOLBin ABUSE ────────────────────────────────────────────────────
		// Living-off-the-land binaries used to proxy malicious execution.

		newRule("LOL001", "Certutil decode/download", "LOLBin", High,
			"certutil used to download or decode files — common malware dropper",
			`(?i)certutil\s+[^;\n]*(-urlcache|-decode|-encode|-decodehex)`,
			"certutil"),

		newRule("LOL002", "Regsvr32 scriptlet", "LOLBin", High,
			"regsvr32 loading a remote scriptlet — AppLocker bypass",
			`(?i)regsvr32\s+[^;\n]*/s\s+[^;\n]*(scrobj|http|\\\\)`,
			"regsvr32"),

		newRule("LOL003", "Rundll32 remote", "LOLBin", High,
			"rundll32 loading from a UNC path or URL — execution bypass",
			`(?i)rundll32\s+[^;\n]*(\\\\[^;\n]+\.dll|javascript:|shell32\.dll,ShellExec)`,
			"rundll32"),

		newRule("LOL004", "MSHTA remote execution", "LOLBin", High,
			"mshta loading remote HTA or JavaScript — execution bypass",
			`(?i)mshta\s+[^;\n]*(https?://|javascript:|vbscript:)`,
			"mshta"),

		newRule("LOL005", "WMIC process create", "LOLBin", High,
			"WMIC used to create a process — execution bypass",
			`(?i)wmic\s+[^;\n]*process\s+[^;\n]*call\s+create`,
			"wmic", "process", "create"),

		newRule("LOL006", "Bitsadmin download", "LOLBin", High,
			"bitsadmin used to download files — common malware dropper",
			`(?i)bitsadmin\s+[^;\n]*/transfer\s+[^;\n]*(http|ftp)`,
			"bitsadmin", "/transfer"),

		// ─── OBFUSCATION ─────────────────────────────────────────────────────
		// Only flag obfuscation when combined with execution, not standalone encoding.

		newRule("OBF001", "Base64 decode then execute", "Obfuscation", High,
			"Decoding base64 and immediately executing the result",
			`(?i)(base64\s+-d|atob|FromBase64String|b64decode)\s*[\s\S]{0,100}(exec|eval|invoke|system|subprocess|os\.system)`,
			"base64", "atob", "frombase64string"),

		newRule("OBF002", "Char-code string construction", "Obfuscation", High,
			"Building strings from character codes — evades string-based detection",
			`(?i)(String\.fromCharCode|chr\s*\(\s*\d+\s*\)(\s*[+.]\s*chr\s*\(\s*\d+\s*\)){4,}|\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){7,})`,
			"fromcharcode", "chr("),

		newRule("OBF003", "Eval of encoded/obfuscated string", "Obfuscation", High,
			"eval() wrapping an encoded or constructed string — common JS malware pattern",
			`(?i)\beval\s*\(\s*(atob|unescape|decodeURIComponent|String\.fromCharCode|base64_decode)\s*\(`,
			"eval", "atob", "unescape", "fromcharcode"),

		// ─── RUNTIME DECRYPTION ─────────────────────────────────────────────────────
		// Detects patterns of runtime decryption commonly used by malware to hide
		// malicious payloads that are decoded in memory before execution.

		newRule("DEC001", "XOR decryption loop", "Runtime Decryption", High,
			"XOR-based decryption loop with hardcoded key - common malware obfuscation",
			`(?i)(for|while)[\s\S]{0,200}(xor|\^)[\s\S]{0,200}(data|buffer|payload|shellcode)[\s\S]{0,200}(key|cipher)[\s\S]{0,200}[$$$$]`,
			"xor", "key", "decrypt"),

		newRule("DEC002", "AES decryption with hardcoded key", "Runtime Decryption", High,
			"AES decryption with hardcoded key - suspicious if combined with immediate execution",
			`(?i)(AES|aes_decrypt|aes128|aes256|CryptDecrypt)[\s\S]{0,300}(key|password|secret)\s*[:=]\s*["'][^"'\s]{16,}["'][\s\S]{0,200}(exec|eval|invoke|CreateThread|VirtualProtect)`,
			"aes", "decrypt", "key"),

		newRule("DEC003", "RC4 decryption with execution", "Runtime Decryption", High,
			"RC4 decryption followed by immediate execution - common malware pattern",
			`(?i)(rc4|ARC4)[\s\S]{0,200}(key|password)[\s\S]{0,200}(exec|eval|invoke|CreateThread|VirtualProtect|memcpy)`,
			"rc4", "decrypt", "key"),

		newRule("DEC004", "Base64 decode to executable memory", "Runtime Decryption", Medium,
			"Base64 decoding to executable memory region - potential shellcode loader",
			`(?i)(base64_decode|atob|FromBase64String|b64decode)[\s\S]{0,200}(VirtualAlloc|VirtualProtect|malloc|mmap)[\s\S]{0,200}(PAGE_EXECUTE_READWRITE|PROT_EXEC|0x40)`,
			"base64", "virtualalloc", "execute"),

		newRule("DEC005", "Custom decryption function", "Runtime Decryption", High,
			"Custom decryption function with hardcoded keys and immediate execution",
			`(?i)(decrypt|decode|deobfuscate)[\s\S]{0,300}(key|secret|password)\s*[:=]\s*["'][^"'\s]{8,}["'][\s\S]{0,300}(exec|eval|invoke|CreateThread|VirtualProtect)`,
			"decrypt", "key", "exec"),

		newRule("DEC006", "Multi-stage decryption", "Runtime Decryption", High,
			"Multiple decryption layers - common in sophisticated malware",
			`(?i)(decrypt|decode)[\s\S]{0,200}(decrypt|decode)[\s\S]{0,200}(exec|eval|invoke|CreateThread|VirtualProtect)`,
			"decrypt", "decode", "exec"),

		newRule("DEC007", "Shellcode XOR with single-byte key", "Runtime Decryption", High,
			"Shellcode XOR decryption with single-byte key - classic malware pattern",
			`(?i)(for|while)[\s\S]{0,200}(byte|uint8|char)[\s\S]{0,200}(xor|\^)\s*0x[0-9a-f]{2}[\s\S]{0,200}(shellcode|payload|buffer)[\s\S]{0,200}(jmp|call|ret)`,
			"xor", "shellcode", "0x"),

		newRule("DEC008", "Dynamic API resolution after decryption", "Runtime Decryption", Critical,
			"Decrypting API function names and resolving them dynamically - common evasion",
			`(?i)(decrypt|decode)[\s\S]{0,200}(GetProcAddress|GetModuleHandle|dlsym)[\s\S]{0,200}(LoadLibrary|dlopen)`,
			"decrypt", "getprocaddress", "loadlibrary"),

		newRule("DEC009", "Encrypted payload in resources", "Runtime Decryption", High,
			"Extracting and decrypting payload from embedded resources",
			`(?i)(FindResource|LoadResource|LockResource)[\s\S]{0,300}(decrypt|decode|aes|des|rc4|xor)[\s\S]{0,200}(VirtualProtect|CreateThread|exec)`,
			"resource", "decrypt", "execute"),

		newRule("DEC010", "Polymorphic decryption routine", "Runtime Decryption", Critical,
			"Self-modifying decryption routine - highly indicative of malware",
			`(?i)(VirtualProtect|PAGE_EXECUTE_READWRITE|PROT_EXEC)[\s\S]{0,200}(memcpy|memset|xor)[\s\S]{0,200}(decrypt|decode)[\s\S]{0,200}(jmp|call|ret)`,
			"virtualprotect", "decrypt", "self-modifying"),
	}
}
