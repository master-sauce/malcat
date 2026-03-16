package analyzer

import "net"

// isPublicIPv4 returns true only for valid, publicly routable IPv4 addresses.
func isPublicIPv4(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	ip = ip.To4()
	if ip == nil {
		return false
	}
	switch {
	case ip[0] == 10: // 10.0.0.0/8
		return false
	case ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31: // 172.16.0.0/12
		return false
	case ip[0] == 192 && ip[1] == 168: // 192.168.0.0/16
		return false
	case ip[0] == 127: // 127.0.0.0/8 loopback
		return false
	case ip[0] == 169 && ip[1] == 254: // 169.254.0.0/16 link-local
		return false
	case ip[0] == 0: // 0.0.0.0/8 reserved
		return false
	case ip[0] == 100 && ip[1] >= 64 && ip[1] <= 127: // 100.64.0.0/10 shared
		return false
	case ip[0] == 192 && ip[1] == 0 && ip[2] == 2: // 192.0.2.0/24 documentation
		return false
	case ip[0] == 198 && ip[1] == 51 && ip[2] == 100: // 198.51.100.0/24 documentation
		return false
	case ip[0] == 203 && ip[1] == 0 && ip[2] == 113: // 203.0.113.0/24 documentation
		return false
	case ip[0] == 255: // broadcast
		return false
	}
	return true
}

// BinaryRules returns rules for compiled binary analysis via strings output.
func BinaryRules() []Rule {
	return []Rule{

		newRule("URL001", "URL in file", "Network", Medium,
			"URL found in file",
			`(?i)https?://[^\s/$.?#].[^\s]*`,
			"http://", "https://"),

		newRuleWithFilter("IP001", "Public IP address", "Network", Medium,
			"Hardcoded public IPv4 address — potential C2 or exfil endpoint",
			`\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`,
			isPublicIPv4),

		// ─── C2 / NETWORK ────────────────────────────────────────────────────

		newRule("BNET001", "Reverse shell string", "C2/Backdoor", Critical,
			"Reverse shell command string embedded in binary",
			`(?i)(bash\s+-i\s+>&?\s*/dev/tcp/|/bin/(ba)?sh\s+-i\s+>&|nc\s+.*-e\s+/bin/(ba)?sh)`,
			"/dev/tcp", "-e /bin"),

		newRule("BNET002", "PowerShell download cradle", "C2/Backdoor", Critical,
			"PowerShell download-and-execute cradle embedded in binary",
			`(?i)(IEX|Invoke-Expression)\s*\(?\s*(New-Object\s+Net\.WebClient|Invoke-WebRequest)`,
			"iex", "invoke-expression", "webclient"),

		newRule("BNET003", "PowerShell encoded command", "C2/Backdoor", Critical,
			"PowerShell -EncodedCommand with a payload — hidden execution",
			`(?i)powershell(\.exe)?\s+.*-enc(odedcommand)?\s+[A-Za-z0-9+/=]{40,}`,
			"-enc", "-encodedcommand"),

		newRule("BNET004", "curl/wget pipe to shell", "C2/Backdoor", Critical,
			"Shell command fetching and executing remote code",
			`(?i)(curl|wget)\s+https?://[^\s]+\s*\|\s*(ba)?sh`,
			"curl", "wget"),

		newRule("BNET005", "C2 domain/IP with port", "C2/Backdoor", High,
			"Non-local IP:port or domain:port pattern typical of C2 beacons",
			`(?i)(connect|dial|socket)\s*[\s\S]{0,60}([1-9]\d{1,2}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}|[a-z0-9-]{4,}\.[a-z]{2,}:\d{2,5})`,
			"connect", "dial"),

		newRule("BNET006", "LHOST/LPORT beacon config", "C2/Backdoor", High,
			"Metasploit-style listener config strings in binary",
			`(?i)\b(LHOST|LPORT)\s*=\s*[\d"']`,
			"lhost", "lport"),

		// ─── PERSISTENCE ─────────────────────────────────────────────────────

		newRule("BPER001", "Autorun registry write string", "Persistence", High,
			"Registry Run key path string — binary writing persistence",
			`(?i)(Software\\Microsoft\\Windows\\CurrentVersion\\Run\\|HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)`,
			"currentversion\\run"),

		newRule("BPER002", "Cron write string", "Persistence", High,
			"Cron path string with write intent in binary",
			`(?i)(echo|printf|write|fwrite)\s*[\s\S]{0,100}/etc/cron`,
			"/etc/cron"),

		newRule("BPER003", "SSH authorized_keys path", "Persistence", High,
			"authorized_keys path found — potential SSH backdoor",
			`\.ssh/authorized_keys`,
			"authorized_keys"),

		newRule("BPER004", "LD_PRELOAD injection", "Persistence", High,
			"LD_PRELOAD set to a .so file — library injection",
			`LD_PRELOAD\s*=\s*[^\s]{4,}\.so`,
			"ld_preload"),

		// ─── PROCESS INJECTION ───────────────────────────────────────────────

		newRule("BINJ001", "Process injection API combo", "Process Injection", Critical,
			"VirtualAllocEx + WriteProcessMemory or CreateRemoteThread — injection triad",
			`(?i)(VirtualAllocEx|WriteProcessMemory|CreateRemoteThread)`,
			"virtualallocex", "writeprocessmemory", "createremotethread"),

		newRule("BINJ002", "RWX shellcode allocation", "Process Injection", Critical,
			"PAGE_EXECUTE_READWRITE memory allocation — shellcode staging",
			`(?i)(PAGE_EXECUTE_READWRITE|PROT_READ\|PROT_WRITE\|PROT_EXEC|0x40)[\s\S]{0,100}(VirtualAlloc|mmap)`,
			"page_execute_readwrite", "prot_exec"),

		newRule("BINJ003", "Process hollowing strings", "Process Injection", Critical,
			"CREATE_SUSPENDED + NtUnmapViewOfSection — hollowing pair",
			`(?i)(CREATE_SUSPENDED|NtUnmapViewOfSection|ZwUnmapViewOfSection)`,
			"create_suspended", "ntunmapviewofsection", "zwunmapviewofsection"),

		// ─── EVASION ─────────────────────────────────────────────────────────

		newRule("BEVA001", "Debugger detection API", "Evasion", High,
			"IsDebuggerPresent or PEB.BeingDebugged — anti-debug",
			`(?i)(IsDebuggerPresent|CheckRemoteDebuggerPresent|PEB\.BeingDebugged|NtQueryInformationProcess)`,
			"isdebuggerpresent", "beingdebugged"),

		newRule("BEVA002", "VM artifact strings", "Evasion", High,
			"VMware/VirtualBox/QEMU string checks — sandbox evasion",
			`(?i)(vmware|vbox|virtualbox|qemu|sandboxie|cuckoo|wireshark|procmon|x64dbg|ollydbg)`,
			"vmware", "vbox", "virtualbox", "qemu", "sandboxie"),

		newRule("BEVA003", "Log wipe command", "Evasion", High,
			"Shell command clearing logs or history — covering tracks",
			`(?i)(history\s+-c|unset\s+HISTFILE|HISTSIZE=0|rm\s+-f\s+[^\s]*\.bash_history|>\s*/var/log/)`,
			"histfile", "histsize", "bash_history"),

		// ─── CREDENTIAL THEFT ────────────────────────────────────────────────

		newRule("BCRED001", "LSASS dump string", "Credential Theft", Critical,
			"LSASS dump tooling strings — credential extraction",
			`(?i)(MiniDumpWriteDump|lsass\.exe|comsvcs\.dll[\s\S]{0,50}MiniDump)`,
			"lsass", "minidumpwritedump"),

		newRule("BCRED002", "Hardcoded AWS key", "Credential Theft", Critical,
			"AWS access key ID embedded in binary",
			`AKIA[0-9A-Z]{16}`,
			"akia"),

		newRule("BCRED003", "Shadow/passwd file path", "Credential Theft", High,
			"Accessing /etc/shadow or SAM — credential file theft",
			`(?i)(/etc/shadow|/etc/passwd|\\SAM\b|\\SYSTEM\b|\\SECURITY\b)`,
			"/etc/shadow", "\\sam", "\\system"),

		// ─── LOLBin ──────────────────────────────────────────────────────────

		newRule("BLOL001", "Certutil abuse", "LOLBin", High,
			"certutil with download or decode flags — dropper pattern",
			`(?i)certutil\s+[^\n]*(-urlcache|-decode|-decodehex)`,
			"certutil"),

		newRule("BLOL002", "WMIC process create", "LOLBin", High,
			"WMIC process call create — execution bypass",
			`(?i)wmic\s+[^\n]*process\s+[^\n]*call\s+create`,
			"wmic"),

		newRule("BLOL003", "Regsvr32 scriptlet", "LOLBin", High,
			"regsvr32 /s with scrobj or remote path — AppLocker bypass",
			`(?i)regsvr32\s+[^\n]*/s\s+[^\n]*(scrobj|http|\\\\)`,
			"regsvr32"),

		// ─── DESTRUCTIVE ─────────────────────────────────────────────────────

		newRule("BDST001", "Root deletion command", "Destructive", Critical,
			"rm -rf targeting root or critical directories",
			`(?i)rm\s+-[rRf]+\s+(/\s*$|/\*|/home|/etc|/var|/usr|/boot)`,
			"rm -"),

		newRule("BDST002", "Disk wipe command", "Destructive", Critical,
			"dd writing to raw disk device — disk wipe",
			`(?i)dd\s+[^\n]*of=/dev/(sd[a-z]|nvme\d|vd[a-z])`,
			"dd ", "/dev/sd", "/dev/nvme"),

		newRule("BDST003", "Ransomware known family", "Destructive", Critical,
			"Known ransomware family name string",
			`(?i)\b(WannaCry|Petya|NotPetya|REvil|Conti|LockBit|BlackCat|Ryuk|Maze)\b`,
			"wannacry", "petya", "revil", "conti", "lockbit"),

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
