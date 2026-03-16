package analyzer

import (
	"fmt"
	"strings"

	"malcat/internal/peparser"
	"malcat/internal/x86asm"
)

// DisasmFinding holds a single disassembly-level detection.
type DisasmFinding struct {
	Section  string
	Offset   uint32 // file offset
	RVA      uint32
	Mnemonic string
	Operands string
	RuleID   string
	RuleName string
	Category string
	Severity Severity
	Details  string
}

// DisasmConfig controls the disassembly pass.
type DisasmConfig struct {
	MaxInstructions int     // max instructions per section (0 = use default)
	ROPDetection    bool    // look for gadget chains
	NOPSledMin      int     // flag NOP sleds >= this length (0 = 16)
}

const (
	defaultMaxInstr  = 5000
	defaultNOPSledMin = 16
)

// DisassembleFile disassembles all executable sections of a parsed PE.
func DisassembleFile(pe *peparser.File, cfg DisasmConfig) []DisasmFinding {
	if cfg.MaxInstructions == 0 {
		cfg.MaxInstructions = defaultMaxInstr
	}
	if cfg.NOPSledMin == 0 {
		cfg.NOPSledMin = defaultNOPSledMin
	}

	bits := 32
	if pe.Is64 {
		bits = 64
	}

	var findings []DisasmFinding
	for _, sec := range pe.Sections {
		if !sec.Executable || len(sec.Data) == 0 {
			continue
		}
		findings = append(findings, disassembleSection(sec, bits, pe.EntryPoint, cfg)...)
	}
	return findings
}

func disassembleSection(sec peparser.Section, bits int, entryRVA uint32, cfg DisasmConfig) []DisasmFinding {
	data := sec.Data
	var findings []DisasmFinding

	// Gadget tracking
	var (
		nopCount      int
		nopStart      uint32
		callRegCount  int
		lastCallRegOff uint32
		syscallCount  int
	)

	instrCount := 0
	offset := 0

	for offset < len(data) && instrCount < cfg.MaxInstructions {
		inst, err := x86asm.Decode(data[offset:], bits)
		if err != nil || inst.Len == 0 {
			// Skip one byte on decode failure (common in data interleaved with code)
			offset++
			continue
		}
		instrCount++

		rva := sec.VirtualAddress + uint32(offset)
		fileOff := sec.RawOffset + uint32(offset)
		mnemonic := inst.Op.String()
		operands := formatOperands(inst)

		// ── NOP sled detection ──
		if mnemonic == "NOP" && inst.Len == 1 {
			if nopCount == 0 {
				nopStart = fileOff
			}
			nopCount++
		} else {
			if nopCount >= cfg.NOPSledMin {
				findings = append(findings, DisasmFinding{
					Section:  sec.Name,
					Offset:   nopStart,
					RVA:      sec.VirtualAddress + (nopStart - sec.RawOffset),
					Mnemonic: "NOP (sled)",
					Operands: fmt.Sprintf("%d consecutive NOPs", nopCount),
					RuleID:   "DIS002",
					RuleName: "NOP sled",
					Category: "Shellcode",
					Severity: High,
					Details:  fmt.Sprintf("NOP sled of %d bytes — classic shellcode alignment pad", nopCount),
				})
			}
			nopCount = 0
		}

		// ── CALL/JMP through register (indirect dispatch) ──
		if cfg.ROPDetection {
			if isIndirectDispatch(mnemonic, operands) {
				if callRegCount == 0 || fileOff-lastCallRegOff < 256 {
					callRegCount++
					lastCallRegOff = fileOff
				} else {
					callRegCount = 1
					lastCallRegOff = fileOff
				}
				if callRegCount >= 3 {
					findings = append(findings, DisasmFinding{
						Section:  sec.Name,
						Offset:   fileOff,
						RVA:      rva,
						Mnemonic: mnemonic,
						Operands: operands,
						RuleID:   "DIS001",
						RuleName: "Indirect dispatch chain",
						Category: "ROP/Shellcode",
						Severity: High,
						Details:  fmt.Sprintf("%d indirect CALL/JMP through registers within 256 bytes — ROP chain or shellcode dispatcher", callRegCount),
					})
					callRegCount = 0
				}
			} else if !strings.HasPrefix(mnemonic, "NOP") {
				// Reset if too many non-indirect instructions between them
				if fileOff-lastCallRegOff > 512 {
					callRegCount = 0
				}
			}
		}

		// ── Syscall / int 0x2e (direct kernel invocation, common in shellcode) ──
		if mnemonic == "SYSCALL" || mnemonic == "SYSENTER" {
			syscallCount++
			if syscallCount >= 2 {
				findings = append(findings, DisasmFinding{
					Section:  sec.Name,
					Offset:   fileOff,
					RVA:      rva,
					Mnemonic: mnemonic,
					Operands: operands,
					RuleID:   "DIS003",
					RuleName: "Direct syscall sequence",
					Category: "Evasion",
					Severity: Critical,
					Details:  "Multiple direct syscall instructions — bypasses API hooking (Hell's Gate / Halo's Gate technique)",
				})
				syscallCount = 0
			}
		}
		if mnemonic == "INT" && operands == "0x2e" {
			findings = append(findings, DisasmFinding{
				Section:  sec.Name,
				Offset:   fileOff,
				RVA:      rva,
				Mnemonic: mnemonic,
				Operands: operands,
				RuleID:   "DIS003",
				RuleName: "int 0x2e syscall",
				Category: "Evasion",
				Severity: Critical,
				Details:  "int 0x2e is a legacy direct kernel syscall mechanism used to bypass EDR hooks",
			})
		}

		// ── CPUID (VM/sandbox detection) ──
		if mnemonic == "CPUID" {
			findings = append(findings, DisasmFinding{
				Section:  sec.Name,
				Offset:   fileOff,
				RVA:      rva,
				Mnemonic: mnemonic,
				Operands: operands,
				RuleID:   "DIS004",
				RuleName: "CPUID instruction",
				Category: "Evasion",
				Severity: Medium,
				Details:  "CPUID used to fingerprint CPU — common in VM/sandbox detection routines",
			})
		}

		// ── RDTSC (timing-based anti-debug/anti-sandbox) ──
		if mnemonic == "RDTSC" {
			findings = append(findings, DisasmFinding{
				Section:  sec.Name,
				Offset:   fileOff,
				RVA:      rva,
				Mnemonic: mnemonic,
				Operands: operands,
				RuleID:   "DIS005",
				RuleName: "RDTSC timing check",
				Category: "Evasion",
				Severity: Medium,
				Details:  "RDTSC reads CPU timestamp counter — used for timing-based anti-debug/sandbox evasion",
			})
		}

		// ── Self-referencing JMP (infinite loops / stalling) ──
		if (mnemonic == "JMP" || mnemonic == "JMP SHORT") && operands == fmt.Sprintf("0x%x", rva) {
			findings = append(findings, DisasmFinding{
				Section:  sec.Name,
				Offset:   fileOff,
				RVA:      rva,
				Mnemonic: mnemonic,
				Operands: operands,
				RuleID:   "DIS006",
				RuleName: "Infinite loop",
				Category: "Evasion",
				Severity: Low,
				Details:  "JMP to self — deliberate infinite loop, often used as sandbox stalling",
			})
		}

		// ── PEB access via FS/GS (manual PEB walk — common in shellcode) ──
		if isPEBAccess(inst) {
			findings = append(findings, DisasmFinding{
				Section:  sec.Name,
				Offset:   fileOff,
				RVA:      rva,
				Mnemonic: mnemonic,
				Operands: operands,
				RuleID:   "DIS007",
				RuleName: "PEB access via segment register",
				Category: "Evasion",
				Severity: High,
				Details:  "Accessing PEB via FS:[0x30] or GS:[0x60] — manual module enumeration, common in shellcode for API resolution without imports",
			})
		}

		offset += inst.Len
	}

	// Flush trailing NOP sled
	if nopCount >= cfg.NOPSledMin {
		findings = append(findings, DisasmFinding{
			Section:  sec.Name,
			Offset:   nopStart,
			RVA:      sec.VirtualAddress + (nopStart - sec.RawOffset),
			Mnemonic: "NOP (sled)",
			Operands: fmt.Sprintf("%d consecutive NOPs", nopCount),
			RuleID:   "DIS002",
			RuleName: "NOP sled",
			Category: "Shellcode",
			Severity: High,
			Details:  fmt.Sprintf("NOP sled of %d bytes — classic shellcode alignment pad", nopCount),
		})
	}

	return findings
}

// isIndirectDispatch returns true for CALL/JMP instructions through a register.
func isIndirectDispatch(mnemonic, operands string) bool {
	switch mnemonic {
	case "CALL", "JMP":
		// register-indirect: CALL EAX, CALL [EAX], JMP RCX, etc.
		return isRegisterOrMemReg(operands)
	}
	return false
}

var x86Registers = map[string]bool{
	"eax": true, "ebx": true, "ecx": true, "edx": true,
	"esi": true, "edi": true, "esp": true, "ebp": true,
	"rax": true, "rbx": true, "rcx": true, "rdx": true,
	"rsi": true, "rdi": true, "rsp": true, "rbp": true,
	"r8": true, "r9": true, "r10": true, "r11": true,
	"r12": true, "r13": true, "r14": true, "r15": true,
}

func isRegisterOrMemReg(op string) bool {
	op = strings.ToLower(strings.TrimSpace(op))
	// bare register
	if x86Registers[op] {
		return true
	}
	// memory indirect [reg] or [reg+offset]
	if strings.HasPrefix(op, "[") && strings.HasSuffix(op, "]") {
		inner := op[1 : len(op)-1]
		for reg := range x86Registers {
			if strings.HasPrefix(inner, reg) {
				return true
			}
		}
	}
	return false
}

// isPEBAccess detects FS:[0x30] or GS:[0x60] memory accesses.
func isPEBAccess(inst x86asm.Inst) bool {
	for _, arg := range inst.Args {
		if arg == nil {
			continue
		}
		s := strings.ToLower(fmt.Sprintf("%v", arg))
		if (strings.Contains(s, "fs") && strings.Contains(s, "0x30")) ||
			(strings.Contains(s, "gs") && strings.Contains(s, "0x60")) {
			return true
		}
	}
	return false
}

// formatOperands returns a compact string representation of instruction operands.
func formatOperands(inst x86asm.Inst) string {
	var parts []string
	for _, arg := range inst.Args {
		if arg == nil {
			break
		}
		parts = append(parts, strings.ToLower(fmt.Sprintf("%v", arg)))
	}
	return strings.Join(parts, ", ")
}
