// Package peparser provides a lightweight, malware-focused PE (Portable Executable)
// parser with zero external dependencies.
package peparser

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"strings"
)

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	MagicDOS   = 0x5A4D
	MagicPE    = 0x00004550
	MagicPE32  = 0x010B
	MagicPE32P = 0x020B

	SCN_MEM_EXECUTE = 0x20000000
	SCN_MEM_READ    = 0x40000000
	SCN_MEM_WRITE   = 0x80000000

	DirExport      = 0
	DirImport      = 1
	DirSecurity    = 4
	DirTLS         = 9
)

// ─── Public types ─────────────────────────────────────────────────────────────

var MachineType = map[uint16]string{
	0x0000: "Unknown", 0x014c: "x86 (i386)", 0x8664: "x86-64 (AMD64)",
	0x01c4: "ARM (Thumb-2)", 0xaa64: "ARM64", 0x0200: "IA-64",
}

var SubsystemName = map[uint16]string{
	1: "Native", 2: "Windows GUI", 3: "Windows CUI", 5: "OS/2 CUI",
	7: "POSIX CUI", 9: "Windows CE GUI", 10: "EFI Application",
	11: "EFI Boot Driver", 12: "EFI Runtime Driver", 14: "Xbox",
	16: "Windows Boot Application",
}

type Section struct {
	Name            string
	VirtualAddress  uint32
	VirtualSize     uint32
	RawOffset       uint32
	RawSize         uint32
	Characteristics uint32
	Executable      bool
	Writable        bool
	Readable        bool
	Entropy         float64
	Data            []byte
	SuspiciousName  bool
}

func (s Section) IsWX() bool { return s.Writable && s.Executable }

type Import struct {
	DLL       string
	Function  string
	Ordinal   uint16
	ByOrdinal bool
}

type Export struct {
	Name    string
	Ordinal uint16
	RVA     uint32
}

type TLSInfo struct {
	Present       bool
	CallbackCount int
	CallbackRVAs  []uint32
}

type RichEntry struct {
	ProductID uint16
	BuildID   uint16
	Count     uint32
}

type Anomaly struct {
	Field   string
	Message string
}

type OverlayInfo struct {
	Present bool
	Offset  int64
	Size    int64
}

type File struct {
	Path               string
	Is64               bool
	Machine            string
	Subsystem          string
	TimeDateStamp      uint32
	EntryPoint         uint32
	ImageBase          uint64
	Checksum           uint32
	ComputedChecksum   uint32
	DllCharacteristics uint16

	Sections  []Section
	Imports   []Import
	Exports   []Export
	TLS       TLSInfo
	Rich      []RichEntry
	HasRich   bool
	Overlay   OverlayInfo
	Anomalies []Anomaly
	ImportSet map[string]bool // "dll::func" lowercased

	Compiler Compiler // detected toolchain
	raw     []byte
}

// ─── Known packer section names ───────────────────────────────────────────────

var packerSectionNames = map[string]bool{
	".upx0": true, ".upx1": true, ".upx2": true,
	".aspack": true, ".adata": true,
	".nsp0": true, ".nsp1": true, ".nsp2": true,
	".mpress1": true, ".mpress2": true,
	"_winzip_": true, ".themida": true, ".winlicens": true,
	".vmp0": true, ".vmp1": true, ".vmp2": true,
	".enigma1": true, ".enigma2": true,
	".petite": true, "pebundles": true,
	".perplex": true, "codewatch": true, ".obsidium": true,
}

// ─── IsPE fast check ─────────────────────────────────────────────────────────

func IsPE(data []byte) bool {
	if len(data) < 64 {
		return false
	}
	if data[0] != 0x4D || data[1] != 0x5A {
		return false
	}
	off := int(binary.LittleEndian.Uint32(data[60:]))
	return off >= 64 && off+4 <= len(data) &&
		data[off] == 0x50 && data[off+1] == 0x45 &&
		data[off+2] == 0x00 && data[off+3] == 0x00
}

// ─── Parse ────────────────────────────────────────────────────────────────────

func Parse(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseBytes(path, data)
}

func ParseBytes(path string, data []byte) (*File, error) {
	if len(data) < 64 {
		return nil, fmt.Errorf("file too small")
	}
	if data[0] != 0x4D || data[1] != 0x5A {
		return nil, fmt.Errorf("not a PE file (bad MZ magic)")
	}

	f := &File{Path: path, raw: data, ImportSet: make(map[string]bool)}

	// PE header offset
	peOff := int(binary.LittleEndian.Uint32(data[60:]))
	if peOff < 64 || peOff+24 > len(data) {
		return nil, fmt.Errorf("invalid PE header offset %d", peOff)
	}

	// Rich header (between end of DOS header stub at 64 and PE header)
	if peOff > 64 {
		f.Rich, f.HasRich = parseRichHeader(data[64:peOff])
	}

	// PE signature
	if binary.LittleEndian.Uint32(data[peOff:]) != MagicPE {
		return nil, fmt.Errorf("bad PE signature")
	}

	// ── COFF file header (20 bytes at peOff+4) ──────────────────────────────
	coffOff := peOff + 4
	if coffOff+20 > len(data) {
		return nil, fmt.Errorf("truncated COFF header")
	}
	machine := binary.LittleEndian.Uint16(data[coffOff:])
	numSections := int(binary.LittleEndian.Uint16(data[coffOff+2:]))
	f.TimeDateStamp = binary.LittleEndian.Uint32(data[coffOff+4:])
	optHdrSize := int(binary.LittleEndian.Uint16(data[coffOff+16:]))
	coffChars := binary.LittleEndian.Uint16(data[coffOff+18:])
	_ = coffChars

	f.Machine = MachineType[machine]
	if f.Machine == "" {
		f.Machine = fmt.Sprintf("Unknown(0x%04x)", machine)
	}

	// ── Optional header (at coffOff+20) ─────────────────────────────────────
	// We read fields by direct offset to avoid struct alignment surprises.
	// PE32 optional header field offsets (all from start of optional header):
	//   0:  Magic (uint16)
	//   4:  SizeOfCode (uint32)
	//  16:  AddressOfEntryPoint (uint32)
	//  20:  BaseOfCode (uint32)
	//  24:  BaseOfData (uint32)  [PE32 only]
	//  28:  ImageBase (uint32)   [PE32] / 24: ImageBase (uint64) [PE32+]
	//  32/32: SectionAlignment
	//  36/36: FileAlignment
	//  64/60: CheckSum
	//  68/64: Subsystem
	//  70/66: DllCharacteristics
	//  92/88: NumberOfRvaAndSizes
	//  96/92: DataDirectory array

	optOff := coffOff + 20
	if optOff+2 > len(data) {
		return nil, fmt.Errorf("truncated optional header")
	}
	optMagic := binary.LittleEndian.Uint16(data[optOff:])

	type dirEntry struct{ va, size uint32 }
	var dirs [16]dirEntry
	var checksumOff int // file offset of checksum field

	switch optMagic {
	case MagicPE32:
		f.Is64 = false
		if optOff+96 > len(data) {
			return nil, fmt.Errorf("truncated PE32 optional header")
		}
		f.EntryPoint = binary.LittleEndian.Uint32(data[optOff+16:])
		f.ImageBase = uint64(binary.LittleEndian.Uint32(data[optOff+28:]))
		checksumOff = optOff + 64
		f.Checksum = binary.LittleEndian.Uint32(data[optOff+64:])
		sub := binary.LittleEndian.Uint16(data[optOff+68:])
		f.DllCharacteristics = binary.LittleEndian.Uint16(data[optOff+70:])
		if name, ok := SubsystemName[sub]; ok {
			f.Subsystem = name
		} else {
			f.Subsystem = fmt.Sprintf("0x%04x", sub)
		}
		nDirs := int(binary.LittleEndian.Uint32(data[optOff+92:]))
		if nDirs > 16 {
			nDirs = 16
		}
		dirBase := optOff + 96
		for i := 0; i < nDirs && dirBase+i*8+8 <= len(data); i++ {
			dirs[i].va = binary.LittleEndian.Uint32(data[dirBase+i*8:])
			dirs[i].size = binary.LittleEndian.Uint32(data[dirBase+i*8+4:])
		}

	case MagicPE32P:
		// PE32+ optional header field offsets (verified against PE spec):
		//   16: AddressOfEntryPoint  20: BaseOfCode  24: ImageBase (uint64, 8 bytes)
		//   32: SectionAlignment     36: FileAlignment
		//   40-51: version fields    52: Win32VersionValue
		//   56: SizeOfImage          60: SizeOfHeaders
		//   64: CheckSum             68: Subsystem   70: DllCharacteristics
		//   72-103: stack/heap       104: LoaderFlags  108: NumberOfRvaAndSizes
		//  112: DataDirectory[0]
		f.Is64 = true
		if optOff+112 > len(data) {
			return nil, fmt.Errorf("truncated PE32+ optional header")
		}
		f.EntryPoint = binary.LittleEndian.Uint32(data[optOff+16:])
		f.ImageBase = binary.LittleEndian.Uint64(data[optOff+24:])
		checksumOff = optOff + 64
		f.Checksum = binary.LittleEndian.Uint32(data[optOff+64:])
		sub := binary.LittleEndian.Uint16(data[optOff+68:])
		f.DllCharacteristics = binary.LittleEndian.Uint16(data[optOff+70:])
		if name, ok := SubsystemName[sub]; ok {
			f.Subsystem = name
		} else {
			f.Subsystem = fmt.Sprintf("0x%04x", sub)
		}
		nDirs := int(binary.LittleEndian.Uint32(data[optOff+108:]))
		if nDirs > 16 {
			nDirs = 16
		}
		dirBase := optOff + 112
		for i := 0; i < nDirs && dirBase+i*8+8 <= len(data); i++ {
			dirs[i].va = binary.LittleEndian.Uint32(data[dirBase+i*8:])
			dirs[i].size = binary.LittleEndian.Uint32(data[dirBase+i*8+4:])
		}

	default:
		return nil, fmt.Errorf("unsupported optional header magic 0x%04x", optMagic)
	}

	// ── Section table ────────────────────────────────────────────────────────
	// Starts immediately after optional header
	secTableOff := optOff + optHdrSize
	for i := 0; i < numSections; i++ {
		off := secTableOff + i*40
		if off+40 > len(data) {
			break
		}
		name := strings.TrimRight(string(data[off:off+8]), "\x00")
		virtSize := binary.LittleEndian.Uint32(data[off+8:])
		virtAddr := binary.LittleEndian.Uint32(data[off+12:])
		rawSize := binary.LittleEndian.Uint32(data[off+16:])
		rawOff := binary.LittleEndian.Uint32(data[off+20:])
		chars := binary.LittleEndian.Uint32(data[off+36:])

		sec := Section{
			Name:            name,
			VirtualSize:     virtSize,
			VirtualAddress:  virtAddr,
			RawSize:         rawSize,
			RawOffset:       rawOff,
			Characteristics: chars,
			Executable:      chars&SCN_MEM_EXECUTE != 0,
			Writable:        chars&SCN_MEM_WRITE != 0,
			Readable:        chars&SCN_MEM_READ != 0,
			SuspiciousName:  packerSectionNames[strings.ToLower(name)],
		}
		end := int(rawOff) + int(rawSize)
		if rawOff > 0 && end <= len(data) {
			sec.Data = data[rawOff:end]
			sec.Entropy = shannonEntropy(sec.Data)
		}
		f.Sections = append(f.Sections, sec)
	}

	// Entry point anomaly check
	if f.EntryPoint != 0 {
		found := false
		for _, s := range f.Sections {
			if f.EntryPoint >= s.VirtualAddress && f.EntryPoint < s.VirtualAddress+s.VirtualSize {
				found = true
				if !s.Executable {
					f.Anomalies = append(f.Anomalies, Anomaly{
						Field:   "EntryPoint",
						Message: fmt.Sprintf("entry point RVA 0x%x is in non-executable section %q", f.EntryPoint, s.Name),
					})
				}
				break
			}
		}
		if !found && len(f.Sections) > 0 {
			f.Anomalies = append(f.Anomalies, Anomaly{
				Field:   "EntryPoint",
				Message: fmt.Sprintf("entry point RVA 0x%x does not fall in any section", f.EntryPoint),
			})
		}
	}

	// ── Imports ──────────────────────────────────────────────────────────────
	if dirs[DirImport].va != 0 {
		f.Imports = parseImports(data, f.Sections, dirs[DirImport].va, f.Is64)
		for _, imp := range f.Imports {
			key := strings.ToLower(imp.DLL + "::" + imp.Function)
			f.ImportSet[key] = true
		}
	}

	// ── Exports ──────────────────────────────────────────────────────────────
	if dirs[DirExport].va != 0 {
		f.Exports = parseExports(data, f.Sections, dirs[DirExport].va)
	}

	// ── TLS ──────────────────────────────────────────────────────────────────
	if dirs[DirTLS].va != 0 {
		f.TLS = parseTLS(data, f.Sections, dirs[DirTLS].va, f.Is64, f.ImageBase)
	}

	// ── Overlay ──────────────────────────────────────────────────────────────
	var lastEnd int64
	for _, s := range f.Sections {
		end := int64(s.RawOffset) + int64(s.RawSize)
		if end > lastEnd {
			lastEnd = end
		}
	}
	if lastEnd > 0 && int64(len(data)) > lastEnd {
		f.Overlay = OverlayInfo{Present: true, Offset: lastEnd, Size: int64(len(data)) - lastEnd}
	}

	// ── Checksum validation ───────────────────────────────────────────────────
	if f.Checksum != 0 {
		f.ComputedChecksum = computeChecksum(data, checksumOff)
		if f.ComputedChecksum != f.Checksum {
			f.Anomalies = append(f.Anomalies, Anomaly{
				Field:   "Checksum",
				Message: fmt.Sprintf("checksum mismatch: header=0x%08X computed=0x%08X", f.Checksum, f.ComputedChecksum),
			})
		}
	}

	// Compiler detection (done last so all sections/imports are populated)
	f.Compiler = DetectCompiler(f)
	return f, nil
}

// ─── Imports ─────────────────────────────────────────────────────────────────

func parseImports(data []byte, sections []Section, dirVA uint32, is64 bool) []Import {
	off := rvaToOffset(dirVA, sections)
	if off == 0 {
		return nil
	}

	var imports []Import
	for {
		if int(off)+20 > len(data) {
			break
		}
		// Import descriptor: OriginalFirstThunk(4) + TimeDateStamp(4) + ForwarderChain(4) + Name(4) + FirstThunk(4)
		nameRVA := binary.LittleEndian.Uint32(data[off+12:])
		firstThunk := binary.LittleEndian.Uint32(data[off+16:])
		origThunk := binary.LittleEndian.Uint32(data[off:])
		off += 20

		if nameRVA == 0 && firstThunk == 0 {
			break
		}
		dllName := readCString(data, rvaToOffset(nameRVA, sections))
		if dllName == "" {
			continue
		}

		thunkRVA := origThunk
		if thunkRVA == 0 {
			thunkRVA = firstThunk
		}
		thunkOff := rvaToOffset(thunkRVA, sections)
		if thunkOff == 0 {
			continue
		}

		for {
			var thunk uint64
			if is64 {
				if int(thunkOff)+8 > len(data) {
					break
				}
				thunk = binary.LittleEndian.Uint64(data[thunkOff:])
				thunkOff += 8
			} else {
				if int(thunkOff)+4 > len(data) {
					break
				}
				thunk = uint64(binary.LittleEndian.Uint32(data[thunkOff:]))
				thunkOff += 4
			}
			if thunk == 0 {
				break
			}

			imp := Import{DLL: dllName}
			var ordinalBit uint64
			if is64 {
				ordinalBit = uint64(1) << 63
			} else {
				ordinalBit = uint64(1) << 31
			}

			if thunk&ordinalBit != 0 {
				imp.ByOrdinal = true
				imp.Ordinal = uint16(thunk & 0xFFFF)
				imp.Function = fmt.Sprintf("Ordinal_%d", imp.Ordinal)
			} else {
				nameOff := rvaToOffset(uint32(thunk&0x7FFFFFFF), sections)
				if nameOff+2 <= uint32(len(data)) {
					imp.Ordinal = binary.LittleEndian.Uint16(data[nameOff:])
					imp.Function = readCString(data, nameOff+2)
				}
			}
			if imp.Function != "" {
				imports = append(imports, imp)
			}
		}
	}
	return imports
}

// ─── Exports ─────────────────────────────────────────────────────────────────

func parseExports(data []byte, sections []Section, dirVA uint32) []Export {
	off := rvaToOffset(dirVA, sections)
	if off == 0 || int(off)+40 > len(data) {
		return nil
	}
	// Export directory: skip Chars(4)+TS(4)+Maj(2)+Min(2)+Name(4)+Base(4) = 20
	numFuncs := binary.LittleEndian.Uint32(data[off+20:])
	numNames := binary.LittleEndian.Uint32(data[off+24:])
	addrFuncs := binary.LittleEndian.Uint32(data[off+28:])
	addrNames := binary.LittleEndian.Uint32(data[off+32:])
	addrOrds := binary.LittleEndian.Uint32(data[off+36:])
	base := binary.LittleEndian.Uint32(data[off+16:])
	_ = numFuncs

	namesOff := rvaToOffset(addrNames, sections)
	ordsOff := rvaToOffset(addrOrds, sections)
	funcsOff := rvaToOffset(addrFuncs, sections)

	var exports []Export
	for i := uint32(0); i < numNames; i++ {
		if int(namesOff)+int(i+1)*4 > len(data) {
			break
		}
		nameRVA := binary.LittleEndian.Uint32(data[namesOff+i*4:])
		nameStr := readCString(data, rvaToOffset(nameRVA, sections))
		var ord uint16
		if int(ordsOff)+int(i+1)*2 <= len(data) {
			ord = binary.LittleEndian.Uint16(data[ordsOff+i*2:])
		}
		var rva uint32
		if int(funcsOff)+int(ord+1)*4 <= len(data) {
			rva = binary.LittleEndian.Uint32(data[funcsOff+uint32(ord)*4:])
		}
		exports = append(exports, Export{Name: nameStr, Ordinal: ord + uint16(base), RVA: rva})
	}
	return exports
}

// ─── TLS ─────────────────────────────────────────────────────────────────────

func parseTLS(data []byte, sections []Section, dirVA uint32, is64 bool, imageBase uint64) TLSInfo {
	off := rvaToOffset(dirVA, sections)
	if off == 0 {
		return TLSInfo{}
	}
	tls := TLSInfo{Present: true}

	// TLS directory: StartAddressOfRawData, EndAddressOfRawData, AddressOfIndex, AddressOfCallBacks
	// All VAs (not RVAs), so 4 bytes each (PE32) or 8 bytes each (PE32+)
	var callbacksVA uint64
	if is64 {
		if int(off)+32 > len(data) {
			return tls
		}
		callbacksVA = binary.LittleEndian.Uint64(data[off+24:])
	} else {
		if int(off)+16 > len(data) {
			return tls
		}
		callbacksVA = uint64(binary.LittleEndian.Uint32(data[off+12:]))
	}

	if callbacksVA == 0 || imageBase == 0 {
		return tls
	}

	// Convert VA → RVA → file offset
	if callbacksVA < imageBase {
		return tls
	}
	callbackRVA := uint32(callbacksVA - imageBase)
	callbackFileOff := rvaToOffset(callbackRVA, sections)
	if callbackFileOff == 0 {
		return tls
	}

	step := uint32(4)
	if is64 {
		step = 8
	}
	for i := uint32(0); i < 64; i++ {
		pos := callbackFileOff + i*step
		if int(pos)+int(step) > len(data) {
			break
		}
		var cb uint64
		if is64 {
			cb = binary.LittleEndian.Uint64(data[pos:])
		} else {
			cb = uint64(binary.LittleEndian.Uint32(data[pos:]))
		}
		if cb == 0 {
			break
		}
		tls.CallbackCount++
		if cb >= imageBase {
			tls.CallbackRVAs = append(tls.CallbackRVAs, uint32(cb-imageBase))
		}
	}
	return tls
}

// ─── Rich header ─────────────────────────────────────────────────────────────

func parseRichHeader(stub []byte) ([]RichEntry, bool) {
	richIdx := bytes.Index(stub, []byte("Rich"))
	if richIdx < 4 {
		return nil, false
	}
	key := binary.LittleEndian.Uint32(stub[richIdx+4:])

	// Find "DanS" XOR'd with key
	xorDans := make([]byte, 4)
	binary.LittleEndian.PutUint32(xorDans, key^0x536E6144)
	dansIdx := bytes.Index(stub, xorDans)
	if dansIdx < 0 {
		return nil, true // Rich present but key wrong
	}

	var entries []RichEntry
	// Entries start at dansIdx+16 (skip DanS + 3 padding dwords)
	for i := dansIdx + 16; i+8 <= richIdx; i += 8 {
		raw := binary.LittleEndian.Uint32(stub[i:]) ^ key
		cnt := binary.LittleEndian.Uint32(stub[i+4:]) ^ key
		entries = append(entries, RichEntry{
			ProductID: uint16(raw >> 16),
			BuildID:   uint16(raw & 0xFFFF),
			Count:     cnt,
		})
	}
	return entries, true
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func rvaToOffset(rva uint32, sections []Section) uint32 {
	if rva == 0 {
		return 0
	}
	for _, s := range sections {
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+s.VirtualSize {
			return s.RawOffset + (rva - s.VirtualAddress)
		}
	}
	return 0
}

func readCString(data []byte, offset uint32) string {
	if offset == 0 || int(offset) >= len(data) {
		return ""
	}
	end := int(offset)
	for end < len(data) && data[end] != 0 {
		end++
		if end-int(offset) > 512 {
			break
		}
	}
	return string(data[offset:end])
}

func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	var e float64
	for _, f := range freq {
		if f > 0 {
			p := float64(f) / n
			e -= p * math.Log2(p)
		}
	}
	return e
}

// computeChecksum implements the PE checksum algorithm, zeroing the checksum
// field itself before computing.
func computeChecksum(data []byte, checksumFileOff int) uint32 {
	sum := uint32(0)
	for i := 0; i+1 < len(data); i += 2 {
		if i == checksumFileOff {
			continue // zero out checksum field
		}
		word := uint32(data[i]) | uint32(data[i+1])<<8
		sum += word
		if sum > 0xFFFF {
			sum = (sum & 0xFFFF) + (sum >> 16)
		}
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1])
	}
	sum = (sum & 0xFFFF) + (sum >> 16)
	sum += uint32(len(data))
	return sum
}
