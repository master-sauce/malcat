package cmd

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"malcat/analyzer"
	"malcat/reporter"
)

func inferFormat(outputFile string) string {
	if outputFile == "" {
		return "text"
	}
	switch strings.ToLower(filepath.Ext(outputFile)) {
	case ".json":
		return "json"
	case ".csv":
		return "csv"
	default:
		return "text"
	}
}

func extractFlag(args []string, short, long string) (cleaned []string, value string) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		for _, prefix := range []string{"--" + long + "=", "-" + long + "=", "--" + short + "=", "-" + short + "="} {
			if strings.HasPrefix(arg, prefix) {
				value = strings.TrimPrefix(arg, prefix)
				goto next
			}
		}
		if arg == "--"+long || arg == "-"+long || arg == "-"+short || arg == "--"+short {
			if i+1 < len(args) {
				value = args[i+1]
				i++
				goto next
			}
		}
		cleaned = append(cleaned, arg)
		continue
	next:
	}
	return
}

func Execute() error {
	var (
		recursive    bool
		outputFile   string
		minSeverity  string
		maxDepth     int
		extensions   string
		scanBinaries bool

		// PE flags
		parsePE          bool
		disassemble      bool
		ropDetection     bool
		disasmDepth      int
		entropyThreshold float64

		// All-in-one
		all bool

		// Extraction modes
		extractURLs bool
		extractIPs  bool
	)

	args, outputFile := extractFlag(os.Args[1:], "o", "output")

	flag.BoolVar(&recursive, "r", false, "Recursively scan directories")
	flag.BoolVar(&recursive, "recursive", false, "Recursively scan directories")
	flag.StringVar(&minSeverity, "severity", "low", "Minimum severity: low, medium, high, critical")
	flag.IntVar(&maxDepth, "depth", -1, "Max recursion depth (-1 = unlimited)")
	flag.StringVar(&extensions, "ext", "", "Comma-separated file extensions to scan (e.g. .py,.sh,.js)")
	flag.StringVar(&extensions, "e", "", "Comma-separated extensions (shorthand)")
	flag.BoolVar(&scanBinaries, "binaries", false, "Scan binary files via strings extraction")
	flag.BoolVar(&scanBinaries, "bin", false, "Scan binary files via strings extraction (shorthand)")

	// PE / disasm flags
	flag.BoolVar(&parsePE, "pe", false, "Parse PE structure: sections, imports, TLS, entropy, anomalies")
	flag.BoolVar(&disassemble, "disasm", false, "Disassemble executable PE sections (implies --pe)")
	flag.BoolVar(&ropDetection, "rop", false, "Detect ROP gadget chains in disassembly (implies --disasm)")
	flag.IntVar(&disasmDepth, "disasm-depth", 5000, "Max instructions to disassemble per section")
	flag.Float64Var(&entropyThreshold, "entropy", 7.2, "Section entropy threshold to flag as packed/encrypted (0.0-8.0)")

	// All-in-one
	flag.BoolVar(&all, "all", false, "Enable all analysis layers: --pe --disasm --rop --bin combined")

	// Extraction flags
	flag.BoolVar(&extractURLs, "urls", false, "Extract and list all URLs found (works on text files, binaries, and PE files)")
	flag.BoolVar(&extractIPs, "ips", false, "Extract and list all public IP addresses found (works on text files, binaries, and PE files)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
malcat - Static malware behavior analyzer

USAGE:
  malcat [flags] <file|directory> [<file|directory>...] [-o output]

GENERAL FLAGS:
  -r, --recursive        Recursively scan directories
      --severity string  Minimum severity: low, medium, high, critical (default "low")
      --depth int        Max recursion depth, -1 = unlimited (default -1)
  -e, --ext string       Comma-separated extensions to scan, empty = all
  -o, --output string    Output file (.json → JSON, .csv → CSV, other → text)

BINARY SCANNING:
      --bin, --binaries  String-extraction scan on binary files

PE ANALYSIS (Windows executables):
      --pe               Parse PE structure: sections, imports, exports, TLS, entropy,
                         anomalies, Rich header, overlay detection
      --disasm           Disassemble executable PE sections (implies --pe)
      --rop              Detect ROP gadget chains in disassembly (implies --disasm)
      --disasm-depth N   Max instructions per section (default 5000)
      --entropy float    Entropy threshold for packed-section detection (default 7.2)

EXTRACTION:
      --urls             Extract all URLs from the target (text, binary, or PE)
      --ips              Extract all public IP addresses from the target
                         Both flags work alongside other flags and auto-enable
                         binary/PE scanning so nothing is missed.

ALL-IN-ONE:
      --all              Enable every analysis layer simultaneously:
                           PE parsing + disassembly + ROP + binary strings
                         Equivalent to: --pe --disasm --rop --bin

EXAMPLES:
  malcat suspicious.sh
  malcat -r ./project --severity high
  malcat -r --severity high ./src -o report.json
  malcat -r --ext .py,.sh /opt/scripts -o results.csv
  malcat --bin suspicious.exe
  malcat --pe malware.exe
  malcat --pe --disasm --rop dropper.exe -o analysis.json
  malcat --pe --entropy 6.5 packed.exe
  malcat --all malware.exe -o full_report.json
  malcat -r --all ./samples -o report.csv
  malcat --urls suspicious.exe
  malcat --ips --urls ./cloned-repo -r
  malcat --ips malware.exe -o ips.json

FINDING SOURCES (shown in output):
  [text]    Line-based source code / script scan
  [strings] Strings extracted from binary (false-positive filtered)
  [pe]      PE structural analysis
  [disasm]  Disassembly-level detection

`)
	}

	flag.CommandLine.Parse(args)

	// --rop and --disasm imply --pe
	if ropDetection {
		disassemble = true
	}
	if disassemble {
		parsePE = true
	}

	targets := flag.Args()
	if len(targets) == 0 {
		flag.Usage()
		return fmt.Errorf("no target files or directories specified")
	}

	cfg := analyzer.Config{
		Recursive:        recursive,
		MaxDepth:         maxDepth,
		Extensions:       extensions,
		MinSeverity:      analyzer.ParseSeverity(minSeverity),
		ScanBinaries:     scanBinaries,
		ParsePE:          parsePE,
		Disassemble:      disassemble,
		ROPDetection:     ropDetection,
		DisasmDepth:      disasmDepth,
		EntropyThreshold: entropyThreshold,
		All:              all,
		ExtractURLs:      extractURLs,
		ExtractIPs:       extractIPs,
	}

	results, err := analyzer.Scan(targets, cfg)
	if err != nil {
		return err
	}

	format := inferFormat(outputFile)
	rep := reporter.New(format, outputFile, cfg.MinSeverity)
	return rep.Write(results)
}
