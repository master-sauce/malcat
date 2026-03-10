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

// extractFlag pulls -o/--output (and other known string flags) out of args
// regardless of position, returning the cleaned args and the extracted value.
func extractFlag(args []string, short, long string) (cleaned []string, value string) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		// --flag=value or -flag=value
		for _, prefix := range []string{"--" + long + "=", "-" + long + "=", "--" + short + "=", "-" + short + "="} {
			if strings.HasPrefix(arg, prefix) {
				value = strings.TrimPrefix(arg, prefix)
				goto next
			}
		}
		// --flag value or -flag value or -f value
		if arg == "--"+long || arg == "-"+long || arg == "-"+short || arg == "--"+short {
			if i+1 < len(args) {
				value = args[i+1]
				i++ // skip the value
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
	)

	// Pre-process args to extract -o/--output from any position before flag.Parse
	args, outputFile := extractFlag(os.Args[1:], "o", "output")

	flag.BoolVar(&recursive, "r", false, "Recursively scan directories")
	flag.BoolVar(&recursive, "recursive", false, "Recursively scan directories")
	flag.StringVar(&minSeverity, "severity", "low", "Minimum severity to report: low, medium, high, critical")
	flag.IntVar(&maxDepth, "depth", -1, "Max recursion depth (-1 = unlimited)")
	flag.StringVar(&extensions, "ext", "", "Comma-separated file extensions to scan (e.g. .py,.sh,.js). Empty = all")
	flag.StringVar(&extensions, "e", "", "Comma-separated file extensions to scan (shorthand)")
	flag.BoolVar(&scanBinaries, "binaries", false, "Scan binary files using strings command")
	flag.BoolVar(&scanBinaries, "bin", false, "Scan binary files using strings command (shorthand)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
malcat - Static malicious behavior analyzer

USAGE:
  malcat [flags] <file|directory> [<file|directory>...] [-o output]

FLAGS:
  -r, --recursive        Recursively scan directories
      --severity string  Minimum severity: low, medium, high, critical (default "low")
      --depth int        Max directory recursion depth, -1 = unlimited (default -1)
      --ext string       Comma-separated extensions to scan, empty = all
      --binaries, --bin  Scan binary files using strings command (default: false)
  -o, --output string    Write results to file (format inferred from extension)
                           .json  -> JSON output
                           .csv   -> CSV output
                           other  -> plain text (default: stdout)

EXAMPLES:
  malcat suspicious.sh
  malcat -r ./project
  malcat -r --severity high ./src -o report.json
  malcat -r --ext .py,.sh /opt/scripts -o results.csv
  malcat --bin suspicious.exe -o report.json
  malcat -r --bin ./mixed_directory

`)
	}

	flag.CommandLine.Parse(args)

	targets := flag.Args()
	if len(targets) == 0 {
		flag.Usage()
		return fmt.Errorf("no target files or directories specified")
	}

	cfg := analyzer.Config{
		Recursive:    recursive,
		MaxDepth:     maxDepth,
		Extensions:   extensions,
		MinSeverity:  analyzer.ParseSeverity(minSeverity),
		ScanBinaries: scanBinaries,
	}

	results, err := analyzer.Scan(targets, cfg)
	if err != nil {
		return err
	}

	format := inferFormat(outputFile)
	rep := reporter.New(format, outputFile, cfg.MinSeverity)
	return rep.Write(results)
}
