package reporter

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"malcat/analyzer"
)

type Reporter struct {
	format      string
	outputFile  string
	minSeverity analyzer.Severity
}

func New(format, outputFile string, minSev analyzer.Severity) *Reporter {
	return &Reporter{format: format, outputFile: outputFile, minSeverity: minSev}
}

func (r *Reporter) Write(result *analyzer.ScanResult) error {
	var w io.Writer = os.Stdout
	if r.outputFile != "" {
		f, err := os.Create(r.outputFile)
		if err != nil {
			return fmt.Errorf("cannot open output file: %w", err)
		}
		defer f.Close()
		w = f
	}
	switch strings.ToLower(r.format) {
	case "json":
		return r.writeJSON(w, result)
	case "csv":
		return r.writeCSV(w, result)
	default:
		return r.writeText(w, result)
	}
}

// ──────────────── ANSI ────────────────

const (
	colorReset    = "\033[0m"
	colorRed      = "\033[31m"
	colorYellow   = "\033[33m"
	colorCyan     = "\033[36m"
	colorGray     = "\033[90m"
	colorBold     = "\033[1m"
	colorWhite    = "\033[97m"
	colorDimWhite = "\033[37m"
	colorGreen    = "\033[32m"
	colorBlue     = "\033[34m"

	bgRed     = "\033[41m"
	bgYellow  = "\033[43m"
	bgMagenta = "\033[45m"
	bgCyan    = "\033[46m"
)

func severityStyle(s analyzer.Severity) (fg, bg string) {
	switch s {
	case analyzer.Critical:
		return colorWhite, bgMagenta
	case analyzer.High:
		return colorWhite, bgRed
	case analyzer.Medium:
		return "\033[30m", bgYellow
	default:
		return "\033[30m", bgCyan
	}
}

func severityFg(s analyzer.Severity) string {
	switch s {
	case analyzer.Critical:
		return "\033[35m"
	case analyzer.High:
		return colorRed
	case analyzer.Medium:
		return colorYellow
	default:
		return colorCyan
	}
}

// sourceTag returns a short colored tag for the finding source.
func sourceTag(src analyzer.FindingSource) string {
	switch src {
	case analyzer.SourcePEStruct:
		return colorBold + colorBlue + "[pe]" + colorReset
	case analyzer.SourceDisasm:
		return colorBold + colorGreen + "[disasm]" + colorReset
	case analyzer.SourceBinaryStrings:
		return colorBold + colorYellow + "[strings]" + colorReset
	default:
		return colorGray + "[text]" + colorReset
	}
}

func truncate(s string, maxLen int) string {
	if utf8.RuneCountInString(s) <= maxLen {
		return s
	}
	runes := []rune(s)
	return string(runes[:maxLen-3]) + "..."
}

func smartTrim(content, matchText string, windowLen int) string {
	content = strings.TrimSpace(content)
	if matchText == "" || utf8.RuneCountInString(content) <= windowLen {
		return truncate(content, windowLen)
	}
	idx := strings.Index(content, matchText)
	if idx == -1 {
		return truncate(content, windowLen)
	}
	matchLen := utf8.RuneCountInString(matchText)
	runes := []rune(content)
	total := len(runes)
	half := (windowLen - matchLen) / 2
	start := idx - half
	if start < 0 {
		start = 0
	}
	end := start + windowLen
	if end > total {
		end = total
		start = end - windowLen
		if start < 0 {
			start = 0
		}
	}
	result := string(runes[start:end])
	if start > 0 {
		result = "…" + result[1:]
	}
	if end < total {
		result = result[:len([]rune(result))-1] + "…"
	}
	return result
}

func highlightMatch(content, matchText, matchColor string) string {
	if matchText == "" {
		return content
	}
	idx := strings.Index(content, matchText)
	if idx == -1 {
		return content
	}
	return content[:idx] +
		colorBold + matchColor + matchText + colorReset +
		colorDimWhite + content[idx+len(matchText):]
}

// ──────────────── TEXT ────────────────

func (r *Reporter) writeText(w io.Writer, result *analyzer.ScanResult) error {
	total := result.Stats.TotalFindings

	// Always iterate files so PE metadata is shown even for clean results.
	// The "✅ No findings" line is printed per-file (or globally if no PE info).
	hasPEFiles := false
	for _, fr := range result.Files {
		if fr.PE != nil {
			hasPEFiles = true
			break
		}
	}
	if total == 0 && !hasPEFiles {
		fmt.Fprintln(w, "✅  No findings detected.")
		printStats(w, result)
		return nil
	}

	for _, fr := range result.Files {
		if fr.Error != nil {
			fmt.Fprintf(w, "\n%s[ERROR]%s %s: %v\n", colorRed, colorReset, fr.Path, fr.Error)
			continue
		}
		if fr.Skipped {
			continue
		}

		// Always print file header — even when clean, PE info is valuable
		fmt.Fprintf(w, "\n%s╔══ %s ══%s\n", colorBold, fr.Path, colorReset)
		if fr.PE != nil {
			pe := fr.PE
			// Compiler badge: color-coded by how well we know it
			compilerColor := colorGray
			compilerLabel := pe.Compiler.String()
			switch pe.Compiler {
			case 2: // CompilerGo
				compilerColor = colorCyan
			case 3: // CompilerRust
				compilerColor = "\033[38;5;208m" // orange
			case 4: // CompilerGCC
				compilerColor = colorGreen
			case 1: // CompilerMSVC
				compilerColor = colorBlue
			case 7: // CompilerNET
				compilerColor = "\033[35m" // magenta
			}
			// Verdict: clean or N findings
			verdictStr := ""
			if len(fr.Findings) == 0 {
				verdictStr = colorGreen + colorBold + "  ✓ clean" + colorReset
			}
			fmt.Fprintf(w, "  %s%s  ·  %s  ·  %s%s%s%s  ·  EP: 0x%x  ·  %d sections  ·  %d imports%s%s\n",
				colorGray,
				pe.Machine, pe.Subsystem,
				colorBold+compilerColor, compilerLabel, colorReset,
				colorGray,
				pe.EntryPoint,
				len(pe.Sections),
				len(pe.Imports),
				colorReset,
				verdictStr,
			)
			if pe.TLS.Present {
				fmt.Fprintf(w, "  %s⚠ TLS callbacks: %d%s\n", colorYellow, pe.TLS.CallbackCount, colorReset)
			}
			if pe.Overlay.Present {
				fmt.Fprintf(w, "  %s⚠ Overlay: %.1f KB at 0x%x%s\n", colorYellow, float64(pe.Overlay.Size)/1024, pe.Overlay.Offset, colorReset)
			}
			// Section entropy table
			fmt.Fprintf(w, "  %sSections:%s", colorGray, colorReset)
			for _, s := range pe.Sections {
				entropyColor := colorGray
				if s.Entropy >= 7.2 {
					entropyColor = colorRed
				} else if s.Entropy >= 6.5 {
					entropyColor = colorYellow
				}
				flags := ""
				if s.Executable {
					flags += "X"
				}
				if s.Writable {
					flags += "W"
				}
				if s.Readable {
					flags += "R"
				}
				fmt.Fprintf(w, "  %s%s%s(%s)%sH=%.2f%s",
					colorBold, s.Name, colorReset,
					flags,
					entropyColor, s.Entropy, colorReset,
				)
			}
			fmt.Fprintln(w)
		}

		if len(fr.Findings) == 0 {
			fmt.Fprintf(w, "%s╚%s%s\n", colorGray, strings.Repeat("═", 69), colorReset)
			continue
		}
		for i, f := range fr.Findings {
			fg, bg := severityStyle(f.Severity)
			accentColor := severityFg(f.Severity)

			// Severity badge + source tag + rule name
			fmt.Fprintf(w, "%s %s%s %s %s  %s%s%s%s",
				colorBold+bg+fg,
				f.Severity,
				colorReset,
				sourceTag(f.Source),
				colorBold+accentColor+f.RuleName+colorReset,
				colorGray,
				locationStr(f),
				colorReset,
				"\n",
			)

			fmt.Fprintf(w, "  %s%s  ·  %s%s\n",
				colorGray, f.Category, f.RuleID, colorReset,
			)
			fmt.Fprintf(w, "  %s%s%s\n", colorGray, f.Details, colorReset)

			// Content line (text/strings) or context (PE/disasm)
			if f.Content != "" {
				trimmed := smartTrim(f.Content, f.MatchText, 120)
				highlighted := highlightMatch(trimmed, f.MatchText, accentColor)
				fmt.Fprintf(w, "  %s›%s %s%s%s\n",
					accentColor, colorReset, colorDimWhite, highlighted, colorReset)
			} else if f.Context != "" {
				fmt.Fprintf(w, "  %s›%s %s%s%s\n",
					accentColor, colorReset, colorDimWhite, f.Context, colorReset)
			}

			if i < len(fr.Findings)-1 {
				fmt.Fprintf(w, "  %s%s%s\n", colorGray, strings.Repeat("·", 60), colorReset)
			}
		}

		fmt.Fprintf(w, "%s╚%s%s\n", colorGray, strings.Repeat("═", 69), colorReset)
	}

	printStats(w, result)
	return nil
}

// locationStr formats the location part of a finding header.
func locationStr(f analyzer.Finding) string {
	switch f.Source {
	case analyzer.SourcePEStruct:
		if f.Context != "" {
			return fmt.Sprintf("  ctx=%s", f.Context)
		}
		return ""
	case analyzer.SourceDisasm:
		return fmt.Sprintf("  RVA=0x%x  sect=%s", f.RVA, f.Context)
	default:
		if f.Line > 0 {
			return fmt.Sprintf("  L%d", f.Line)
		}
		return ""
	}
}

func printStats(w io.Writer, result *analyzer.ScanResult) {
	s := result.Stats
	fmt.Fprintf(w, "\n%s── Scan Summary ──%s\n", colorBold, colorReset)
	fmt.Fprintf(w, "  Files scanned : %d\n", s.FilesScanned)
	fmt.Fprintf(w, "  Files skipped : %d\n", s.FilesSkipped)
	fmt.Fprintf(w, "  Errors        : %d\n", s.FilesErrored)
	fmt.Fprintf(w, "  Total findings: %d\n", s.TotalFindings)
	if s.SuppressedFindings > 0 {
		fmt.Fprintf(w, "  FP suppressed  : %s%d%s\n", colorGray, s.SuppressedFindings, colorReset)
	}

	if s.TotalFindings > 0 {
		fmt.Fprintf(w, "  By severity   :")
		for _, sev := range []struct {
			key   string
			color string
		}{
			{"CRITICAL", "\033[35m"},
			{"HIGH", colorRed},
			{"MEDIUM", colorYellow},
			{"LOW", colorCyan},
		} {
			if s.BySeverity[sev.key] > 0 {
				fmt.Fprintf(w, "  %s%s%s=%d%s", colorBold, sev.color, sev.key, s.BySeverity[sev.key], colorReset)
			}
		}
		fmt.Fprintln(w)

		// Source breakdown
		fmt.Fprintf(w, "  By source     :")
		for _, src := range []string{"pe", "disasm", "strings", "text"} {
			if s.BySource[src] > 0 {
				fmt.Fprintf(w, "  %s=%d", src, s.BySource[src])
			}
		}
		fmt.Fprintln(w)
	}
}

// ──────────────── JSON ────────────────

type jsonOutput struct {
	Stats    analyzer.Stats `json:"stats"`
	Findings []jsonFinding  `json:"findings"`
	Errors   []jsonError    `json:"errors,omitempty"`
}

type jsonFinding struct {
	File      string `json:"file"`
	Line      int    `json:"line,omitempty"`
	Column    int    `json:"column,omitempty"`
	RVA       string `json:"rva,omitempty"`
	Severity  string `json:"severity"`
	RuleID    string `json:"rule_id"`
	RuleName  string `json:"rule_name"`
	Category  string `json:"category"`
	Details   string `json:"details"`
	Content   string `json:"content,omitempty"`
	MatchText string `json:"match_text,omitempty"`
	Context   string `json:"context,omitempty"`
	Source    string `json:"source"`
}

type jsonError struct {
	File  string `json:"file"`
	Error string `json:"error"`
}

func (r *Reporter) writeJSON(w io.Writer, result *analyzer.ScanResult) error {
	out := jsonOutput{Stats: result.Stats}

	for _, fr := range result.Files {
		if fr.Error != nil {
			out.Errors = append(out.Errors, jsonError{File: fr.Path, Error: fr.Error.Error()})
			continue
		}
		for _, f := range fr.Findings {
			jf := jsonFinding{
				File:      f.File,
				Line:      f.Line,
				Column:    f.Column,
				Severity:  f.Severity.String(),
				RuleID:    f.RuleID,
				RuleName:  f.RuleName,
				Category:  f.Category,
				Details:   f.Details,
				Content:   f.Content,
				MatchText: f.MatchText,
				Context:   f.Context,
				Source:    f.Source.String(),
			}
			if f.RVA != 0 {
				jf.RVA = fmt.Sprintf("0x%x", f.RVA)
			}
			out.Findings = append(out.Findings, jf)
		}
	}

	sort.Slice(out.Findings, func(i, j int) bool {
		si := analyzer.ParseSeverity(out.Findings[i].Severity)
		sj := analyzer.ParseSeverity(out.Findings[j].Severity)
		return si > sj
	})

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// ──────────────── CSV ────────────────

func (r *Reporter) writeCSV(w io.Writer, result *analyzer.ScanResult) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	_ = cw.Write([]string{
		"file", "line", "column", "rva", "severity", "source",
		"rule_id", "rule_name", "category", "details", "content", "match_text", "context",
	})

	for _, fr := range result.Files {
		if fr.Skipped || fr.Error != nil {
			continue
		}
		for _, f := range fr.Findings {
			rvaStr := ""
			if f.RVA != 0 {
				rvaStr = fmt.Sprintf("0x%x", f.RVA)
			}
			lineStr := ""
			if f.Line > 0 {
				lineStr = fmt.Sprintf("%d", f.Line)
			}
			colStr := ""
			if f.Column > 0 {
				colStr = fmt.Sprintf("%d", f.Column)
			}
			_ = cw.Write([]string{
				f.File,
				lineStr,
				colStr,
				rvaStr,
				f.Severity.String(),
				f.Source.String(),
				f.RuleID,
				f.RuleName,
				f.Category,
				f.Details,
				f.Content,
				f.MatchText,
				f.Context,
			})
		}
	}
	return cw.Error()
}
