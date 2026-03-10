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

// Reporter writes scan results in a given format
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

// ──────────────── TEXT ────────────────

const (
	colorReset    = "\033[0m"
	colorRed      = "\033[31m"
	colorYellow   = "\033[33m"
	colorCyan     = "\033[36m"
	colorGray     = "\033[90m"
	colorBold     = "\033[1m"
	colorWhite    = "\033[97m"
	colorDimWhite = "\033[37m"

	// Background colors for severity badge
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
		return "\033[30m", bgYellow // black text on yellow
	default:
		return "\033[30m", bgCyan // black text on cyan
	}
}

func severityFg(s analyzer.Severity) string {
	switch s {
	case analyzer.Critical:
		return "\033[35m" // magenta
	case analyzer.High:
		return colorRed
	case analyzer.Medium:
		return colorYellow
	default:
		return colorCyan
	}
}

// truncate shortens a string to maxLen runes, appending "..." if cut
func truncate(s string, maxLen int) string {
	if utf8.RuneCountInString(s) <= maxLen {
		return s
	}
	runes := []rune(s)
	return string(runes[:maxLen-3]) + "..."
}

// smartTrim finds the match inside content and returns a window around it
// so the matched part is visible and centred rather than buried in a blob.
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

	// Try to centre the match in the window
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

// highlightMatch wraps the matched portion of content with color
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

func (r *Reporter) writeText(w io.Writer, result *analyzer.ScanResult) error {
	total := result.Stats.TotalFindings
	if total == 0 {
		fmt.Fprintln(w, "✅  No findings detected.")
		printStats(w, result)
		return nil
	}

	for _, fr := range result.Files {
		if fr.Error != nil {
			fmt.Fprintf(w, "\n%s[ERROR]%s %s: %v\n", colorRed, colorReset, fr.Path, fr.Error)
			continue
		}
		if fr.Skipped || len(fr.Findings) == 0 {
			continue
		}

		// File header
		fmt.Fprintf(w, "\n%s╔══ %s ══%s\n", colorBold, fr.Path, colorReset)

		for i, f := range fr.Findings {
			fg, bg := severityStyle(f.Severity)
			accentColor := severityFg(f.Severity)

			// Severity badge + rule name
			fmt.Fprintf(w, "%s %s%s %s %s%s%s  %sL%d%s\n",
				colorBold+bg+fg,
				f.Severity,
				colorReset,
				colorBold+accentColor, f.RuleName, colorReset,
				colorGray,
				colorGray, f.Line, colorReset,
			)

			// Category and rule ID on one line, dimmed
			fmt.Fprintf(w, "  %s%s  ·  %s%s\n",
				colorGray, f.Category,
				f.RuleID, colorReset,
			)

			// Details
			fmt.Fprintf(w, "  %s%s%s\n", colorGray, f.Details, colorReset)

			// Matched content — trimmed to a readable window centred on the match
			trimmed := smartTrim(f.Content, f.MatchText, 120)
			highlighted := highlightMatch(trimmed, f.MatchText, accentColor)
			fmt.Fprintf(w, "  %s›%s %s%s%s\n",
				accentColor, colorReset,
				colorDimWhite, highlighted, colorReset,
			)

			// Separator between findings, but not after the last one
			if i < len(fr.Findings)-1 {
				fmt.Fprintf(w, "  %s%s%s\n", colorGray, strings.Repeat("·", 60), colorReset)
			}
		}

		fmt.Fprintf(w, "%s╚%s%s\n", colorGray, strings.Repeat("═", 69), colorReset)
	}

	printStats(w, result)
	return nil
}

func printStats(w io.Writer, result *analyzer.ScanResult) {
	s := result.Stats
	fmt.Fprintf(w, "\n%s── Scan Summary ──%s\n", colorBold, colorReset)
	fmt.Fprintf(w, "  Files scanned : %d\n", s.FilesScanned)
	fmt.Fprintf(w, "  Files skipped : %d\n", s.FilesSkipped)
	fmt.Fprintf(w, "  Errors        : %d\n", s.FilesErrored)
	fmt.Fprintf(w, "  Total findings: %d\n", s.TotalFindings)
	if s.TotalFindings > 0 {
		fmt.Fprintf(w, "  By severity   :")
		if s.BySeverity["CRITICAL"] > 0 {
			fmt.Fprintf(w, "  %s%sCRITICAL=%d%s", colorBold, "\033[35m", s.BySeverity["CRITICAL"], colorReset)
		}
		if s.BySeverity["HIGH"] > 0 {
			fmt.Fprintf(w, "  %s%sHIGH=%d%s", colorBold, colorRed, s.BySeverity["HIGH"], colorReset)
		}
		if s.BySeverity["MEDIUM"] > 0 {
			fmt.Fprintf(w, "  %s%sMEDIUM=%d%s", colorBold, colorYellow, s.BySeverity["MEDIUM"], colorReset)
		}
		if s.BySeverity["LOW"] > 0 {
			fmt.Fprintf(w, "  %s%sLOW=%d%s", colorBold, colorCyan, s.BySeverity["LOW"], colorReset)
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
	Line      int    `json:"line"`
	Column    int    `json:"column"`
	Severity  string `json:"severity"`
	RuleID    string `json:"rule_id"`
	RuleName  string `json:"rule_name"`
	Category  string `json:"category"`
	Details   string `json:"details"`
	Content   string `json:"content"`
	MatchText string `json:"match_text,omitempty"`
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
			out.Findings = append(out.Findings, jsonFinding{
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
			})
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

	_ = cw.Write([]string{"file", "line", "column", "severity", "rule_id", "rule_name", "category", "details", "content", "match_text"})

	for _, fr := range result.Files {
		if fr.Skipped || fr.Error != nil {
			continue
		}
		for _, f := range fr.Findings {
			_ = cw.Write([]string{
				f.File,
				fmt.Sprintf("%d", f.Line),
				fmt.Sprintf("%d", f.Column),
				f.Severity.String(),
				f.RuleID,
				f.RuleName,
				f.Category,
				f.Details,
				f.Content,
				f.MatchText,
			})
		}
	}
	return cw.Error()
}