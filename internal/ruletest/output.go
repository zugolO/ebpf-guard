package ruletest

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// TAP output (Test Anything Protocol v13)
// ─────────────────────────────────────────────────────────────────────────────

// TAPWriter writes TAP v13 output to an io.Writer.
type TAPWriter struct {
	w   io.Writer
	seq int // current test number (1-based)
}

// NewTAPWriter creates a writer and emits the TAP version header.
func NewTAPWriter(w io.Writer) *TAPWriter {
	fmt.Fprintln(w, "TAP version 13")
	return &TAPWriter{w: w}
}

// Plan emits the test plan line (must be called before any WriteResult).
func (t *TAPWriter) Plan(count int) {
	fmt.Fprintf(t.w, "1..%d\n", count)
}

// WriteResult emits a single TAP test line for the result.
func (t *TAPWriter) WriteResult(r Result) {
	t.seq++
	prefix := "ok"
	if !r.Passed {
		prefix = "not ok"
	}
	desc := fmt.Sprintf("%s: %s", r.Suite, r.Name)
	fmt.Fprintf(t.w, "%s %d - %s\n", prefix, t.seq, desc)

	if !r.Passed {
		if r.Error != "" {
			fmt.Fprintf(t.w, "  # error: %s\n", r.Error)
		} else {
			fmt.Fprintf(t.w, "  # expected: %s\n", r.Expected)
			fmt.Fprintf(t.w, "  # got:      %s\n", r.Got)
			if len(r.MatchedIDs) > 0 {
				fmt.Fprintf(t.w, "  # matched rules: %s\n", strings.Join(r.MatchedIDs, ", "))
			}
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// JUnit XML output
// ─────────────────────────────────────────────────────────────────────────────

// WriteJUnit writes all results as JUnit-compatible XML to w.
// Results are grouped by suite name.
func WriteJUnit(w io.Writer, results []Result) error {
	// Group by suite.
	suiteMap := make(map[string][]Result)
	suiteOrder := make([]string, 0)
	for _, r := range results {
		if _, ok := suiteMap[r.Suite]; !ok {
			suiteOrder = append(suiteOrder, r.Suite)
		}
		suiteMap[r.Suite] = append(suiteMap[r.Suite], r)
	}

	type jFailure struct {
		XMLName xml.Name `xml:"failure"`
		Message string   `xml:"message,attr"`
		Body    string   `xml:",chardata"`
	}
	type jTestCase struct {
		XMLName   xml.Name  `xml:"testcase"`
		Name      string    `xml:"name,attr"`
		ClassName string    `xml:"classname,attr"`
		Failure   *jFailure `xml:"failure,omitempty"`
	}
	type jTestSuite struct {
		XMLName   xml.Name    `xml:"testsuite"`
		Name      string      `xml:"name,attr"`
		Tests     int         `xml:"tests,attr"`
		Failures  int         `xml:"failures,attr"`
		Timestamp string      `xml:"timestamp,attr"`
		Cases     []jTestCase `xml:"testcase"`
	}
	type jTestSuites struct {
		XMLName xml.Name     `xml:"testsuites"`
		Suites  []jTestSuite `xml:"testsuite"`
	}

	jss := jTestSuites{}
	ts := time.Now().UTC().Format(time.RFC3339)

	for _, name := range suiteOrder {
		rs := suiteMap[name]
		js := jTestSuite{
			Name:      name,
			Tests:     len(rs),
			Timestamp: ts,
		}
		for _, r := range rs {
			jc := jTestCase{
				Name:      r.Name,
				ClassName: r.Suite,
			}
			if !r.Passed {
				js.Failures++
				msg := fmt.Sprintf("expected %s, got %s", r.Expected, r.Got)
				if r.Error != "" {
					msg = r.Error
				}
				body := msg
				if len(r.MatchedIDs) > 0 {
					body += "\nmatched rules: " + strings.Join(r.MatchedIDs, ", ")
				}
				jc.Failure = &jFailure{Message: msg, Body: body}
			}
			js.Cases = append(js.Cases, jc)
		}
		jss.Suites = append(jss.Suites, js)
	}

	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	return enc.Encode(jss)
}
