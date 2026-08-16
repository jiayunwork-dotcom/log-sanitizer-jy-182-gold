// Package sanitize provides a small pipeline that masks sensitive fields in
// log lines (email, phone, ID card, IPv4) and optionally normalizes their
// formatting (trim, collapse whitespace, single trailing newline).
//
// It is stream-oriented: Process reads line-by-line from an io.Reader and
// writes the sanitized result to an io.Writer, so it never holds a whole file
// in memory.
package sanitize

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// registry maps a mask name to its implementation.
var registry = map[string]func(string) string{
	"email":  maskEmail,
	"phone":  maskPhone,
	"idcard": maskIDCard,
	"ip":     maskIPv4,
}

// ValidMasks returns the supported mask names in a stable order.
func ValidMasks() []string {
	return []string{"email", "phone", "idcard", "ip"}
}

// Option configures a Pipeline.
type Option struct {
	Masks     []string // ordered mask names; empty means no masking
	Normalize bool     // collapse whitespace and trim each line
}

// Pipeline applies a fixed set of masks and optional normalization.
type Pipeline struct {
	maskers   []func(string) string
	normalize bool
}

// NewPipeline validates the requested mask names and builds a Pipeline.
func NewPipeline(opts Option) (*Pipeline, error) {
	p := &Pipeline{normalize: opts.Normalize}
	for _, name := range opts.Masks {
		fn, ok := registry[name]
		if !ok {
			return nil, fmt.Errorf("unknown mask %q (valid: %s)", name, strings.Join(ValidMasks(), ", "))
		}
		p.maskers = append(p.maskers, fn)
	}
	return p, nil
}

// SanitizeLine masks and optionally normalizes a single line.
func (p *Pipeline) SanitizeLine(line string) string {
	out := line
	for _, m := range p.maskers {
		out = m(out)
	}
	if p.normalize {
		out = normalize(out)
	}
	return out
}

// Process streams the input through the pipeline to the output, line by line.
func (p *Pipeline) Process(in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	w := bufio.NewWriter(out)
	defer w.Flush()
	for sc.Scan() {
		if _, err := w.WriteString(p.SanitizeLine(sc.Text()) + "\n"); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return w.Flush()
}

// ----- masks -----

var reEmail = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

func maskEmail(s string) string {
	return reEmail.ReplaceAllStringFunc(s, func(m string) string {
		at := strings.Index(m, "@")
		if at <= 0 {
			return m
		}
		local, domain := m[:at], m[at:] // domain keeps the leading "@"
		if len(local) <= 1 {
			return "***" + domain
		}
		return string(local[0]) + "***" + domain
	})
}

var rePhone = regexp.MustCompile(`\b1[3-9]\d{9}\b`)

func maskPhone(s string) string {
	return rePhone.ReplaceAllStringFunc(s, func(m string) string {
		return m[:3] + "****" + m[7:]
	})
}

var reID = regexp.MustCompile(`\b\d{17}[\dXx]\b|\b\d{15}\b`)

func maskIDCard(s string) string {
	return reID.ReplaceAllStringFunc(s, func(m string) string {
		switch len(m) {
		case 18:
			return m[:6] + "********" + m[14:]
		case 15:
			return m[:6] + "********" + m[14:]
		default:
			return m
		}
	})
}

var reIP = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

func maskIPv4(s string) string {
	return reIP.ReplaceAllStringFunc(s, func(m string) string {
		parts := strings.Split(m, ".")
		if len(parts) != 4 {
			return m
		}
		return parts[0] + "." + parts[1] + ".*.*"
	})
}

// ----- normalization -----

var wsRe = regexp.MustCompile(`[ \t]+`)

func normalize(s string) string {
	s = strings.TrimSpace(s)
	s = wsRe.ReplaceAllString(s, " ")
	return s
}
