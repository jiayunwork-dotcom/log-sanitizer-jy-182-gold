// Command log-sanitizer masks sensitive fields (email, phone, ID card, IPv4)
// in log files and optionally normalizes their formatting. It reads from a
// single file, a directory (filtered by extension), or a glob, and writes to
// stdout or a file/directory.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"log-sanitizer/internal/sanitize"
)

func main() {
	in := flag.String("in", "", "input file, directory, or glob (required)")
	out := flag.String("out", "", "output file or directory; empty = stdout")
	mask := flag.String("mask", "email,phone,idcard,ip", "comma list of masks: email,phone,idcard,ip")
	normalize := flag.Bool("normalize", true, "normalize whitespace and trim each line")
	ext := flag.String("ext", ".log,.txt,.csv", "file extensions to include when -in is a directory")
	flag.Parse()

	if *in == "" {
		fatal("missing required -in (input file, directory, or glob)")
	}

	var masks []string
	for _, m := range strings.Split(*mask, ",") {
		if m = strings.TrimSpace(m); m != "" {
			masks = append(masks, m)
		}
	}
	p, err := sanitize.NewPipeline(sanitize.Option{Masks: masks, Normalize: *normalize})
	if err != nil {
		fatal("%v", err)
	}

	inputs, err := resolveInputs(*in, *ext)
	if err != nil {
		fatal("%v", err)
	}

	outIsDir := false
	if *out != "" {
		if fi, statErr := os.Stat(*out); statErr == nil && fi.IsDir() {
			outIsDir = true
		} else if statErr != nil && !os.IsNotExist(statErr) {
			fatal("cannot access -out %q: %v", *out, statErr)
		}
		if !outIsDir && len(inputs) > 1 {
			fatal("-out %q must be a directory when processing multiple inputs", *out)
		}
	}

	for _, path := range inputs {
		var w io.Writer = os.Stdout
		var f *os.File
		if *out != "" {
			outPath := *out
			if outIsDir {
				outPath = filepath.Join(*out, filepath.Base(path)+".sanitized")
			}
			f, err = os.Create(outPath)
			if err != nil {
				fatal("create %q: %v", outPath, err)
			}
			w = f
		}
		procErr := processOne(p, path, w)
		if f != nil {
			if closeErr := f.Close(); closeErr != nil && procErr == nil {
				fatal("close output: %v", closeErr)
			}
		}
		if procErr != nil {
			fatal("process %q: %v", path, procErr)
		}
	}
}

func processOne(p *sanitize.Pipeline, path string, w io.Writer) error {
	src, err := os.Open(path)
	if err != nil {
		return err
	}
	defer src.Close()
	return p.Process(src, w)
}

// resolveInputs expands -in into a concrete list of file paths.
func resolveInputs(in, exts string) ([]string, error) {
	if strings.Contains(in, "*") {
		matches, err := filepath.Glob(in)
		if err != nil {
			return nil, err
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("no files match %q", in)
		}
		return matches, nil
	}

	info, err := os.Stat(in)
	if err != nil {
		return nil, fmt.Errorf("cannot access -in %q: %w", in, err)
	}
	if !info.IsDir() {
		return []string{in}, nil
	}

	extSet := make(map[string]bool)
	for _, e := range strings.Split(exts, ",") {
		if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
			extSet[e] = true
		}
	}
	entries, err := os.ReadDir(in)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if len(extSet) > 0 && !extSet[strings.ToLower(filepath.Ext(e.Name()))] {
			continue
		}
		out = append(out, filepath.Join(in, e.Name()))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no matching files in directory %q", in)
	}
	sort.Strings(out)
	return out, nil
}

func fatal(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "log-sanitizer: "+format+"\n", a...)
	os.Exit(1)
}
