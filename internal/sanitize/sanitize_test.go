package sanitize

import (
	"bytes"
	"strings"
	"testing"
)

func TestMaskEmail(t *testing.T) {
	in := "user alice.smith@corp.example.com logged in"
	got := maskEmail(in)
	want := "user a***@corp.example.com logged in"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestMaskPhone(t *testing.T) {
	got := maskPhone("call from 13812345678 at 09:00")
	want := "call from 138****5678 at 09:00"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestMaskIDCard(t *testing.T) {
	got := maskIDCard("id 110101199003071234 issued")
	want := "id 110101********1234 issued"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestMaskIPv4(t *testing.T) {
	got := maskIPv4("connect 192.168.1.100:8080 ok")
	want := "connect 192.168.*.*:8080 ok"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestUnknownMask(t *testing.T) {
	if _, err := NewPipeline(Option{Masks: []string{"bogus"}}); err == nil {
		t.Fatal("expected error for unknown mask")
	}
}

func TestSanitizeLineNoMask(t *testing.T) {
	p, _ := NewPipeline(Option{Masks: nil, Normalize: true})
	got := p.SanitizeLine("  error    occurred   ")
	if got != "error occurred" {
		t.Fatalf("got %q, want %q", got, "error occurred")
	}
}

func TestProcessStream(t *testing.T) {
	p, _ := NewPipeline(Option{Masks: []string{"email", "phone"}, Normalize: true})
	in := "alice@x.com  called 13900001111   \nnext line\n"
	var buf bytes.Buffer
	if err := p.Process(strings.NewReader(in), &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "a***@x.com") {
		t.Fatalf("email not masked: %q", out)
	}
	if !strings.Contains(out, "139****1111") {
		t.Fatalf("phone not masked: %q", out)
	}
	if !strings.Contains(out, "called 139****1111") {
		t.Fatalf("whitespace not normalized: %q", out)
	}
}

func TestMaskIDCard15(t *testing.T) {
	got := maskIDCard("old id 110101900307123 here")
	want := "old id 110101********3 here"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestMaskEmailSingleChar(t *testing.T) {
	got := maskEmail("user a@x.com end")
	want := "user ***@x.com end"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNormalizeTrimEdges(t *testing.T) {
	p, _ := NewPipeline(Option{Masks: nil, Normalize: true})
	got := p.SanitizeLine("\t  hello  world  \t")
	want := "hello world"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestProcessFlushError(t *testing.T) {
	p, _ := NewPipeline(Option{Masks: []string{"ip"}, Normalize: false})
	in := "server 10.0.0.1 responded\n"
	var buf bytes.Buffer
	if err := p.Process(strings.NewReader(in), &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "10.0.*.*") {
		t.Fatalf("ip not masked: %q", got)
	}
}

func TestMaskPhonePreservesLength(t *testing.T) {
	got := maskPhone("tel 13900001111 end")
	want := "tel 139****1111 end"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
