package notify

import (
	"context"
	"errors"
	"os"
	"os/user"
	"runtime"
	"strings"
	"testing"
)

type originRecorder struct {
	title, text string
	err         error
}

func (r *originRecorder) Markdown(_ context.Context, title, text string) error {
	r.title, r.text = title, text
	return r.err
}

func TestLocalOriginIdentifiesTheServingProcess(t *testing.T) {
	o, err := LocalOrigin()
	if err != nil {
		t.Fatal(err)
	}
	host, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	if o.Hostname != cleanOrigin(host) || o.PID != os.Getpid() || o.OS != runtime.GOOS || o.Arch != runtime.GOARCH || o.User == "" {
		t.Fatalf("unexpected local origin: %+v", o)
	}
}

func TestOriginFallbackReportsDetectionErrors(t *testing.T) {
	fail := errors.New("unavailable")
	o, err := detectOrigin(func() (string, error) { return "", fail }, func() (*user.User, error) { return nil, fail })
	if !errors.Is(err, fail) || o.Hostname != "unknown" || o.User != "unknown" || o.PID != os.Getpid() {
		t.Fatalf("fallback must remain useful and report failures: %+v %v", o, err)
	}
}

func TestOriginNotifierLabelsSourceWithoutAlteringTheRequest(t *testing.T) {
	r := &originRecorder{}
	o := Origin{Hostname: "worker-1", User: "alice", PID: 42, OS: "linux", Arch: "arm64"}
	text := "**Replacement login link**\n\n[Open](https://page.example/#secret)"
	if err := WithOrigin(r, o).Markdown(context.Background(), "Login request: target.example", text); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(r.text, text) || !strings.Contains(r.title, "worker-1") || !strings.Contains(r.title, "target.example") {
		t.Fatalf("source must not replace the destination, link or warning: %q %q", r.title, r.text)
	}
	for _, want := range []string{"Request origin (securl host)", "worker-1", "alice", "42", "linux/arm64"} {
		if !strings.Contains(r.text, want) {
			t.Errorf("message missing %q: %s", want, r.text)
		}
	}
}

func TestOriginNotifierEscapesBoundsAndPropagatesErrors(t *testing.T) {
	fail := errors.New("delivery failed")
	r := &originRecorder{err: fail}
	o := Origin{Hostname: "[evil](https://example)\n# forged\x1b\u202e", User: strings.Repeat("a", 1000), PID: 1, OS: "linux", Arch: "amd64"}
	if err := WithOrigin(r, o).Markdown(context.Background(), "Login", "original"); !errors.Is(err, fail) {
		t.Fatalf("delivery error lost: %v", err)
	}
	for _, bad := range []string{"](https://example)", "\n# forged", "\x1b", "\u202e", strings.Repeat("a", 129)} {
		if strings.Contains(r.title+r.text, bad) {
			t.Errorf("unsafe or unbounded origin %q in %q", bad, r.title+r.text)
		}
	}
}

func TestWithLocalOriginAndUnknownDescription(t *testing.T) {
	r := &originRecorder{}
	if err := WithLocalOrigin(r).Markdown(context.Background(), "Test", "original"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.text, "Request origin (securl host)") {
		t.Fatalf("local diagnostics must identify their source too: %s", r.text)
	}
	if got := (Origin{PID: -1}).Description(); got != "host unknown; account unknown; PID 0; unknown/unknown" {
		t.Fatalf("missing metadata must not invent an identity: %s", got)
	}
}

func TestOriginDoesNotCollectAccountProfileOrHomeDirectory(t *testing.T) {
	o, err := detectOrigin(func() (string, error) { return "worker-4", nil }, func() (*user.User, error) {
		return &user.User{Username: "alice", Name: "PRIVATE-FULL-NAME", HomeDir: "/private/home/path", Uid: "PRIVATE-UID", Gid: "PRIVATE-GID"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if o.User != "alice" || strings.Contains(o.Description(), "PRIVATE") || strings.Contains(o.Description(), "/private/home") {
		t.Fatalf("origin must not collect the rest of the OS account profile: %+v", o)
	}
}
