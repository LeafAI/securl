package climode

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/browsertest"
	"github.com/LeafAI/securl/internal/web"

	_ "github.com/LeafAI/securl/internal/site/gitlab"
)

// fakeGitLab is a sign-in form with no second factor.
func fakeGitLab() *httptest.Server {
	const form = `<form><input type="hidden" name="authenticity_token" value="T1"/></form>`
	mux := http.NewServeMux()
	mux.HandleFunc("/users/sign_in", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.Write([]byte(form))
			return
		}
		r.ParseForm()
		if r.PostForm.Get("user[login]") == "alice" && r.PostForm.Get("user[password]") == "pw-SECRET-1" {
			http.SetCookie(w, &http.Cookie{Name: "_gitlab_session", Value: "COOKIE-SECRET-9", Path: "/"})
			http.Redirect(w, r, "/", 302)
			return
		}
		w.Write([]byte(form))
	})
	mux.HandleFunc("/api/v4/user", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("_gitlab_session"); err != nil || c.Value != "COOKIE-SECRET-9" {
			http.Error(w, "no", 401)
			return
		}
		w.Write([]byte(`{"username":"alice"}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("home")) })
	return httptest.NewServer(mux)
}

var linkRE = regexp.MustCompile(`\]\((file://[^)]+#[^)]+)\)`)

// linkIn waits for the n-th message to the robot and returns the link in it.
func linkIn(t *testing.T, rec *recorder, n int) string {
	t.Helper()
	for i := 0; i < 600; i++ {
		rec.mu.Lock()
		if len(rec.msgs) >= n {
			m := linkRE.FindStringSubmatch(rec.msgs[n-1])
			rec.mu.Unlock()
			if m == nil {
				t.Fatalf("no link in the message:\n%s", rec.msgs[n-1])
			}
			return m[1]
		}
		rec.mu.Unlock()
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no message #%d to the robot", n)
	return ""
}

// syncBuf is a buffer the command writes to while the test reads it.
type syncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func TestLoggingInFromTheCommandLineSendsTheLinkToTheRobotAndPrintsOnlyTheAnswer(t *testing.T) {
	browsertest.Require(t)
	gl := fakeGitLab()
	defer gl.Close()

	r := newRig(t, false)
	pages := t.TempDir()
	if err := web.WriteTo(pages); err != nil {
		t.Fatal(err)
	}
	r.cfg.Web.PageURL = "file://" + pages + "/index.html"
	r.cfg.Web.TTL = time.Minute
	rec := r.withRobot()
	r.cfg.Web.TTL = time.Minute

	stderr := &syncBuf{}
	env := r.envFor()
	env.Err = stderr
	done := make(chan int, 1)
	go func() {
		done <- Run(t.Context(), []string{"session", "open", "--url", gl.URL, "--site", "gitlab", "--reason", "cli test"}, env)
	}()

	// the person: with a robot the link is in the message, and the terminal only says that a person is being waited for
	link := linkIn(t, rec, 1)
	deadline := time.Now().Add(30 * time.Second)
	for !strings.Contains(stderr.String(), "waiting for the human") && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(stderr.String(), "waiting for the human") {
		t.Errorf("the terminal says what it waits for:\n%s", stderr.String())
	}
	if strings.Contains(stderr.String(), link) {
		t.Errorf("a link that went to the robot must not also be printed:\n%s", stderr.String())
	}
	page := browsertest.Drive(t, pages, browsertest.Fragment(link), "submit", `{"username":"alice","password":"pw-SECRET-1"}`, "").Msg
	if !strings.Contains(page, "Done") {
		t.Fatalf("page said %q", page)
	}

	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, env.Out.(interface{ String() string }).String(), stderr.String())
		}
	case <-time.After(60 * time.Second):
		t.Fatal("the command did not finish after the person typed")
	}
	out := r.out.String()
	if m := r.json(t); m["status"] != "ok" || m["site"] != "gitlab" {
		t.Errorf("the final answer is the session: %s", out)
	}
	for _, secret := range []string{"pw-SECRET-1", "COOKIE-SECRET-9", "_gitlab_session"} {
		if strings.Contains(out, secret) || strings.Contains(stderr.String(), secret) {
			t.Errorf("a credential reached the terminal: %q", secret)
		}
	}
	if strings.Contains(out, "file://") || strings.Contains(out, "key_code") {
		t.Errorf("a link is never part of the final answer\n%s", out)
	}
}

// The session of one command is there for the next: the vault keeps it, so `request` in a second process finds it.
func TestASessionOpenedByOneCommandIsUsedByTheNext(t *testing.T) {
	browsertest.Require(t)
	gl := fakeGitLab()
	defer gl.Close()
	r := newRig(t, true)
	r.secret = func() (string, error) { return testPass, nil }
	pages := t.TempDir()
	if err := web.WriteTo(pages); err != nil {
		t.Fatal(err)
	}
	r.cfg.Web.PageURL = "file://" + pages + "/index.html"
	r.cfg.Web.TTL = time.Minute
	rec := r.withRobot()
	r.cfg.Web.TTL = time.Minute

	stderr := &syncBuf{}
	env := r.envFor()
	env.Err = stderr
	env.Secret = func() (string, error) { return testPass, nil }
	done := make(chan int, 1)
	go func() {
		done <- Run(t.Context(), []string{"session", "open", "--url", gl.URL, "--site", "gitlab"}, env)
	}()
	link := linkIn(t, rec, 1)
	browsertest.Drive(t, pages, browsertest.Fragment(link), "submit", `{"username":"alice","password":"pw-SECRET-1"}`, "")
	if code := <-done; code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if r.vault.State().String() != "locked" {
		t.Fatal("the first command must have locked the vault when it ended")
	}

	// a second process: a new rig around the same vault files, locked, with the passphrase typed again
	r.out.Reset()
	code := r.run(t, "request", "--url", gl.URL, "--method", "GET", "--path", "/api/v4/user")
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, r.out.String(), r.errOut.String())
	}
	m := r.json(t)
	if m["status"] != float64(200) || !strings.Contains(r.out.String(), "alice") {
		t.Errorf("the second command used the session: %s", r.out.String())
	}
	for _, secret := range []string{"COOKIE-SECRET-9", "_gitlab_session", "pw-SECRET-1"} {
		if strings.Contains(r.out.String(), secret) {
			t.Errorf("the answer carries %q", secret)
		}
	}
}
