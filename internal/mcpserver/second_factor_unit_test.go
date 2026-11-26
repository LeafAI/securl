package mcpserver

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/remember"
	"github.com/LeafAI/securl/internal/site"
	"github.com/LeafAI/securl/internal/totp"
	"github.com/LeafAI/securl/internal/vault"
)

type unitGA struct{}

func (unitGA) Name() string                      { return "unit-ga" }
func (unitGA) Match(*url.URL) bool               { return false }
func (unitGA) NeedsLogin() bool                  { return true }
func (unitGA) RememberScope() (string, *url.URL) { return "", nil }
func (unitGA) SecondFactorHeader() (string, int) { return "x-ga-code", 6 }
func (unitGA) CodeRefused(int, []byte) bool      { return false }
func (unitGA) Login(context.Context, *url.URL, site.Asker, *http.Client) (*site.Session, error) {
	return &site.Session{}, nil
}
func (unitGA) Probe(context.Context, *url.URL, *site.Session, *http.Client) error { return nil }

type plainUnit struct{ unitGA }

func (plainUnit) SecondFactorHeader() {} // shadows the method so that plainUnit does not implement site.SecondFactor

// A code is made only for the grant the session was opened under, and only while it is in force. These are checked where the code is
// made, and not left to the checks that come before it, so that one of them being changed cannot let a code out under a grant that
// the person has ended or replaced.
func TestNoCodeIsMadeUnderAGrantThatEndedOrWasReplacedOrNeverWas(t *testing.T) {
	g := gateServer(t, "open", func(c *config.Config) {})
	base, _ := url.Parse("https://console.example")
	key := site.Key(base)
	seed := []byte("12345678901234567890")
	if err := remember.Enroll(g.v, key, remember.Record{Site: "unit-ga", Username: "u", Password: "p", Secret: seed}); err != nil {
		t.Fatal(err)
	}
	rec, err := remember.Load(g.v, key)
	if err != nil {
		t.Fatal(err)
	}
	rec, err = remember.Approve(g.v, key, rec, time.Now(), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	k, terr := g.s.gate()
	if terr != nil {
		t.Fatal(terr)
	}
	d := unitGA{}
	if sf, terr := g.s.secondFactorFor(k, d, base, &site.Session{ApprovalID: rec.Revision}); terr != nil || sf == nil {
		t.Fatalf("a live grant with a seed makes a code: %v", terr)
	}
	if sf, terr := g.s.secondFactorFor(k, d, base, &site.Session{}); terr == nil || sf != nil {
		t.Error("a session that was never under a grant makes no code")
	}
	if sf, terr := g.s.secondFactorFor(k, d, base, &site.Session{ApprovalID: "another-revision"}); terr == nil || sf != nil {
		t.Error("a session under another grant than the saved one makes no code")
	}
	if sf, terr := g.s.secondFactorFor(k, plainUnit{}, base, &site.Session{ApprovalID: rec.Revision}); terr != nil || sf != nil {
		t.Errorf("a driver that asks for no code gets none and no error: %v", terr)
	}
	if _, err = remember.Approve(g.v, key, rec, time.Now().Add(-48*time.Hour), 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	old, _ := remember.Load(g.v, key)
	if sf, terr := g.s.secondFactorFor(k, d, base, &site.Session{ApprovalID: old.Revision}); terr == nil || sf != nil {
		t.Error("a grant that has run out makes no code")
	}
}

// The person removes the saved credentials after the session was opened: the session still names a grant, but there is nothing to
// make a code from, and the call must say so instead of failing on a record that is not there.
func TestNoCodeIsMadeWhenTheSavedCredentialsWereRemovedAfterTheSessionOpened(t *testing.T) {
	g := gateServer(t, "open", func(c *config.Config) {})
	base, _ := url.Parse("https://console.example")
	key := site.Key(base)
	if err := remember.Enroll(g.v, key, remember.Record{Site: "unit-ga", Username: "u", Password: "p", Secret: []byte("12345678901234567890")}); err != nil {
		t.Fatal(err)
	}
	rec, err := remember.Load(g.v, key)
	if err != nil {
		t.Fatal(err)
	}
	if rec, err = remember.Approve(g.v, key, rec, time.Now(), 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	k, terr := g.s.gate()
	if terr != nil {
		t.Fatal(terr)
	}
	if err = remember.Remove(g.v, key); err != nil {
		t.Fatal(err)
	}
	sf, terr := g.s.secondFactorFor(k, unitGA{}, base, &site.Session{ApprovalID: rec.Revision})
	if terr == nil || sf != nil {
		t.Fatalf("no saved credentials, no code: %v", terr)
	}
	if terr.Code != "session_expired" {
		t.Errorf("the answer says approval is needed again: %q", terr.Code)
	}
}

// A code is the standard one for the saved seed, made when it is asked for, once. The seed is cleared after it is used, so a second
// ask must be an error: a code made from a cleared seed would be wrong, look like any other, and count against the account.
func TestACodeIsTheStandardOneForTheSavedSeedAndCanBeAskedForOnlyOnce(t *testing.T) {
	g := gateServer(t, "open", func(c *config.Config) {})
	base, _ := url.Parse("https://console.example")
	key := site.Key(base)
	seed := []byte("12345678901234567890")
	if err := remember.Enroll(g.v, key, remember.Record{Site: "unit-ga", Username: "u", Password: "p", Secret: append([]byte(nil), seed...)}); err != nil {
		t.Fatal(err)
	}
	rec, _ := remember.Load(g.v, key)
	rec, _ = remember.Approve(g.v, key, rec, time.Now(), 24*time.Hour)
	k, _ := g.s.gate()
	sf, terr := g.s.secondFactorFor(k, unitGA{}, base, &site.Session{ApprovalID: rec.Revision})
	if terr != nil {
		t.Fatal(terr)
	}
	if sf.Header != "x-ga-code" || sf.Refused == nil {
		t.Errorf("%q, and the driver is asked whether the site refused the code: %v", sf.Header, sf.Refused != nil)
	}
	before := time.Now()
	code, err := sf.Code()
	after := time.Now()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{totp.Code(seed, before, 30*time.Second, 6): true, totp.Code(seed, after, 30*time.Second, 6): true}
	if !want[code] {
		t.Errorf("%q is not the code of the saved seed at this moment (%v)", code, want)
	}
	if again, err := sf.Code(); err == nil {
		t.Errorf("a second code was made (%q) from a seed that was cleared", again)
	}
}

// Every ask of secondFactorFor reads the seed afresh: two requests make two independent codes, neither from a seed another cleared.
func TestTwoRequestsEachGetAWorkingCode(t *testing.T) {
	g := gateServer(t, "open", func(c *config.Config) {})
	base, _ := url.Parse("https://console.example")
	key := site.Key(base)
	seed := []byte("12345678901234567890")
	remember.Enroll(g.v, key, remember.Record{Site: "unit-ga", Username: "u", Password: "p", Secret: append([]byte(nil), seed...)})
	rec, _ := remember.Load(g.v, key)
	rec, _ = remember.Approve(g.v, key, rec, time.Now(), 24*time.Hour)
	k, _ := g.s.gate()
	for i := 0; i < 3; i++ {
		sf, terr := g.s.secondFactorFor(k, unitGA{}, base, &site.Session{ApprovalID: rec.Revision})
		if terr != nil {
			t.Fatal(terr)
		}
		code, err := sf.Code()
		if err != nil || (code != totp.Code(seed, time.Now(), 30*time.Second, 6) && code != totp.Code(seed, time.Now().Add(-time.Second), 30*time.Second, 6)) {
			t.Errorf("request %d: %q %v", i, code, err)
		}
	}
}

var _ = vault.ErrNoEntry

// The saved record belongs to the vault: making a code must not change what the vault will hand out next time, and the seed made into
// a code is wiped from the copy that was taken, so that nothing keeps it after the one use.
func TestMakingACodeDoesNotChangeWhatTheVaultHolds(t *testing.T) {
	g := gateServer(t, "open", func(c *config.Config) {})
	base, _ := url.Parse("https://console.example")
	key := site.Key(base)
	seed := []byte("12345678901234567890")
	remember.Enroll(g.v, key, remember.Record{Site: "unit-ga", Username: "u", Password: "p", Secret: append([]byte(nil), seed...)})
	rec, _ := remember.Load(g.v, key)
	rec, _ = remember.Approve(g.v, key, rec, time.Now(), 24*time.Hour)
	k, _ := g.s.gate()
	for i := 0; i < 3; i++ {
		sf, terr := g.s.secondFactorFor(k, unitGA{}, base, &site.Session{ApprovalID: rec.Revision})
		if terr != nil {
			t.Fatalf("round %d: %v", i, terr)
		}
		if _, err := sf.Code(); err != nil {
			t.Fatal(err)
		}
		after, err := remember.Load(g.v, key)
		if err != nil || string(after.Secret) != string(seed) {
			t.Fatalf("round %d: the saved seed was changed by making a code: %q %v", i, after.Secret, err)
		}
	}
}

// With no grant at all a request has no approval to rest on, and the answer is the one that tells the person what to do, not a code.
func TestASessionWithNoApprovalIsToldWhatMissesAndMakesNoCode(t *testing.T) {
	g := gateServer(t, "open", func(c *config.Config) {})
	base, _ := url.Parse("https://console.example")
	k, _ := g.s.gate()
	sf, terr := g.s.secondFactorFor(k, unitGA{}, base, &site.Session{})
	if sf != nil || terr == nil || terr.Code != "second_factor_required" {
		t.Errorf("%v %v", sf, terr)
	}
}
