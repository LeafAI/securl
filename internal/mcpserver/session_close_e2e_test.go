package mcpserver_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/securl/internal/browsertest"
	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/mcpserver"
	"github.com/LeafAI/securl/internal/vault"
	"github.com/LeafAI/securl/internal/web"
)

// Closing a session forgets what a person typed: a database account is a password that cannot be asked back from anywhere. So no
// session is closed until a person has said so, out of band, on the page that a link leads to, naming what goes. The socket of a
// daemon is open to every process of the user, an agent's shell among them, so the question is the server's and the answer comes only
// through the page: nothing a caller can send makes it unnecessary.

type closeEnv struct {
	cs    *mcp.ClientSession
	app   *mcpserver.Server
	rec   *recorder
	dir   string
	v     *vault.Vault
	audit string
}

func closeSetup(t *testing.T, tweak func(*config.Config)) *closeEnv {
	t.Helper()
	browsertest.Require(t)
	dir := t.TempDir()
	if err := web.WriteTo(dir); err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.Load(dir + "/none.yaml")
	cfg.Security.AllowLocalAddresses = true
	cfg.Web.PageURL = "file://" + dir + "/index.html"
	cfg.Web.TTL = time.Minute
	cfg.MCP.MaxBlockSeconds = 1
	cfg.Audit.File = dir + "/audit.jsonl"
	cfg.Databases = []config.Database{
		{Name: "dev-pg", Driver: config.DriverPostgres, Host: "pg.dev.corp.example", Port: 5432, Environment: "dev", Mode: config.ModeReadOnly},
		{Name: "dev-my", Driver: config.DriverMySQL, Host: "my.dev.corp.example", Port: 3306, Environment: "test", Mode: config.ModeReadOnly},
	}
	if tweak != nil {
		tweak(cfg)
	}
	v := testVault(t, cfg)
	rec := &recorder{}
	srv, app, err := mcpserver.New(cfg, mcpserver.Options{Notifier: rec, Tunnels: localTunnels{}, Log: func(string, ...any) {}, Vault: v})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	ct, st := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(context.Background(), st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return &closeEnv{cs: cs, app: app, rec: rec, dir: dir, v: v, audit: cfg.Audit.File}
}

func (e *closeEnv) seed(t *testing.T) {
	t.Helper()
	for _, s := range []struct{ url, site string }{{"https://gitlab.corp.example", "gitlab"}, {"https://sw.corp.example", "skywalking"}} {
		if err := e.app.SeedSession(s.url, s.site); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"dev-pg", "dev-my"} {
		if err := e.app.SeedDatabaseSession(name); err != nil {
			t.Fatal(err)
		}
	}
}

func (e *closeEnv) call(t *testing.T, tool string, args map[string]any) (map[string]any, bool) {
	t.Helper()
	res, err := e.cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	b, _ := json.Marshal(res.StructuredContent)
	var out map[string]any
	json.Unmarshal(b, &out)
	return out, res.IsError
}

// names are the sessions that exist, as session_list names them: by what they are for, never by what they hold.
func (e *closeEnv) names(t *testing.T) []string {
	t.Helper()
	out, isErr := e.call(t, "session_list", nil)
	if isErr {
		t.Fatalf("session_list: %v", out)
	}
	var n []string
	for _, s := range out["sessions"].([]any) {
		m := s.(map[string]any)
		n = append(n, m["base_url"].(string))
	}
	return n
}

func (e *closeEnv) answer(t *testing.T, n int, word string) string {
	t.Helper()
	vals, _ := json.Marshal(map[string]string{"confirm": word})
	return human(t, e.rec.wait(t, n), e.dir, "submit", string(vals), "")
}

func TestNothingIsClosedUntilAPersonHasConfirmedOnThePage(t *testing.T) {
	e := closeSetup(t, nil)
	e.seed(t)
	before := e.names(t)
	if len(before) != 4 {
		t.Fatalf("the test needs four sessions, has %v", before)
	}
	out, isErr := e.call(t, "session_close", map[string]any{"all": true})
	if isErr || out["status"] != "pending" || out["login_id"] == nil {
		t.Fatalf("closing all must come back pending, with a confirmation to wait for: %v %v", isErr, out)
	}
	if got := e.names(t); len(got) != 4 {
		t.Errorf("a session was closed before anybody confirmed: %v", got)
	}
	if out["removed"] != nil && out["removed"] != float64(0) {
		t.Errorf("the call says it removed something: %v", out)
	}
	// asking again, or in any other way, does not do it either
	for _, args := range []map[string]any{{"all": true}, {"url": "https://gitlab.corp.example"}, {"url": "db://dev-pg"}} {
		e.call(t, "session_close", args)
		if got := e.names(t); len(got) != 4 {
			t.Fatalf("%v closed something with nobody's confirmation: %v", args, got)
		}
	}
}

func TestTheMessageNamesExactlyWhatWillBeClosedAndHoldsNothingSecret(t *testing.T) {
	e := closeSetup(t, nil)
	e.seed(t)
	e.call(t, "session_close", map[string]any{"all": true})
	msg := e.rec.wait(t, 1)
	for _, want := range []string{"gitlab.corp.example", "sw.corp.example", "db://dev-pg", "db://dev-my"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the message must name %s:\n%s", want, msg)
		}
	}
	for _, secret := range []string{"SECRET-SEEDED-COOKIE", "SECRET-DB-PASSWORD", "alice"} {
		if strings.Contains(msg, secret) {
			t.Errorf("the message holds %q", secret)
		}
	}
	if !strings.Contains(strings.ToLower(msg), "close") && !strings.Contains(strings.ToLower(msg), "forget") {
		t.Errorf("the message says what is being asked:\n%s", msg)
	}
	if !strings.Contains(msg, "db://") || !strings.Contains(strings.ToLower(msg), "account") && !strings.Contains(strings.ToLower(msg), "password") {
		t.Errorf("a database target's account cannot be asked back: the message says that closing it loses a password a person typed:\n%s", msg)
	}
}

func TestTheWordTheyTypeOnThePageClosesExactlyWhatWasNamed(t *testing.T) {
	e := closeSetup(t, nil)
	e.seed(t)
	out, _ := e.call(t, "session_close", map[string]any{"url": "https://gitlab.corp.example"})
	if out["status"] != "pending" {
		t.Fatalf("%v", out)
	}
	if page := e.answer(t, 1, "DELETE"); !strings.Contains(page, "Done") {
		t.Fatalf("the page said %q", page)
	}
	done, isErr := e.call(t, "session_close", map[string]any{"url": "https://gitlab.corp.example", "close_id": out["login_id"], "max_block_seconds": 20})
	if isErr || done["status"] != "closed" || done["removed"] != float64(1) {
		t.Fatalf("after the person confirmed: %v %v", isErr, done)
	}
	got := e.names(t)
	if len(got) != 3 {
		t.Errorf("one session was named and one must go: %v", got)
	}
	for _, g := range got {
		if strings.Contains(g, "gitlab") {
			t.Errorf("the named session is still there: %v", got)
		}
	}
}

func TestAWrongWordClosesNothingAndAsksAgain(t *testing.T) {
	e := closeSetup(t, nil)
	e.seed(t)
	out, _ := e.call(t, "session_close", map[string]any{"all": true})
	for i, word := range []string{"yes", "delete", "OK"} {
		e.answer(t, i+1, word)
		if got := e.names(t); len(got) != 4 {
			t.Fatalf("%q closed something: %v", word, got)
		}
	}
	// after three wrong answers the question is over: nothing is closed, and the caller is told so
	res, isErr := e.call(t, "session_close", map[string]any{"all": true, "close_id": out["login_id"], "max_block_seconds": 10})
	if !isErr || res["code"] == nil {
		t.Errorf("three wrong answers end the request with an error: %v %v", isErr, res)
	}
	if got := e.names(t); len(got) != 4 {
		t.Errorf("sessions were closed after wrong answers: %v", got)
	}
}

func TestRejectingOnThePageClosesNothing(t *testing.T) {
	e := closeSetup(t, nil)
	e.seed(t)
	out, _ := e.call(t, "session_close", map[string]any{"all": true})
	human(t, e.rec.wait(t, 1), e.dir, "reject", "", "keep them")
	res, isErr := e.call(t, "session_close", map[string]any{"all": true, "close_id": out["login_id"], "max_block_seconds": 20})
	if !isErr || res["code"] != "user_rejected" {
		t.Fatalf("a rejection is user_rejected: %v %v", isErr, res)
	}
	if m := fmt.Sprint(res["message"]); strings.Contains(m, "login") || !strings.Contains(m, "nothing was closed") || !strings.Contains(m, "keep them") {
		t.Errorf("the message is about closing sessions, says nothing was closed and carries the person's reason: %s", m)
	}
	if got := e.names(t); len(got) != 4 {
		t.Errorf("sessions were closed although the person rejected: %v", got)
	}
}

// What a person agreed to is a list. A session that was made while they were deciding is not on it.
func TestASessionMadeWhileThePersonWasDecidingIsNotClosed(t *testing.T) {
	e := closeSetup(t, nil)
	e.seed(t)
	out, _ := e.call(t, "session_close", map[string]any{"all": true})
	if err := e.app.SeedSession("https://new.corp.example", "gitlab"); err != nil {
		t.Fatal(err)
	}
	e.answer(t, 1, "DELETE")
	res, _ := e.call(t, "session_close", map[string]any{"all": true, "close_id": out["login_id"], "max_block_seconds": 20})
	if res["removed"] != float64(4) {
		t.Errorf("the four that were named go: %v", res)
	}
	got := e.names(t)
	if len(got) != 1 || !strings.Contains(got[0], "new.corp.example") {
		t.Errorf("only the session made after the question should be left: %v", got)
	}
}

func TestNothingToCloseIsAnAnswerAtOnceAndNobodyIsBothered(t *testing.T) {
	e := closeSetup(t, nil)
	out, isErr := e.call(t, "session_close", map[string]any{"all": true})
	if isErr || out["status"] != "closed" || out["removed"] != float64(0) {
		t.Errorf("%v %v", isErr, out)
	}
	if out2, _ := e.call(t, "session_close", map[string]any{"url": "https://nothing.corp.example"}); out2["removed"] != float64(0) {
		t.Errorf("a session that does not exist: %v", out2)
	}
	if n := len(e.rec.all()); n != 0 {
		t.Errorf("a person was asked to confirm closing nothing: %d messages", n)
	}
}

func TestOnlyOneConfirmationIsOutAtATimeAndAsksAreNotRepeatedToThePerson(t *testing.T) {
	e := closeSetup(t, nil)
	e.seed(t)
	a, _ := e.call(t, "session_close", map[string]any{"all": true})
	b, _ := e.call(t, "session_close", map[string]any{"all": true})
	if a["login_id"] != b["login_id"] {
		t.Errorf("a second request while one is out joins it: %v vs %v", a["login_id"], b["login_id"])
	}
	if n := len(e.rec.all()); n != 1 {
		t.Errorf("the person is asked once, not once per call: %d messages", n)
	}
	// ...but a request for something else is not folded into an answer given for another list: it is refused while the first is out
	c, isErr := e.call(t, "session_close", map[string]any{"url": "https://gitlab.corp.example"})
	if !isErr || c["code"] != "close_pending" {
		t.Errorf("a different question while a person is looking at the first is refused: %v %v", isErr, c)
	}
	if len(e.rec.all()) != 1 {
		t.Errorf("and does not bother them again: %d messages", len(e.rec.all()))
	}
	// the one that is out is still the one the person answers, and both callers that joined it hear the outcome
	e.answer(t, 1, "DELETE")
	for i, id := range []any{a["login_id"], b["login_id"]} {
		res, isErr := e.call(t, "session_close", map[string]any{"all": true, "close_id": id, "max_block_seconds": 20})
		if isErr || res["status"] != "closed" || res["removed"] != float64(4) {
			t.Errorf("caller %d did not hear that the sessions were closed: %v %v", i, isErr, res)
		}
	}
	raw, _ := os.ReadFile(e.audit)
	if n := strings.Count(string(raw), "session_close_requested"); n != 1 {
		t.Errorf("one question is one audit event, got %d", n)
	}
}

func TestAfterARejectionTheAgentCannotAskAgainAtOnce(t *testing.T) {
	e := closeSetup(t, nil)
	e.seed(t)
	out, _ := e.call(t, "session_close", map[string]any{"all": true})
	human(t, e.rec.wait(t, 1), e.dir, "reject", "", "no")
	e.call(t, "session_close", map[string]any{"all": true, "close_id": out["login_id"], "max_block_seconds": 20})
	before := len(e.rec.all())
	res, isErr := e.call(t, "session_close", map[string]any{"all": true})
	if !isErr || res["code"] != "rate_limited" {
		t.Errorf("after the person said no, asking again is refused for a while: %v %v", isErr, res)
	}
	// it is said in words a person and an agent can read: about closing sessions, with no login and no internal key
	msg := fmt.Sprint(res["message"])
	for _, bad := range []string{"login", "securl://", "session-close"} {
		if strings.Contains(msg, bad) {
			t.Errorf("the refusal says %q: %s", bad, msg)
		}
	}
	if !strings.Contains(msg, "declined to close") || !strings.Contains(msg, "retry in") {
		t.Errorf("the refusal says what was declined and when to retry: %s", msg)
	}
	if len(e.rec.all()) != before {
		t.Error("the person was asked again straight after saying no")
	}
}

func TestTheConfirmationIsRecordedWithoutAnythingSecret(t *testing.T) {
	e := closeSetup(t, nil)
	e.seed(t)
	out, _ := e.call(t, "session_close", map[string]any{"all": true})
	e.answer(t, 1, "DELETE")
	e.call(t, "session_close", map[string]any{"all": true, "close_id": out["login_id"], "max_block_seconds": 20})
	raw, err := os.ReadFile(e.audit)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{"session_close_requested", "session_close_confirmed"} {
		if !strings.Contains(s, want) {
			t.Errorf("the audit log lacks %s:\n%s", want, s)
		}
	}
	for _, secret := range []string{"SECRET-SEEDED-COOKIE", "SECRET-DB-PASSWORD", "DELETE\""} {
		if strings.Contains(s, secret) {
			t.Errorf("the audit log holds %q", secret)
		}
	}
}

func TestTheDeclineIsRecorded(t *testing.T) {
	e := closeSetup(t, nil)
	e.seed(t)
	out, _ := e.call(t, "session_close", map[string]any{"all": true})
	human(t, e.rec.wait(t, 1), e.dir, "reject", "", "no")
	e.call(t, "session_close", map[string]any{"all": true, "close_id": out["login_id"], "max_block_seconds": 20})
	raw, _ := os.ReadFile(e.audit)
	if !strings.Contains(string(raw), "session_close_declined") {
		t.Errorf("a refusal is as much a fact as a consent:\n%s", raw)
	}
}

// The agent is not the one who can say yes: nothing in the call's own arguments stands for the person's word.
func TestNoArgumentOfTheCallCanStandInForThePersonsWord(t *testing.T) {
	e := closeSetup(t, nil)
	e.seed(t)
	for _, args := range []map[string]any{
		{"all": true, "confirm": true},
		{"all": true, "confirmed": true},
		{"all": true, "force": true},
		{"all": true, "yes": true},
		{"all": true, "confirm": "DELETE"},
	} {
		res, isErr := e.call(t, "session_close", args)
		if !isErr || res["code"] != "invalid_argument" {
			t.Errorf("%v: an argument that claims consent is refused, not honoured: %v %v", args, isErr, res)
		}
		if got := e.names(t); len(got) != 4 {
			t.Fatalf("%v closed something: %v", args, got)
		}
	}
}

func TestAnUnknownCloseIdIsAnErrorAndClosesNothing(t *testing.T) {
	e := closeSetup(t, nil)
	e.seed(t)
	res, isErr := e.call(t, "session_close", map[string]any{"all": true, "close_id": "cl_does_not_exist", "max_block_seconds": 1})
	if !isErr || res["code"] != "invalid_argument" {
		t.Errorf("%v %v", isErr, res)
	}
	if got := e.names(t); len(got) != 4 {
		t.Errorf("closed: %v", got)
	}
}

// An answer given for one list is not an answer for another: a close_id from a request for one site does not close all of them.
func TestACloseIdOnlyClosesWhatItWasMadeFor(t *testing.T) {
	e := closeSetup(t, nil)
	e.seed(t)
	out, _ := e.call(t, "session_close", map[string]any{"url": "https://gitlab.corp.example"})
	e.answer(t, 1, "DELETE")
	res, isErr := e.call(t, "session_close", map[string]any{"all": true, "close_id": out["login_id"], "max_block_seconds": 20})
	if !isErr || res["code"] != "invalid_argument" {
		t.Errorf("the id was made for one session, and is refused for all: %v %v", isErr, res)
	}
	// the person did confirm gitlab, so it goes; what must not go is anything they were not asked about
	got := e.names(t)
	if len(got) != 3 {
		t.Errorf("the confirmation for one session must close that one and no more: %v", got)
	}
	for _, g := range got {
		if strings.Contains(g, "gitlab") {
			t.Errorf("the confirmed session is still there: %v", got)
		}
	}
}

func TestACloseIdWorksOnceAndNotAgain(t *testing.T) {
	e := closeSetup(t, nil)
	e.seed(t)
	out, _ := e.call(t, "session_close", map[string]any{"url": "https://gitlab.corp.example"})
	e.answer(t, 1, "DELETE")
	args := map[string]any{"url": "https://gitlab.corp.example", "close_id": out["login_id"], "max_block_seconds": 20}
	first, _ := e.call(t, "session_close", args)
	if first["removed"] != float64(1) {
		t.Fatalf("%v", first)
	}
	if err := e.app.SeedSession("https://gitlab.corp.example", "gitlab"); err != nil { // logged in again, later
		t.Fatal(err)
	}
	// using the id again tells what happened then, as an unlock does; it closes nothing that exists now
	second, _ := e.call(t, "session_close", args)
	if second["status"] != "closed" || second["removed"] != float64(1) {
		t.Errorf("a repeated call tells the earlier outcome: %v", second)
	}
	if got := e.names(t); len(got) != 4 {
		t.Errorf("a confirmation that was used closed a later session as well: %v", got)
	}
}

func TestWhileTheVaultIsLockedThereIsNothingToCloseAndNoQuestion(t *testing.T) {
	e := closeSetup(t, nil)
	e.v.Lock()
	out, isErr := e.call(t, "session_close", map[string]any{"all": true})
	if !isErr || out["code"] != "vault_locked" {
		t.Errorf("%v %v", isErr, out)
	}
	if n := len(e.rec.all()); n != 0 {
		t.Errorf("a person was asked about sessions that cannot be reached: %d messages", n)
	}
}

// confirmClose asks to close what args name and answers the question as a person would, on the page.
func (e *closeEnv) confirmClose(t *testing.T, args map[string]any) map[string]any {
	t.Helper()
	first := map[string]any{"max_block_seconds": 1}
	for k, v := range args {
		first[k] = v
	}
	n := len(e.rec.all())
	out, isErr := e.call(t, "session_close", first)
	if isErr || out["status"] != "pending" {
		t.Fatalf("closing is not asked for confirmation: %v %v", isErr, out)
	}
	e.answer(t, n+1, "DELETE")
	next := map[string]any{"close_id": out["login_id"], "max_block_seconds": 20}
	for k, v := range args {
		next[k] = v
	}
	res, isErr := e.call(t, "session_close", next)
	if isErr {
		t.Fatalf("%v", res)
	}
	return res
}

func TestClosingADatabaseTargetForgetsItsAccountAndKeepsTheOtherOfTheSameEngine(t *testing.T) {
	e := closeSetup(t, func(c *config.Config) {
		c.Databases = append(c.Databases, config.Database{Name: "dev-my-ddl", Driver: config.DriverMySQL, Host: "my2.dev.corp.example", Port: 3306, Environment: "dev", Mode: config.ModeReadOnly})
	})
	for _, n := range []string{"dev-my", "dev-my-ddl"} {
		if err := e.app.SeedDatabaseSession(n); err != nil {
			t.Fatal(err)
		}
	}
	if res := e.confirmClose(t, map[string]any{"url": "db://dev-my"}); res["removed"] != float64(1) || res["status"] != "closed" {
		t.Fatalf("%v", res)
	}
	got := e.names(t)
	if len(got) != 1 || got[0] != "db://dev-my-ddl" {
		t.Errorf("only the named target goes; a name that is a prefix of another does not reach it: %v", got)
	}
}

func TestClosingEverythingAfterConfirmationLeavesNothing(t *testing.T) {
	e := closeSetup(t, nil)
	e.seed(t)
	if res := e.confirmClose(t, map[string]any{"all": true}); res["removed"] != float64(4) {
		t.Fatalf("%v", res)
	}
	if got := e.names(t); len(got) != 0 {
		t.Errorf("%v", got)
	}
}

// Asking for a fresh login must not be a way round the question: a session is replaced when the new login has succeeded, and not
// before. Otherwise an agent that calls session_open with force_refresh erases a database account, and the person who rejects
// (or does not answer) the login link has lost it.
func TestAForcedLoginDoesNotEraseTheSavedSessionBeforeTheNewOneExists(t *testing.T) {
	e := closeSetup(t, nil)
	e.seed(t)
	out, isErr := e.call(t, "session_open", map[string]any{"url": "db://dev-pg", "force_refresh": true, "max_block_seconds": 1})
	if isErr || out["status"] != "pending" {
		t.Fatalf("%v %v", isErr, out)
	}
	if got := e.names(t); len(got) != 4 {
		t.Fatalf("the saved session was erased when the new login only began: %v", got)
	}
	human(t, e.rec.wait(t, 1), e.dir, "reject", "", "no")
	e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 20})
	if got := e.names(t); len(got) != 4 {
		t.Errorf("a rejected login must leave the saved session where it was: %v", got)
	}
}
