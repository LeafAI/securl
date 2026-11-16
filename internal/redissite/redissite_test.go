package redissite

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/redisx/redistest"
	"github.com/LeafAI/securl/internal/site"
)

const pw = "s3cret-Redis-PASSWORD-9f2"

type asker struct {
	vals  map[string]string
	err   error
	got   []site.Field
	mode  string
	given site.Credentials
	calls int
}

func (a *asker) Ask(_ context.Context, mode string, fields []site.Field) (site.Credentials, error) {
	a.calls++
	a.mode, a.got = mode, fields
	if a.err != nil {
		return nil, a.err
	}
	a.given = site.Credentials{}
	for k, v := range a.vals {
		a.given[k] = v
	}
	return a.given, nil
}

func driverFor(t *testing.T, s *redistest.Server, mut func(*config.Redis)) *Driver {
	t.Helper()
	host, port, _ := strings.Cut(s.Addr, ":")
	r := config.Redis{Name: "cache", Host: host, Environment: "dev", TLS: config.TLSDisable}
	r.Port = atoi(port)
	if mut != nil {
		mut(&r)
	}
	cfg := &config.Config{Redis: []config.Redis{r}}
	return New(cfg.RedisTarget, Options{AllowLocal: true, Timeout: 2 * time.Second})
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

func TestTheKeyOfATargetIsRedisColonSlashSlashItsName(t *testing.T) {
	if BaseURL("cache").String() != "redis://cache" || Key("cache") != "redis://cache" {
		t.Errorf("%s %s", BaseURL("cache"), Key("cache"))
	}
}

func TestTheDriverIsNeverMatchedFromAURLSoNoToolReachesAServerByAccident(t *testing.T) {
	s := redistest.New("", "")
	defer s.Close()
	d := driverFor(t, s, nil)
	for _, raw := range []string{"redis://cache", "http://cache", "https://redis.example/", "tcp://127.0.0.1:6379"} {
		u, _ := url.Parse(raw)
		if d.Match(u) {
			t.Errorf("%s is matched: a server is chosen by name, never recognised from a URL", raw)
		}
	}
	if !d.NeedsLogin() || d.Name() != "redis" {
		t.Errorf("%v %q", d.NeedsLogin(), d.Name())
	}
}

func TestLoginAsksForThePasswordAloneOnASecretFieldAndChecksItAgainstTheServer(t *testing.T) {
	s := redistest.New("", pw)
	defer s.Close()
	d := driverFor(t, s, nil)
	a := &asker{vals: map[string]string{"password": pw}}
	sess, err := d.Login(context.Background(), BaseURL("cache"), a, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.mode != "custom" || len(a.got) != 1 || a.got[0].Name != "password" || !a.got[0].Secret {
		t.Errorf("one secret field, in custom mode: %q %+v", a.mode, a.got)
	}
	if sess.Tokens[TokenPassword] != pw || sess.Tokens[TokenUsername] != "" {
		t.Errorf("%v", sess.Tokens)
	}
	if a.given["password"] != "" {
		t.Error("the typed password is wiped from the map the page handed over")
	}
	if got := s.Names(); len(got) < 1 || got[0] != "AUTH" {
		t.Errorf("the password was checked by authenticating: %v", got)
	}
}

// An ACL user is a name in the configuration; the page then asks for the user's password, and the user is kept with it.
func TestATargetWithAnACLUserAuthenticatesAsThatUser(t *testing.T) {
	s := redistest.New("alice", pw)
	defer s.Close()
	d := driverFor(t, s, func(r *config.Redis) { r.Username = "alice" })
	a := &asker{vals: map[string]string{"password": pw}}
	sess, err := d.Login(context.Background(), BaseURL("cache"), a, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sess.Tokens[TokenUsername] != "alice" || sess.Tokens[TokenPassword] != pw {
		t.Errorf("%v", sess.Tokens)
	}
	if !strings.Contains(a.got[0].Label, "alice") {
		t.Errorf("the page says whose password: %q", a.got[0].Label)
	}
	if cmds := s.Commands(); len(cmds) < 1 || len(cmds[0]) != 3 || cmds[0][1] != "alice" {
		t.Errorf("%v", cmds)
	}
}

func TestAServerWithNoPasswordAsksForNoneAndKeepsNone(t *testing.T) {
	s := redistest.New("", "")
	defer s.Close()
	d := driverFor(t, s, nil)
	a := &asker{vals: map[string]string{"password": ""}}
	sess, err := d.Login(context.Background(), BaseURL("cache"), a, nil)
	if err != nil {
		t.Fatalf("a server without a password is logged in to with an empty one: %v", err)
	}
	if sess.Tokens[TokenPassword] != "" {
		t.Errorf("%v", sess.Tokens)
	}
	for _, n := range s.Names() {
		if n == "AUTH" {
			t.Error("AUTH was sent to a server that has no password")
		}
	}
}

func TestAWrongPasswordIsBadCredentialsAndNothingIsKept(t *testing.T) {
	s := redistest.New("", pw)
	defer s.Close()
	d := driverFor(t, s, nil)
	sess, err := d.Login(context.Background(), BaseURL("cache"), &asker{vals: map[string]string{"password": "wrong-" + pw}}, nil)
	if !errors.Is(err, site.ErrBadCredentials) || sess != nil {
		t.Fatalf("%v %v", sess, err)
	}
	for _, leak := range []string{pw, "wrong-", "127.0.0.1"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("the error repeats %q: %v", leak, err)
		}
	}
}

func TestAnUnreachableServerIsUnreachableAndSaysNothingOfTheAddress(t *testing.T) {
	s := redistest.New("", pw)
	d := driverFor(t, s, nil)
	s.Close()
	_, err := d.Login(context.Background(), BaseURL("cache"), &asker{vals: map[string]string{"password": pw}}, nil)
	if !errors.Is(err, site.ErrUnreachable) {
		t.Fatalf("%v", err)
	}
	for _, leak := range []string{pw, "127.0.0.1"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("the error repeats %q: %v", leak, err)
		}
	}
}

func TestAKeyThatIsNotAConfiguredTargetIsRefusedBeforeAnyoneIsAsked(t *testing.T) {
	s := redistest.New("", "")
	defer s.Close()
	d := driverFor(t, s, nil)
	for _, base := range []*url.URL{BaseURL("nope"), {Scheme: "db", Host: "cache"}, {Scheme: "https", Host: "cache"}, nil} {
		a := &asker{vals: map[string]string{"password": "x"}}
		if _, err := d.Login(context.Background(), base, a, nil); !errors.Is(err, site.ErrLoginRejected) {
			t.Errorf("%v: %v", base, err)
		}
		if a.calls != 0 {
			t.Errorf("%v: the person was asked", base)
		}
	}
	if n := len(s.Commands()); n != 0 {
		t.Errorf("%d commands reached the server for a target that is not configured", n)
	}
}

func TestAPageThatFailsIsTheCallersErrorAndNothingIsKept(t *testing.T) {
	s := redistest.New("", pw)
	defer s.Close()
	d := driverFor(t, s, nil)
	boom := errors.New("rejected by the person")
	if sess, err := d.Login(context.Background(), BaseURL("cache"), &asker{err: boom}, nil); !errors.Is(err, boom) || sess != nil {
		t.Errorf("%v %v", sess, err)
	}
	if n := len(s.Commands()); n != 0 {
		t.Errorf("%d commands were sent although nobody typed a password", n)
	}
}

func TestAPasswordWithAControlCharacterIsRefusedBeforeItIsSent(t *testing.T) {
	s := redistest.New("", pw)
	defer s.Close()
	d := driverFor(t, s, nil)
	for _, bad := range []string{"a\r\nb", "x\x00y", strings.Repeat("p", 600)} {
		if _, err := d.Login(context.Background(), BaseURL("cache"), &asker{vals: map[string]string{"password": bad}}, nil); !errors.Is(err, site.ErrBadCredentials) {
			t.Errorf("%q: %v", bad[:min(len(bad), 8)], err)
		}
	}
	if n := len(s.Commands()); n != 0 {
		t.Errorf("%d commands were sent with a password that cannot be one", n)
	}
}

// A kept session is probed by authenticating again: a password that was changed ends the session, as a cookie that the site no
// longer knows would, and a network that is down says nothing about it.
func TestProbeKeepsASessionTheServerStillAcceptsAndEndsOneItRefuses(t *testing.T) {
	s := redistest.New("", pw)
	defer s.Close()
	d := driverFor(t, s, nil)
	good := &site.Session{Tokens: map[string]string{TokenPassword: pw}}
	if err := d.Probe(context.Background(), BaseURL("cache"), good, nil); err != nil {
		t.Errorf("%v", err)
	}
	bad := &site.Session{Tokens: map[string]string{TokenPassword: "changed-" + pw}}
	if err := d.Probe(context.Background(), BaseURL("cache"), bad, nil); !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("a password the server no longer accepts ends the session: %v", err)
	}
	s.Close()
	if err := d.Probe(context.Background(), BaseURL("cache"), good, nil); !errors.Is(err, site.ErrUnreachable) || errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("a server that is down is not a wrong password: %v", err)
	}
}

func TestProbeRefusesASessionWithNoPasswordWhereOneIsNeededButNotWhereNoneIs(t *testing.T) {
	s := redistest.New("", pw)
	defer s.Close()
	d := driverFor(t, s, nil)
	if err := d.Probe(context.Background(), BaseURL("cache"), nil, nil); !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("%v", err)
	}
	if err := d.Probe(context.Background(), BaseURL("cache"), &site.Session{Tokens: map[string]string{}}, nil); !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("a session that holds nothing: %v", err)
	}
	if err := d.Probe(context.Background(), BaseURL("gone"), &site.Session{Tokens: map[string]string{TokenPassword: pw}}, nil); !errors.Is(err, site.ErrLoginRejected) {
		t.Errorf("a target that was removed from the configuration: %v", err)
	}
}

func TestADriverWithNoPasswordSessionIsKeptForAServerThatNeedsNone(t *testing.T) {
	s := redistest.New("", "")
	defer s.Close()
	d := driverFor(t, s, nil)
	empty := &site.Session{Tokens: map[string]string{TokenPassword: ""}}
	if err := d.Probe(context.Background(), BaseURL("cache"), empty, nil); err != nil {
		t.Errorf("a session for a server that has no password is not a missing one: %v", err)
	}
}

func TestOpenGivesAConnectionForASessionAndRefusesOneWithoutCredentials(t *testing.T) {
	s := redistest.New("", pw)
	defer s.Close()
	d := driverFor(t, s, nil)
	c, err := d.Open(context.Background(), BaseURL("cache"), &site.Session{Tokens: map[string]string{TokenPassword: pw}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if v, err := c.Do(context.Background(), "PING"); err != nil || v != "PONG" {
		t.Errorf("%v %v", v, err)
	}
	if _, err := d.Open(context.Background(), BaseURL("cache"), nil); !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("%v", err)
	}
	if _, err := d.Open(context.Background(), BaseURL("nope"), &site.Session{Tokens: map[string]string{TokenPassword: pw}}); !errors.Is(err, site.ErrLoginRejected) {
		t.Errorf("%v", err)
	}
}

// The message to the person says, in securl's own words, what the password will let an agent do, and by name.
func TestTheDetailSaysWhatThePasswordWillLetAnAgentDo(t *testing.T) {
	s := redistest.New("", "")
	defer s.Close()
	ro := driverFor(t, s, nil)
	got := ro.Detail(BaseURL("cache"))
	for _, want := range []string{"cache", "vault", "read", "never sees"} {
		if !strings.Contains(got, want) {
			t.Errorf("the detail does not say %q: %s", want, got)
		}
	}
	if strings.Contains(got, "change data") {
		t.Errorf("a read-only target does not say it changes data: %s", got)
	}
	rw := driverFor(t, s, func(r *config.Redis) { r.Mode = config.ModeReadWrite })
	if got := rw.Detail(BaseURL("cache")); !strings.Contains(got, "change data") {
		t.Errorf("a writable target says so: %s", got)
	}
	if ro.Detail(BaseURL("nope")) != "" || ro.Detail(nil) != "" {
		t.Error("an unknown target has no detail")
	}
}

func TestTheLabelFitsWhatThePageShowsAndNamesTheTarget(t *testing.T) {
	s := redistest.New("", "")
	defer s.Close()
	long := strings.Repeat("a", 64)
	d := driverFor(t, s, func(r *config.Redis) { r.Name = long; r.Username = strings.Repeat("u", 64) })
	a := &asker{vals: map[string]string{"password": ""}}
	d.Login(context.Background(), BaseURL(long), a, nil)
	if len(a.got) != 1 {
		t.Fatal(a.got)
	}
	if n := len([]rune(a.got[0].Label)); n > 60 {
		t.Errorf("%q is %d characters, the page cuts at 60", a.got[0].Label, n)
	}
	a2 := &asker{vals: map[string]string{"password": ""}}
	s2 := redistest.New("", "")
	defer s2.Close()
	driverFor(t, s2, nil).Login(context.Background(), BaseURL("cache"), a2, nil)
	if !strings.Contains(a2.got[0].Label, "cache") {
		t.Errorf("the label names the target: %q", a2.got[0].Label)
	}
}

// The page does not take an empty field, so a person whose server has no password types a space, which is read as none; and a
// password that is only spaces is none, while one with spaces in it is kept exactly as typed.
func TestASpaceMeansNoPasswordAndASpaceInsideAPasswordIsKept(t *testing.T) {
	s := redistest.New("", "")
	defer s.Close()
	d := driverFor(t, s, nil)
	sess, err := d.Login(context.Background(), BaseURL("cache"), &asker{vals: map[string]string{"password": "   "}}, nil)
	if err != nil || sess.Tokens[TokenPassword] != "" {
		t.Fatalf("%v %v", sess, err)
	}
	if got := normalizePassword(" a b "); got != " a b " {
		t.Errorf("a password with spaces is kept as typed: %q", got)
	}
	s2 := redistest.New("", "has space in it")
	defer s2.Close()
	sess2, err := driverFor(t, s2, nil).Login(context.Background(), BaseURL("cache"), &asker{vals: map[string]string{"password": "has space in it"}}, nil)
	if err != nil || sess2.Tokens[TokenPassword] != "has space in it" {
		t.Errorf("%v %v", sess2, err)
	}
}

func TestAPasswordAtTheLimitIsAllowedAndOneOverIsNot(t *testing.T) {
	if !validPassword(strings.Repeat("p", maxPasswordBytes)) || validPassword(strings.Repeat("p", maxPasswordBytes+1)) {
		t.Error("the limit is exact")
	}
	if validPassword("a\x7fb") || validPassword("a\tb") || !validPassword("üñí©ødé-密码") {
		t.Error("control characters are refused and other text is not")
	}
}

func TestATimeoutIsUnreachableAndNotAWrongPassword(t *testing.T) {
	s := redistest.New("", pw)
	defer s.Close()
	d := driverFor(t, s, nil)
	d.opt.Timeout = 150 * time.Millisecond
	s.SetSlow(make(chan struct{}))
	_, err := d.Login(context.Background(), BaseURL("cache"), &asker{vals: map[string]string{"password": pw}}, nil)
	if !errors.Is(err, site.ErrUnreachable) || errors.Is(err, site.ErrBadCredentials) {
		t.Fatalf("a silent server is unreachable, not a refusal: %v", err)
	}
	if !strings.Contains(err.Error(), "in time") {
		t.Errorf("it says it did not answer in time: %v", err)
	}
}

// A server on this machine is refused unless the owner allows local addresses, and the person is told it is a matter of policy and
// not that the password was wrong.
func TestAServerOnThisMachineIsRefusedUnlessAllowedAndSaysSo(t *testing.T) {
	s := redistest.New("", pw)
	defer s.Close()
	d := driverFor(t, s, nil)
	d.opt.AllowLocal = false
	_, err := d.Login(context.Background(), BaseURL("cache"), &asker{vals: map[string]string{"password": pw}}, nil)
	if !errors.Is(err, site.ErrLoginRejected) || errors.Is(err, site.ErrBadCredentials) || errors.Is(err, site.ErrUnreachable) {
		t.Fatalf("%v", err)
	}
	if !strings.Contains(err.Error(), "on this machine") {
		t.Errorf("%v", err)
	}
	if n := len(s.Commands()); n != 0 {
		t.Errorf("%d commands reached a server that should not have been dialled", n)
	}
}

// Probe judges the session by what it holds and by the target it belongs to, before it dials anything.
func TestProbeRefusesAnUnknownTargetBeforeDialling(t *testing.T) {
	s := redistest.New("", pw)
	defer s.Close()
	d := driverFor(t, s, nil)
	if err := d.Probe(context.Background(), BaseURL("gone"), &site.Session{Tokens: map[string]string{TokenPassword: pw}}, nil); !errors.Is(err, site.ErrLoginRejected) {
		t.Errorf("%v", err)
	}
	if n := len(s.Commands()); n != 0 {
		t.Errorf("the server was dialled for a target that is not configured: %d commands", n)
	}
	// a session that never held a password key at all is not the same as one for a server with none: the key is what says so
	if err := d.Probe(context.Background(), BaseURL("cache"), &site.Session{Tokens: map[string]string{TokenUsername: "a"}}, nil); !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("%v", err)
	}
	if n := len(s.Commands()); n != 0 {
		t.Errorf("the server was dialled with a session that holds no password entry: %d commands", n)
	}
}

func TestTheDetailNamesTheACLUserWhenThereIsOne(t *testing.T) {
	s := redistest.New("", "")
	defer s.Close()
	d := driverFor(t, s, func(r *config.Redis) { r.Username = "alice" })
	if got := d.Detail(BaseURL("cache")); !strings.Contains(got, "as the user alice") {
		t.Errorf("%s", got)
	}
	if got := driverFor(t, s, nil).Detail(BaseURL("cache")); strings.Contains(got, "as the user") {
		t.Errorf("a target without a user does not name one: %s", got)
	}
}

// The reply limit of the target is what the connection is held to, and the target's own timeout is what bounds a command when the
// driver was given none.
func TestTheConnectionIsHeldToTheTargetsOwnReplyLimitAndTimeout(t *testing.T) {
	s := redistest.New("", "")
	defer s.Close()
	s.SetString("big", strings.Repeat("x", 5000))
	d := driverFor(t, s, func(r *config.Redis) { r.MaxReplyBytes = 1000; r.CommandTimeout = 150 * time.Millisecond })
	d.opt.Timeout = 0
	c, err := d.Open(context.Background(), BaseURL("cache"), &site.Session{Tokens: map[string]string{TokenPassword: ""}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Do(context.Background(), "GET", "big"); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Errorf("the target's reply limit holds: %v", err)
	}
	c2, _ := d.Open(context.Background(), BaseURL("cache"), &site.Session{Tokens: map[string]string{TokenPassword: ""}})
	defer c2.Close()
	s.SetSlow(make(chan struct{}))
	start := time.Now()
	if _, err := c2.Do(context.Background(), "GET", "k"); err == nil || time.Since(start) > 2*time.Second {
		t.Errorf("the target's timeout holds: %v after %s", err, time.Since(start))
	}
}

// A password that is too long to be one is cut off at the label, never at the field: the page cuts a label, the driver cuts a name.
func TestALongNameIsCutWithDotsAndAShortOneIsNot(t *testing.T) {
	if got := label("cache", ""); got != "Redis password for cache" {
		t.Errorf("%q", got)
	}
	long := label(strings.Repeat("n", 100), "")
	if len([]rune(long)) != 60 || !strings.HasSuffix(long, "...") {
		t.Errorf("%q (%d)", long, len([]rune(long)))
	}
}
