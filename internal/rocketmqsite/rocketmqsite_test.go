package rocketmqsite

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/rmq/rmqtest"
	"github.com/LeafAI/securl/internal/site"
)

const (
	ak = "reader1"
	sk = "reader-secret-1"
)

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

func fake(t *testing.T) *rmqtest.Server {
	t.Helper()
	s := rmqtest.New(
		rmqtest.Account{AccessKey: ak, SecretKey: sk, SubTopics: []string{"orders", "payments"}, Groups: []string{"securl-reader"}},
		rmqtest.Account{AccessKey: "writer1", SecretKey: "writer-secret-1"},
		rmqtest.Account{AccessKey: "nogroup", SecretKey: "nogroup-secret", SubTopics: []string{"orders"}},
	)
	t.Cleanup(s.Close)
	s.AddTopic("orders", 2)
	s.AddTopic("payments", 1)
	s.AddGroup("securl-reader")
	s.Put("orders", 0, rmqtest.Message{Body: []byte("one")})
	return s
}

func driverFor(s *rmqtest.Server, mut func(*config.RocketMQ)) *Driver {
	r := config.RocketMQ{Name: "mq", NameServers: []string{s.Addr}, Environment: "dev", Topics: []string{"orders", "payments"}}
	if mut != nil {
		mut(&r)
	}
	cfg := &config.Config{RocketMQ: []config.RocketMQ{r}}
	return New(cfg.RocketMQTarget, Options{AllowLocal: true, Timeout: 2 * time.Second})
}

func login(t *testing.T, d *Driver, key, secret string) (*site.Session, error) {
	t.Helper()
	return d.Login(context.Background(), BaseURL("mq"), &asker{vals: map[string]string{"access_key": key, "secret_key": secret}}, nil)
}

func TestTheKeyOfATargetIsRocketmqColonSlashSlashItsName(t *testing.T) {
	if BaseURL("mq").String() != "rocketmq://mq" || Key("mq") != "rocketmq://mq" {
		t.Errorf("%s %s", BaseURL("mq"), Key("mq"))
	}
}

func TestTheDriverIsNeverMatchedFromAURLSoNoToolReachesAClusterByAccident(t *testing.T) {
	d := driverFor(fake(t), nil)
	for _, raw := range []string{"rocketmq://mq", "http://mq", "https://rocketmq.example/", "tcp://127.0.0.1:9876"} {
		u, _ := url.Parse(raw)
		if d.Match(u) {
			t.Errorf("%s is matched", raw)
		}
	}
	if !d.NeedsLogin() || d.Name() != "rocketmq" {
		t.Errorf("%v %q", d.NeedsLogin(), d.Name())
	}
}

func TestLoginAsksForTheTwoKeysWithTheSecretOneHiddenAndKeepsThem(t *testing.T) {
	d := driverFor(fake(t), nil)
	a := &asker{vals: map[string]string{"access_key": " " + ak + " ", "secret_key": sk}}
	sess, err := d.Login(context.Background(), BaseURL("mq"), a, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sess.Tokens[TokenAccessKey] != ak || sess.Tokens[TokenSecretKey] != sk {
		t.Errorf("%v", sess.Tokens)
	}
	if len(a.got) != 2 || a.got[0].Secret || !a.got[1].Secret || !strings.Contains(a.got[0].Label, "mq") || len([]rune(a.got[0].Label)) > 60 || len([]rune(a.got[1].Label)) > 60 {
		t.Errorf("%+v", a.got)
	}
	if a.given["secret_key"] != "" || a.given["access_key"] != "" {
		t.Errorf("what was typed is left in the answer: %v", a.given)
	}
}

func TestLoginTellsApartWhatWentWrong(t *testing.T) {
	cases := []struct {
		name, key, secret string
		mut               func(*config.RocketMQ)
		want              error
		say               string
	}{
		{"wrong secret", ak, "nope-nope", nil, site.ErrBadCredentials, "refused that AccessKey"},
		{"unknown key", "nobody", "x", nil, site.ErrBadCredentials, "refused that AccessKey"},
		{"a key that may only send", "writer1", "writer-secret-1", nil, site.ErrLoginRejected, "not allowed to read the topic orders"},
		{"a group the key may not use", "nogroup", "nogroup-secret", nil, site.ErrLoginRejected, "consumer group securl-reader"},
		{"a group that does not exist", ak, sk, func(r *config.RocketMQ) { r.ConsumerGroup = "ghost" }, site.ErrLoginRejected, "consumer group ghost"},
		{"a topic that is not on the cluster", ak, sk, func(r *config.RocketMQ) { r.Topics = []string{"missing"} }, site.ErrLoginRejected, "does not exist"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := driverFor(fake(t), tc.mut)
			_, err := login(t, d, tc.key, tc.secret)
			if !errors.Is(err, tc.want) || !strings.Contains(err.Error(), tc.say) {
				t.Fatalf("%v", err)
			}
			for _, leak := range []string{tc.secret, "AclException", "PlainAccessValidator", "127.0.0.1"} {
				if strings.Contains(err.Error(), leak) {
					t.Errorf("the error says %q: %v", leak, err)
				}
			}
		})
	}
}

func TestLoginRefusesWhatCannotBeAKeyBeforeAskingTheCluster(t *testing.T) {
	s := fake(t)
	d := driverFor(s, nil)
	for _, c := range [][2]string{{"", sk}, {ak, ""}, {"a\nb", sk}, {ak, "x\x00y"}, {strings.Repeat("a", maxKeyBytes+1), sk}} {
		if _, err := login(t, d, c[0], c[1]); !errors.Is(err, site.ErrBadCredentials) {
			t.Errorf("%q: %v", c, err)
		}
	}
	if n := len(s.Requests()); n != 0 {
		t.Errorf("the cluster was asked %d times about keys that cannot be keys", n)
	}
}

func TestAnAskerThatFailsEndsTheLoginAsItIs(t *testing.T) {
	d := driverFor(fake(t), nil)
	boom := errors.New("closed")
	if _, err := d.Login(context.Background(), BaseURL("mq"), &asker{err: boom}, nil); !errors.Is(err, boom) {
		t.Errorf("%v", err)
	}
}

func TestAnUnknownTargetAndAForeignKeyAreRefused(t *testing.T) {
	d := driverFor(fake(t), nil)
	for _, u := range []*url.URL{BaseURL("other"), {Scheme: "redis", Host: "mq"}, nil} {
		a := &asker{vals: map[string]string{"access_key": ak, "secret_key": sk}}
		if _, err := d.Login(context.Background(), u, a, nil); !errors.Is(err, site.ErrLoginRejected) || a.calls != 0 {
			t.Errorf("%v: %v (asked %d times)", u, err, a.calls)
		}
		if d.Detail(u) != "" {
			t.Errorf("a detail for %v", u)
		}
	}
}

func TestProbeKeepsTheSessionWhenTheNetworkIsDownAndEndsItWhenTheKeyIsChanged(t *testing.T) {
	s := fake(t)
	d := driverFor(s, nil)
	sess, err := login(t, d, ak, sk)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Probe(context.Background(), BaseURL("mq"), sess, nil); err != nil {
		t.Errorf("a good session is probed bad: %v", err)
	}
	changed := &site.Session{Tokens: map[string]string{TokenAccessKey: ak, TokenSecretKey: "changed"}}
	if err := d.Probe(context.Background(), BaseURL("mq"), changed, nil); !errors.Is(err, site.ErrBadCredentials) || errors.Is(err, site.ErrUnreachable) {
		t.Errorf("%v", err)
	}
	for _, empty := range []*site.Session{nil, {}, {Tokens: map[string]string{TokenAccessKey: ak}}} {
		if err := d.Probe(context.Background(), BaseURL("mq"), empty, nil); !errors.Is(err, site.ErrBadCredentials) {
			t.Errorf("%+v: %v", empty, err)
		}
	}
	s.Close()
	err = d.Probe(context.Background(), BaseURL("mq"), sess, nil)
	if !errors.Is(err, site.ErrUnreachable) || errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("a cluster that is down is not a key that is wrong: %v", err)
	}
}

func TestTheDetailSaysThatTheAgentOnlyReadsAndFromWhichTopics(t *testing.T) {
	d := driverFor(fake(t), nil)
	got := d.Detail(BaseURL("mq"))
	for _, want := range []string{"READ", "orders", "payments", "cannot send", "never sees"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q is not said: %s", want, got)
		}
	}
}

func TestALocalBrokerAddressIsRefusedUnlessTheOwnerAllowsIt(t *testing.T) {
	s := fake(t)
	r := config.RocketMQ{Name: "mq", NameServers: []string{s.Addr}, Environment: "dev", Topics: []string{"orders"}}
	cfg := &config.Config{RocketMQ: []config.RocketMQ{r}}
	d := New(cfg.RocketMQTarget, Options{AllowLocal: false, Timeout: time.Second})
	if _, err := login(t, d, ak, sk); !errors.Is(err, site.ErrLoginRejected) || !strings.Contains(err.Error(), "on this machine") {
		t.Errorf("%v", err)
	}
}

func TestTheClientIsBoundedByWhatTheOwnerAllowsToBeReturned(t *testing.T) {
	cases := []struct {
		body *int
		want int
	}{{nil, 4096}, {ptr(0), 1024}, {ptr(10), 1024}, {ptr(50000), 50000}}
	for _, tc := range cases {
		if got := bodyCeiling(config.RocketMQ{MaxBodyBytes: tc.body}); got != tc.want {
			t.Errorf("%v: %d, want %d", tc.body, got, tc.want)
		}
	}
}

func ptr(n int) *int { return &n }

func TestAnOwnersConsumerGroupIsTheOneUsed(t *testing.T) {
	s := fake(t)
	s.AddGroup("mine")
	d := driverFor(s, func(r *config.RocketMQ) { r.ConsumerGroup = "mine" })
	// the account may use securl-reader only, so the group the owner chose is what is refused, which shows it was the one sent
	_, err := login(t, d, ak, sk)
	if err == nil || !strings.Contains(err.Error(), "consumer group mine") {
		t.Errorf("%v", err)
	}
}

func TestTheOwnersTimeoutBoundsTheLogin(t *testing.T) {
	s := fake(t)
	s.SetDelay(400 * time.Millisecond)
	cfg := &config.Config{RocketMQ: []config.RocketMQ{{Name: "mq", NameServers: []string{s.Addr}, Environment: "dev", Topics: []string{"orders"}, Timeout: 100 * time.Millisecond}}}
	d := New(cfg.RocketMQTarget, Options{AllowLocal: true})
	start := time.Now()
	_, err := login(t, d, ak, sk)
	if !errors.Is(err, site.ErrUnreachable) || !strings.Contains(err.Error(), "did not answer in time") {
		t.Errorf("%v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("the target's timeout was not used: %s", time.Since(start))
	}
}

// What tls: verify, skip-verify and disable each do, checked on a real handshake with a certificate nobody vouches for.
func TestTheTLSModesEachDoWhatTheirNamesSay(t *testing.T) {
	ts := httptest.NewTLSServer(nil)
	defer ts.Close()
	cert := ts.TLS.Certificates[0]
	handshake := func(mode string) (bool, error) {
		d := New((&config.Config{}).RocketMQTarget, Options{})
		o := d.options(config.RocketMQ{TLS: mode})
		if o.TLS == nil {
			return false, nil
		}
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()
		go func() {
			srv := tls.Server(c2, &tls.Config{Certificates: []tls.Certificate{cert}})
			srv.Handshake()
		}()
		c1.SetDeadline(time.Now().Add(3 * time.Second))
		_, err := o.TLS(c1, "broker.example")
		return true, err
	}
	if on, _ := handshake(""); on {
		t.Error("the default is no TLS: RocketMQ's port is plain unless the broker was set up for it")
	}
	if on, _ := handshake(config.TLSDisable); on {
		t.Error("disable still wraps the connection")
	}
	if on, err := handshake(config.TLSVerify); !on || err == nil {
		t.Errorf("verify accepted a certificate nobody vouches for: %v %v", on, err)
	}
	if on, err := handshake(config.TLSSkipVerify); !on || err != nil {
		t.Errorf("skip-verify did not encrypt: %v %v", on, err)
	}
}

// The check at login does what a read does, in the same order: where the topic is, how long a queue is, one pull at its end.
func TestTheLoginCheckDoesWhatAReadDoes(t *testing.T) {
	s := fake(t)
	d := driverFor(s, nil)
	if _, err := login(t, d, ak, sk); err != nil {
		t.Fatal(err)
	}
	got := s.Codes()
	if len(got) != 3 || got[0] != 105 || got[1] != 30 || got[2] != 11 {
		t.Errorf("route, max offset, pull: %v", got)
	}
	for _, q := range s.Requests() {
		if q.Code == 11 && (q.Ext["commitOffset"] != "0" || q.Ext["queueOffset"] != "1") {
			t.Errorf("the pull is at the end of the queue and commits nothing: %v", q.Ext)
		}
	}
}
