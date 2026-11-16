package redissite

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/site"
)

// Real Redis, when SECURL_TEST_REDIS (no password) and SECURL_TEST_REDIS_PW with SECURL_TEST_REDIS_PASSWORD are set.
func realDriver(t *testing.T, env string) *Driver {
	t.Helper()
	a := os.Getenv(env)
	if a == "" {
		t.Skipf("%s is not set: no real Redis to test against", env)
	}
	host, port, _ := strings.Cut(a, ":")
	cfg := &config.Config{Redis: []config.Redis{{Name: "cache", Host: host, Port: atoi(port), Environment: "dev", TLS: config.TLSDisable}}}
	return New(cfg.RedisTarget, Options{AllowLocal: true, Timeout: 5 * time.Second})
}

func TestRealRedisLoginWithAPasswordAndAWrongOne(t *testing.T) {
	d := realDriver(t, "SECURL_TEST_REDIS_PW")
	pw := os.Getenv("SECURL_TEST_REDIS_PASSWORD")
	if pw == "" {
		t.Skip("SECURL_TEST_REDIS_PASSWORD is not set")
	}
	sess, err := d.Login(context.Background(), BaseURL("cache"), &asker{vals: map[string]string{"password": pw}}, nil)
	if err != nil || sess.Tokens[TokenPassword] != pw {
		t.Fatalf("%v", err)
	}
	if err := d.Probe(context.Background(), BaseURL("cache"), sess, nil); err != nil {
		t.Errorf("%v", err)
	}
	c, err := d.Open(context.Background(), BaseURL("cache"), sess)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if v, err := c.Do(context.Background(), "PING"); err != nil || v != "PONG" {
		t.Errorf("%v %v", v, err)
	}
	if _, err := d.Login(context.Background(), BaseURL("cache"), &asker{vals: map[string]string{"password": "wrong-" + pw}}, nil); !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("%v", err)
	}
	if err := d.Probe(context.Background(), BaseURL("cache"), &site.Session{Tokens: map[string]string{TokenPassword: "changed"}}, nil); !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("%v", err)
	}
}

// The page does not take an empty field, so a person whose server has no password types a space, which is read as none.
func TestRealRedisWithNoPasswordIsLoggedInToWithASpace(t *testing.T) {
	d := realDriver(t, "SECURL_TEST_REDIS")
	sess, err := d.Login(context.Background(), BaseURL("cache"), &asker{vals: map[string]string{"password": " "}}, nil)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if sess.Tokens[TokenPassword] != "" {
		t.Errorf("%v", sess.Tokens)
	}
	if err := d.Probe(context.Background(), BaseURL("cache"), sess, nil); err != nil {
		t.Errorf("%v", err)
	}
	// and a real password given to a server that has none is refused, not taken as fine
	if _, err := d.Login(context.Background(), BaseURL("cache"), &asker{vals: map[string]string{"password": "something"}}, nil); !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("%v", err)
	}
}
