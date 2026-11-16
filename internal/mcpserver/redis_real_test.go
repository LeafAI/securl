package mcpserver

import (
	"os"
	"strings"
	"testing"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/redissite"
	"github.com/LeafAI/securl/internal/site"
)

// The Redis tools against a real Redis server, when SECURL_TEST_REDIS (no password) and SECURL_TEST_REDIS_PW with
// SECURL_TEST_REDIS_PASSWORD are set (scripts/redistest/up.sh starts both). The rest of the suite runs against a fake.
func withRealRedis(t *testing.T) *gateEnv {
	t.Helper()
	open, withPw, pw := os.Getenv("SECURL_TEST_REDIS"), os.Getenv("SECURL_TEST_REDIS_PW"), os.Getenv("SECURL_TEST_REDIS_PASSWORD")
	if open == "" || withPw == "" || pw == "" {
		t.Skip("SECURL_TEST_REDIS, SECURL_TEST_REDIS_PW and SECURL_TEST_REDIS_PASSWORD are not all set: no real Redis")
	}
	oh, op, _ := strings.Cut(open, ":")
	ph, pp, _ := strings.Cut(withPw, ":")
	g := gateServer(t, "open", func(c *config.Config) {
		c.Security.AllowLocalAddresses = true
		c.Redis = []config.Redis{
			{Name: "open", Host: oh, Port: atoiPort(op), Environment: "dev", TLS: config.TLSDisable, Mode: config.ModeReadWrite},
			{Name: "pw", Host: ph, Port: atoiPort(pp), Environment: "dev", TLS: config.TLSDisable},
		}
	})
	d := g.s.redisDriver()
	g.s.core.cache.Put(redissite.BaseURL("open"), d, &site.Session{Tokens: map[string]string{redissite.TokenPassword: ""}})
	g.s.core.cache.Put(redissite.BaseURL("pw"), d, &site.Session{Tokens: map[string]string{redissite.TokenPassword: pw}})
	return g
}

func TestRealRedisThroughTheToolsReadsAndChangesAndRefuses(t *testing.T) {
	g := withRealRedis(t)
	defer g.call(t, toolRedisExec, map[string]any{"target": "open", "command": []string{"DEL", "rt:s", "rt:l", "rt:h"}, "reason": "cleanup of a test"})
	if out, isErr := g.call(t, toolRedisExec, map[string]any{"target": "open", "command": []string{"SET", "rt:s", "hello"}, "reason": "real test"}); isErr || out["value"] != "OK" {
		t.Fatalf("SET: %v %v", isErr, out)
	}
	g.call(t, toolRedisExec, map[string]any{"target": "open", "command": []string{"RPUSH", "rt:l", "a", "b", "c"}, "reason": "real test"})
	g.call(t, toolRedisExec, map[string]any{"target": "open", "command": []string{"HSET", "rt:h", "f", "v"}, "reason": "real test"})
	for _, tc := range []struct {
		cmd  []string
		want string
	}{
		{[]string{"GET", "rt:s"}, `"value":"hello"`},
		{[]string{"LRANGE", "rt:l", "0", "-1"}, `"value":["a","b","c"]`},
		{[]string{"HGETALL", "rt:h"}, `"value":["f","v"]`},
		{[]string{"TYPE", "rt:h"}, `"value":"hash"`},
		{[]string{"EXISTS", "rt:s", "rt:none"}, `"value":1`},
		{[]string{"TTL", "rt:none"}, `"value":-2`},
	} {
		out, isErr := g.call(t, toolRedisQuery, map[string]any{"target": "open", "command": tc.cmd})
		if isErr || !strings.Contains(raw(out), tc.want) || out["untrusted"] != "true" {
			t.Errorf("%v: %v %v", tc.cmd, isErr, out)
		}
	}
	// refused by the policy, and the real server never sees it
	for _, cmd := range [][]string{{"FLUSHALL"}, {"CONFIG", "GET", "*"}, {"KEYS", "*"}, {"EVAL", "return 1", "0"}} {
		if out, isErr := g.call(t, toolRedisQuery, map[string]any{"target": "open", "command": cmd}); !isErr || out["code"] != "command_not_allowed" {
			t.Errorf("%v: %v %v", cmd, isErr, out)
		}
	}
	if out, _ := g.call(t, toolRedisQuery, map[string]any{"target": "open", "command": []string{"GET", "rt:s"}}); !strings.Contains(raw(out), "hello") {
		t.Errorf("a refused FLUSHALL must not have flushed anything: %v", out)
	}
	// a read-only target with a password: reads work, writes are refused before the server
	if out, isErr := g.call(t, toolRedisQuery, map[string]any{"target": "pw", "command": []string{"PING"}}); isErr || out["value"] != "PONG" {
		t.Errorf("%v %v", isErr, out)
	}
	if out, isErr := g.call(t, toolRedisExec, map[string]any{"target": "pw", "command": []string{"SET", "x", "y"}, "reason": "x"}); !isErr || out["code"] != "target_read_only" {
		t.Errorf("%v %v", isErr, out)
	}
	// a wrong command argument is the server's own error, said without the password
	out, isErr := g.call(t, toolRedisQuery, map[string]any{"target": "open", "command": []string{"LRANGE", "rt:s", "0", "1"}})
	if !isErr || out["code"] != "redis_error" || !strings.Contains(raw(out), "WRONGTYPE") {
		t.Errorf("a command on the wrong type: %v %v", isErr, out)
	}
}

func TestRealRedisThroughTheToolsAWrongPasswordEndsTheSession(t *testing.T) {
	g := withRealRedis(t)
	g.s.core.cache.Put(redissite.BaseURL("pw"), g.s.redisDriver(), &site.Session{Tokens: map[string]string{redissite.TokenPassword: "no-longer-valid"}})
	out, isErr := g.call(t, toolRedisQuery, map[string]any{"target": "pw", "command": []string{"PING"}})
	if !isErr || out["code"] != "session_expired" {
		t.Fatalf("%v %v", isErr, out)
	}
	if _, has := g.s.core.cache.Peek(redissite.Key("pw")); has {
		t.Error("the session of a password the server refused is kept")
	}
	if strings.Contains(raw(out), "no-longer-valid") {
		t.Errorf("%v", out)
	}
}
