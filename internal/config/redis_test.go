package config

import (
	"strings"
	"testing"
	"time"
)

const goodRedis = `
redis:
  - name: cache-dev
    host: redis.dev.corp.example
    environment: dev
`

func TestARedisTargetIsReadFromTheConfigurationWithSafeDefaults(t *testing.T) {
	c, err := parseDB(t, goodRedis)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Redis) != 1 {
		t.Fatalf("%d targets", len(c.Redis))
	}
	r, ok := c.RedisTarget("cache-dev")
	if !ok || r.Host != "redis.dev.corp.example" || r.PortOrDefault() != 6379 || r.Environment != "dev" {
		t.Fatalf("%+v", r)
	}
	if r.Writable() {
		t.Error("a target is read-only unless it says otherwise")
	}
	if r.TLSMode() != TLSVerify {
		t.Errorf("the default must verify the certificate: %q", r.TLSMode())
	}
	if r.ItemLimit() != 1000 || r.ReplyLimit() != 1<<20 || r.CommandTimeoutOrDefault() != 10*time.Second {
		t.Errorf("defaults: %d %d %s", r.ItemLimit(), r.ReplyLimit(), r.CommandTimeoutOrDefault())
	}
	if r.Addr() != "redis.dev.corp.example:6379" {
		t.Errorf("%s", r.Addr())
	}
}

func TestARedisTargetThatTakesChangesSaysSo(t *testing.T) {
	c, err := parseDB(t, "redis:\n  - {name: r, host: h.example, environment: test, mode: read_write, username: app, port: 6380, tls: skip-verify, max_items: 50, max_reply_bytes: 4096, command_timeout: 3s}\n")
	if err != nil {
		t.Fatal(err)
	}
	r, _ := c.RedisTarget("r")
	if !r.Writable() || r.Username != "app" || r.PortOrDefault() != 6380 || r.TLSMode() != TLSSkipVerify || r.ItemLimit() != 50 || r.ReplyLimit() != 4096 || r.CommandTimeoutOrDefault() != 3*time.Second {
		t.Errorf("%+v", r)
	}
	if r.Addr() != "h.example:6380" {
		t.Errorf("%s", r.Addr())
	}
}

func TestARedisTargetThatIsMalformedIsRefused(t *testing.T) {
	for name, y := range map[string]string{
		"no name":            "redis:\n  - {host: h.example, environment: dev}\n",
		"bad name":           "redis:\n  - {name: 'a b', host: h.example, environment: dev}\n",
		"name too long":      "redis:\n  - {name: " + strings.Repeat("a", 65) + ", host: h.example, environment: dev}\n",
		"no host":            "redis:\n  - {name: a, environment: dev}\n",
		"host with a port":   "redis:\n  - {name: a, host: 'h.example:6379', environment: dev}\n",
		"host with a scheme": "redis:\n  - {name: a, host: 'redis://h.example', environment: dev}\n",
		"host with a user":   "redis:\n  - {name: a, host: 'u@h.example', environment: dev}\n",
		"no environment":     "redis:\n  - {name: a, host: h.example}\n",
		"production":         "redis:\n  - {name: a, host: h.example, environment: production}\n",
		"prod":               "redis:\n  - {name: a, host: h.example, environment: prod}\n",
		"bad mode":           "redis:\n  - {name: a, host: h.example, environment: dev, mode: rw}\n",
		"bad tls":            "redis:\n  - {name: a, host: h.example, environment: dev, tls: maybe}\n",
		"port 0 negative":    "redis:\n  - {name: a, host: h.example, environment: dev, port: -1}\n",
		"port too big":       "redis:\n  - {name: a, host: h.example, environment: dev, port: 70000}\n",
		"duplicate":          "redis:\n  - {name: a, host: h.example, environment: dev}\n  - {name: a, host: g.example, environment: dev}\n",
		"items negative":     "redis:\n  - {name: a, host: h.example, environment: dev, max_items: -1}\n",
		"items over hard":    "redis:\n  - {name: a, host: h.example, environment: dev, max_items: 100001}\n",
		"reply over hard":    "redis:\n  - {name: a, host: h.example, environment: dev, max_reply_bytes: 67108865}\n",
		"timeout over hard":  "redis:\n  - {name: a, host: h.example, environment: dev, command_timeout: 10m}\n",
		"timeout negative":   "redis:\n  - {name: a, host: h.example, environment: dev, command_timeout: -1s}\n",
		"username with line": "redis:\n  - {name: a, host: h.example, environment: dev, username: \"a\\nb\"}\n",
		"username too long":  "redis:\n  - {name: a, host: h.example, environment: dev, username: " + strings.Repeat("u", 65) + "}\n",
	} {
		if _, err := parseDB(t, y); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
}

// A password is typed on a page and kept in the vault. A file that has one is refused, and the refusal does not repeat it.
func TestARedisTargetWithAPasswordInTheFileIsRefusedWithoutEchoingIt(t *testing.T) {
	for _, key := range []string{"password", "pass", "auth", "requirepass", "secret", "token", "url", "uri"} {
		y := "redis:\n  - {name: a, host: h.example, environment: dev, " + key + ": hunter2-VERY-secret}\n"
		err := ParseStrict([]byte(y))
		if err == nil {
			t.Errorf("%s: a credential in the file was accepted", key)
			continue
		}
		if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%s: the error repeats it: %v", key, err)
		}
	}
}

func TestOnlyAnExactNameFindsARedisTarget(t *testing.T) {
	c, _ := parseDB(t, goodRedis)
	for _, n := range []string{"", "CACHE-DEV", "cache-dev ", "cache", "cache-dev2", "../cache-dev"} {
		if _, ok := c.RedisTarget(n); ok {
			t.Errorf("%q found a target", n)
		}
	}
}

// What a person is shown is checked with the same rule as the file, so a question and the file can never disagree.
func TestARedisHostIsOnlyAHostNotAnAddressWithMore(t *testing.T) {
	for _, h := range []string{"10.0.0.5", "redis", "redis.dev-1.corp.example", "::1"} {
		if _, err := parseDB(t, "redis:\n  - {name: a, host: '"+h+"', environment: dev}\n"); err != nil {
			t.Errorf("%s: %v", h, err)
		}
	}
}
