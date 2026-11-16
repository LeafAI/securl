package redisx

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// These tests talk to a real Redis, and run only when SECURL_TEST_REDIS (host:port of one without a password) and
// SECURL_TEST_REDIS_PW (host:port of one that wants the password SECURL_TEST_REDIS_PASSWORD) are set. scripts/redistest/up.sh
// starts both. Without them they are skipped, and the fake in redistest is what the suite runs against.
func real(t *testing.T, env string) string {
	t.Helper()
	a := os.Getenv(env)
	if a == "" {
		t.Skipf("%s is not set: no real Redis to test against", env)
	}
	return a
}

func realConn(t *testing.T, addr string, cr Credentials) *Conn {
	t.Helper()
	c, err := Open(context.Background(), addr, cr, Options{AllowLocal: true, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestRealRedisAnswersTheCommandsTheAgentMayRun(t *testing.T) {
	c := realConn(t, real(t, "SECURL_TEST_REDIS"), Credentials{})
	ctx := context.Background()
	c.Do(ctx, "SET", "t:str", "hello")
	c.Do(ctx, "HSET", "t:h", "f1", "v1", "f2", "v2")
	c.Do(ctx, "DEL", "t:l")
	c.Do(ctx, "RPUSH", "t:l", "a", "b", "c")
	defer c.Do(ctx, "DEL", "t:str", "t:h", "t:l")
	for _, tc := range []struct {
		cmd  []string
		want any
	}{
		{[]string{"GET", "t:str"}, "hello"},
		{[]string{"GET", "t:none"}, nil},
		{[]string{"TYPE", "t:h"}, "hash"},
		{[]string{"EXISTS", "t:str", "t:h", "t:none"}, int64(2)},
		{[]string{"LRANGE", "t:l", "0", "-1"}, []any{"a", "b", "c"}},
		{[]string{"LLEN", "t:l"}, int64(3)},
		{[]string{"TTL", "t:str"}, int64(-1)},
		{[]string{"TTL", "t:none"}, int64(-2)},
		{[]string{"MGET", "t:str", "t:none"}, []any{"hello", nil}},
		{[]string{"STRLEN", "t:str"}, int64(5)},
		{[]string{"HLEN", "t:h"}, int64(2)},
	} {
		if err := Check(tc.cmd, ModeRead); err != nil {
			t.Errorf("%v: the policy refused it: %v", tc.cmd, err)
			continue
		}
		got, err := c.Do(ctx, tc.cmd[0], tc.cmd[1:]...)
		if err != nil || !equal(got, tc.want) {
			t.Errorf("%v: got %#v (%v), want %#v", tc.cmd, got, err, tc.want)
		}
	}
	h, err := c.Do(ctx, "HGETALL", "t:h")
	if a, ok := h.([]any); err != nil || !ok || len(a) != 4 {
		t.Errorf("HGETALL: %#v %v", h, err)
	}
	r, err := c.Do(ctx, "SCAN", "0", "MATCH", "t:*", "COUNT", "100")
	if a, ok := r.([]any); err != nil || !ok || len(a) != 2 {
		t.Errorf("SCAN: %#v %v", r, err)
	}
}

func TestRealRedisAnswersABinarySafeValueByItsLength(t *testing.T) {
	c := realConn(t, real(t, "SECURL_TEST_REDIS"), Credentials{})
	val := "a\r\nb\x00c\xff$5\r\nd"
	if _, err := c.Do(context.Background(), "SET", "t:bin", val); err != nil {
		t.Fatal(err)
	}
	defer c.Do(context.Background(), "DEL", "t:bin")
	got, err := c.Do(context.Background(), "GET", "t:bin")
	if err != nil || got != val {
		t.Errorf("%q %v", got, err)
	}
}

// What the real server says to a command it does not know, and to the wrong number of arguments, is an error reply and not a broken
// connection.
func TestRealRedisErrorRepliesLeaveTheConnectionUsable(t *testing.T) {
	c := realConn(t, real(t, "SECURL_TEST_REDIS"), Credentials{})
	ctx := context.Background()
	_, err := c.Do(ctx, "NOSUCHCOMMAND")
	var re *ReplyError
	if !errors.As(err, &re) || !strings.Contains(strings.ToLower(re.Message), "unknown command") {
		t.Fatalf("%v", err)
	}
	if _, err := c.Do(ctx, "GET"); !errors.As(err, &re) || !strings.Contains(strings.ToLower(re.Message), "wrong number") {
		t.Errorf("%v", err)
	}
	if v, err := c.Do(ctx, "PING"); err != nil || v != "PONG" {
		t.Errorf("the connection is fine after error replies: %v %v", v, err)
	}
	if _, err := c.Do(ctx, "SET", "t:x", "1"); err != nil {
		t.Fatal(err)
	}
	defer c.Do(ctx, "DEL", "t:x")
	if _, err := c.Do(ctx, "LPUSH", "t:x", "a"); !errors.As(err, &re) || !strings.Contains(re.Message, "WRONGTYPE") {
		t.Errorf("a command on the wrong type: %v", err)
	}
}

func TestRealRedisAcceptsThePasswordAndRefusesAWrongOne(t *testing.T) {
	addr := real(t, "SECURL_TEST_REDIS_PW")
	pw := os.Getenv("SECURL_TEST_REDIS_PASSWORD")
	if pw == "" {
		t.Skip("SECURL_TEST_REDIS_PASSWORD is not set")
	}
	c := realConn(t, addr, Credentials{Password: pw})
	if v, err := c.Do(context.Background(), "PING"); err != nil || v != "PONG" {
		t.Errorf("%v %v", v, err)
	}
	_, err := Open(context.Background(), addr, Credentials{Password: "wrong-" + pw}, Options{AllowLocal: true, Timeout: 5 * time.Second})
	if !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("%v", err)
	}
	if strings.Contains(err.Error(), pw) || strings.Contains(err.Error(), "wrong-") {
		t.Errorf("the error repeats a password: %v", err)
	}
	// none given to a server that wants one
	if _, err := Open(context.Background(), addr, Credentials{}, Options{AllowLocal: true, Timeout: 5 * time.Second}); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("no password where one is needed: %v", err)
	}
	// a password given to a server that has none
	if _, err := Open(context.Background(), real(t, "SECURL_TEST_REDIS"), Credentials{Password: "x"}, Options{AllowLocal: true, Timeout: 5 * time.Second}); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("a password where none is set: %v", err)
	}
}

// A real server must refuse nothing the policy allows and the policy must refuse what a real server would run: here the commands a
// policy refuses are NOT sent, and a flush that was refused did not happen.
func TestRealRedisIsUntouchedByWhatThePolicyRefuses(t *testing.T) {
	c := realConn(t, real(t, "SECURL_TEST_REDIS"), Credentials{})
	ctx := context.Background()
	c.Do(ctx, "SET", "t:keep", "me")
	defer c.Do(ctx, "DEL", "t:keep")
	for _, cmd := range [][]string{{"FLUSHALL"}, {"FLUSHDB"}, {"CONFIG", "SET", "maxmemory", "1"}, {"SHUTDOWN"}, {"EVAL", "return redis.call('flushall')", "0"}, {"KEYS", "*"}, {"DEBUG", "SLEEP", "5"}} {
		if err := Check(cmd, ModeWrite); err == nil {
			t.Errorf("%v was allowed in write mode", cmd)
		}
	}
	if v, err := c.Do(ctx, "GET", "t:keep"); err != nil || v != "me" {
		t.Errorf("the data is still there: %v %v", v, err)
	}
}

func TestRealRedisAReplyOverTheLimitIsRefusedAndTheConnectionIsNotUsedAgain(t *testing.T) {
	addr := real(t, "SECURL_TEST_REDIS")
	c, err := Open(context.Background(), addr, Credentials{}, Options{AllowLocal: true, Timeout: 5 * time.Second, MaxReply: 1000})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Do(context.Background(), "SET", "t:big", strings.Repeat("x", 5000))
	defer func() {
		c2 := realConn(t, addr, Credentials{})
		c2.Do(context.Background(), "DEL", "t:big")
	}()
	if _, err := c.Do(context.Background(), "GET", "t:big"); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("%v", err)
	}
	if _, err := c.Do(context.Background(), "PING"); !errors.Is(err, ErrClosed) {
		t.Errorf("%v", err)
	}
}
