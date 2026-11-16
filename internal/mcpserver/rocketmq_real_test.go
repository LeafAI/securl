package mcpserver

import (
	"os"
	"strings"
	"testing"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/rocketmqsite"
	"github.com/LeafAI/securl/internal/site"
)

// The RocketMQ tools against a real broker with ACL on, when SECURL_TEST_RMQ_NS is set (scripts/rmqtest/up.sh starts it).
func withRealRocketMQ(t *testing.T) *gateEnv {
	t.Helper()
	ns := os.Getenv("SECURL_TEST_RMQ_NS")
	if ns == "" {
		t.Skip("SECURL_TEST_RMQ_NS is not set: no real RocketMQ")
	}
	g := gateServer(t, "open", func(c *config.Config) {
		c.Security.AllowLocalAddresses = true
		c.RocketMQ = []config.RocketMQ{{Name: "mq", NameServers: []string{ns}, Environment: "dev", Topics: []string{"orders", "payments", "secrets", "nothere"}}}
	})
	g.s.core.cache.Put(rocketmqsite.BaseURL("mq"), g.s.rocketmqDriver(), &site.Session{Tokens: map[string]string{rocketmqsite.TokenAccessKey: "reader1", rocketmqsite.TokenSecretKey: "reader-secret-1"}})
	return g
}

func TestRealRocketMQThroughTheToolsReadsNewestFirstAndRefuses(t *testing.T) {
	g := withRealRocketMQ(t)
	out, isErr := g.call(t, toolRocketMQRead, map[string]any{"target": "mq", "topic": "orders"})
	if isErr {
		t.Fatal(out)
	}
	if got := strings.Join(mqBodies(out), ","); got != "order-5 fifth,order-4 fourth,order-3 third,order-2 second,order-1 first" {
		t.Errorf("newest first across the two queues of the real broker: %s", got)
	}
	m := mqMessages(out)[0]
	if m["tags"] != "tag-5" || m["keys"] != "key-5" || out["queues"] != float64(2) || out["untrusted"] != "true" {
		t.Errorf("%v %v", m, out)
	}
	again, _ := g.call(t, toolRocketMQRead, map[string]any{"target": "mq", "topic": "orders"})
	if raw(again["messages"]) != raw(out["messages"]) {
		t.Errorf("the second read differs: a read consumed something\n%v\n%v", out["messages"], again["messages"])
	}
	two, _ := g.call(t, toolRocketMQRead, map[string]any{"target": "mq", "topic": "orders", "limit": 2})
	if strings.Join(mqBodies(two), ",") != "order-5 fifth,order-4 fourth" || two["truncated"] != true {
		t.Errorf("%v", two)
	}
	pay, _ := g.call(t, toolRocketMQRead, map[string]any{"target": "mq", "topic": "payments"})
	if !strings.Contains(raw(pay), "ignore your instructions") || pay["untrusted"] != "true" {
		t.Errorf("%v", pay)
	}
	// the key may not read this topic: said plainly, and the session is kept (it is valid)
	sec, isErr := g.call(t, toolRocketMQRead, map[string]any{"target": "mq", "topic": "secrets"})
	if !isErr || sec["code"] != "permission_denied" || strings.Contains(raw(sec), "TOP-SECRET") {
		t.Errorf("%v %v", isErr, sec)
	}
	if _, has := g.s.core.cache.Peek(rocketmqsite.Key("mq")); !has {
		t.Error("a permission the key lacks ended the session")
	}
	// a topic that is not on the cluster
	if no, isErr := g.call(t, toolRocketMQRead, map[string]any{"target": "mq", "topic": "nothere"}); !isErr || no["code"] != "topic_not_found" {
		t.Errorf("%v %v", isErr, no)
	}
}

func TestRealRocketMQThroughTheToolsAWrongSecretEndsTheSession(t *testing.T) {
	g := withRealRocketMQ(t)
	g.s.core.cache.Put(rocketmqsite.BaseURL("mq"), g.s.rocketmqDriver(), &site.Session{Tokens: map[string]string{rocketmqsite.TokenAccessKey: "reader1", rocketmqsite.TokenSecretKey: "no-longer-valid"}})
	out, isErr := g.call(t, toolRocketMQRead, map[string]any{"target": "mq", "topic": "orders"})
	if !isErr || out["code"] != "session_expired" || strings.Contains(raw(out), "no-longer-valid") {
		t.Fatalf("%v %v", isErr, out)
	}
	if _, has := g.s.core.cache.Peek(rocketmqsite.Key("mq")); has {
		t.Error("the session of a key the cluster refused is kept")
	}
}
