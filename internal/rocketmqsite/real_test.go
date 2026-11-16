package rocketmqsite

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/site"
)

// A real RocketMQ with ACL on (scripts/rmqtest/up.sh); skipped without SECURL_TEST_RMQ_NS.
func realDriver(t *testing.T, mut func(*config.RocketMQ)) *Driver {
	t.Helper()
	ns := os.Getenv("SECURL_TEST_RMQ_NS")
	if ns == "" {
		t.Skip("SECURL_TEST_RMQ_NS is not set: no real RocketMQ to test against")
	}
	r := config.RocketMQ{Name: "mq", NameServers: []string{ns}, Environment: "dev", Topics: []string{"orders", "payments"}}
	if mut != nil {
		mut(&r)
	}
	cfg := &config.Config{RocketMQ: []config.RocketMQ{r}}
	return New(cfg.RocketMQTarget, Options{AllowLocal: true, Timeout: 8 * time.Second})
}

func TestRealBrokerLoginProbeAndTheWaysItRefuses(t *testing.T) {
	d := realDriver(t, nil)
	ctx := context.Background()
	sess, err := login(t, d, "reader1", "reader-secret-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Probe(ctx, BaseURL("mq"), sess, nil); err != nil {
		t.Errorf("%v", err)
	}
	if _, err := login(t, d, "reader1", "nope-nope"); !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("a wrong secret: %v", err)
	}
	if _, err := login(t, d, "writer1", "writer-secret-1"); !errors.Is(err, site.ErrLoginRejected) {
		t.Errorf("a key that may only send: %v", err)
	}
	if err := d.Probe(ctx, BaseURL("mq"), &site.Session{Tokens: map[string]string{TokenAccessKey: "reader1", TokenSecretKey: "changed"}}, nil); !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("a changed secret: %v", err)
	}
	ghost := realDriver(t, func(r *config.RocketMQ) { r.ConsumerGroup = "no-such-group" })
	if _, err := login(t, ghost, "reader1", "reader-secret-1"); !errors.Is(err, site.ErrLoginRejected) {
		t.Errorf("a group that is not there: %v", err)
	}
}
