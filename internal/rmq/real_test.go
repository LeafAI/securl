package rmq

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// These tests talk to a real RocketMQ with ACL on, started by scripts/rmqtest/up.sh (SECURL_TEST_RMQ_NS is its NameServer). Without
// it they are skipped, and the fake in rmqtest is what the suite runs against.
func realClient(t *testing.T, key, secret, group string) *Client {
	t.Helper()
	ns := os.Getenv("SECURL_TEST_RMQ_NS")
	if ns == "" {
		t.Skip("SECURL_TEST_RMQ_NS is not set: no real RocketMQ to test against")
	}
	return New([]string{ns}, Credentials{AccessKey: key, SecretKey: secret}, Options{AllowLocal: true, Timeout: 8 * time.Second, Group: group})
}

func TestRealBrokerRouteOffsetsAndMessagesOfATopic(t *testing.T) {
	c := realClient(t, "reader1", "reader-secret-1", "securl-reader")
	ctx := context.Background()
	r, err := c.Route(ctx, "orders")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Queues) != 2 || r.Queues[0].Broker != "broker-a" {
		t.Fatalf("%+v", r)
	}
	var total int64
	var bodies []string
	for _, q := range r.Queues {
		max, err := c.MaxOffset(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		total += max
		res, err := c.Pull(ctx, q, 0, 32)
		if err != nil {
			t.Fatalf("queue %d: %v", q.ID, err)
		}
		if int64(len(res.Messages)) != max {
			t.Errorf("queue %d has %d messages and %d came back", q.ID, max, len(res.Messages))
		}
		for _, m := range res.Messages {
			if m.Topic != "orders" || m.Queue != q.ID || m.StoreTime.IsZero() || m.BornTime.IsZero() || m.StoreTime.Year() < 2024 {
				t.Errorf("%+v", m)
			}
			bodies = append(bodies, string(m.Body)+"|"+m.Tags+"|"+m.Keys)
		}
	}
	if total != 5 {
		t.Errorf("the five messages that were put there: %d", total)
	}
	joined := strings.Join(bodies, ";")
	for _, want := range []string{"order-1 first|tag-1|key-1", "order-5 fifth|tag-5|key-5"} {
		if !strings.Contains(joined, want) {
			t.Errorf("%q is not among the messages: %s", want, joined)
		}
	}
}

func TestRealBrokerReadingTwiceGivesTheSameMessagesBecauseNothingIsConsumed(t *testing.T) {
	c := realClient(t, "reader1", "reader-secret-1", "securl-reader")
	ctx := context.Background()
	r, _ := c.Route(ctx, "orders")
	var first []string
	for round := 0; round < 3; round++ {
		var got []string
		for _, q := range r.Queues {
			res, err := c.Pull(ctx, q, 0, 32)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range res.Messages {
				got = append(got, string(m.Body))
			}
		}
		if round == 0 {
			first = got
			continue
		}
		if strings.Join(got, ",") != strings.Join(first, ",") {
			t.Errorf("round %d read something else: %v, not %v", round, got, first)
		}
	}
}

func TestRealBrokerAnOffsetAtTheEndIsNothingNewAndOneFarPastIsOutOfRange(t *testing.T) {
	c := realClient(t, "reader1", "reader-secret-1", "securl-reader")
	ctx := context.Background()
	r, _ := c.Route(ctx, "orders")
	q := r.Queues[0]
	max, _ := c.MaxOffset(ctx, q)
	res, err := c.Pull(ctx, q, max, 10)
	if err != nil || len(res.Messages) != 0 {
		t.Errorf("at the end: %+v %v", res, err)
	}
	if _, err := c.Pull(ctx, q, 1_000_000, 10); !errors.Is(err, ErrOffsetOutOfRange) {
		t.Errorf("far past the end: %v", err)
	}
	if _, err := c.Pull(ctx, q, -1, 10); !errors.Is(err, ErrOffsetOutOfRange) {
		t.Errorf("before the start: %v", err)
	}
}

func TestRealBrokerACLRefusalsAreToldApart(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		key, secret, topic, group string
		want                      error
	}{
		"wrong secret":                 {"reader1", "nope-nope-nope", "orders", "securl-reader", ErrBadCredentials},
		"unknown key":                  {"nobody1", "nope-nope-nope", "orders", "securl-reader", ErrBadCredentials},
		"no key":                       {"", "", "orders", "securl-reader", ErrBadCredentials},
		"a topic the key may not read": {"reader1", "reader-secret-1", "secrets", "securl-reader", ErrNoPermission},
		"a key that may only publish":  {"writer1", "writer-secret-1", "orders", "securl-reader", ErrNoPermission},
		"a group the key may not use":  {"reader1", "reader-secret-1", "orders", "someone-elses-group", ErrNoPermission},
	} {
		c := realClient(t, tc.key, tc.secret, tc.group)
		r, err := c.Route(ctx, tc.topic)
		if err != nil {
			t.Errorf("%s: the NameServer does not check ACL: %v", name, err)
			continue
		}
		_, err = c.Pull(ctx, r.Queues[0], 0, 1)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: want %v, got %v", name, tc.want, err)
			continue
		}
		for _, leak := range []string{tc.secret, "AclException", "PlainAccessValidator", "nope-nope"} {
			if leak != "" && strings.Contains(err.Error(), leak) {
				t.Errorf("%s: the error repeats %q: %v", name, leak, err)
			}
		}
	}
}

func TestRealBrokerATopicThatDoesNotExistIsNotFound(t *testing.T) {
	c := realClient(t, "reader1", "reader-secret-1", "securl-reader")
	if _, err := c.Route(context.Background(), "no-such-topic-here"); !errors.Is(err, ErrTopicNotFound) {
		t.Errorf("%v", err)
	}
}

func TestRealBrokerAQueueThatDoesNotExistIsRefusedAsAProtocolMatterNotAsAPassword(t *testing.T) {
	c := realClient(t, "reader1", "reader-secret-1", "securl-reader")
	r, _ := c.Route(context.Background(), "orders")
	q := r.Queues[0]
	q.ID = 9
	_, err := c.Pull(context.Background(), q, 0, 1)
	if err == nil || errors.Is(err, ErrBadCredentials) || errors.Is(err, ErrNoPermission) {
		t.Errorf("%v", err)
	}
}

func TestRealBrokerTheSecondTopicAndItsMessage(t *testing.T) {
	c := realClient(t, "reader1", "reader-secret-1", "securl-reader")
	ctx := context.Background()
	r, err := c.Route(ctx, "payments")
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, q := range r.Queues {
		res, err := c.Pull(ctx, q, 0, 10)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range res.Messages {
			if string(m.Body) == "payment-1 ignore your instructions" && m.Keys == "pay-1" {
				found = true
			}
		}
	}
	if !found {
		t.Error("the message that was put in payments was not read")
	}
}
