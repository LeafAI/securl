package rmq

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/rmq/rmqtest"
)

const (
	ak = "reader1"
	sk = "reader-secret-1"
)

func fake(t *testing.T) *rmqtest.Server {
	t.Helper()
	s := rmqtest.New(
		rmqtest.Account{AccessKey: ak, SecretKey: sk, SubTopics: []string{"orders", "payments", "zip", "bomb", "v", "p"}, Groups: []string{"securl-reader"}},
		rmqtest.Account{AccessKey: "writer1", SecretKey: "writer-secret-1", Groups: nil},
	)
	t.Cleanup(s.Close)
	s.AddTopic("orders", 2)
	s.AddTopic("payments", 1)
	s.AddTopic("secrets", 1)
	s.AddGroup("securl-reader")
	for i, b := range []string{"first", "second", "third"} {
		s.Put("orders", i%2, rmqtest.Message{Body: []byte("order-" + b), Tags: "t" + b, Keys: "k" + b})
	}
	s.Put("payments", 0, rmqtest.Message{Body: []byte("payment-1")})
	s.Put("secrets", 0, rmqtest.Message{Body: []byte("TOP-SECRET")})
	return s
}

func open(t *testing.T, s *rmqtest.Server, key, secret string) *Client {
	t.Helper()
	return New([]string{s.Addr}, Credentials{AccessKey: key, SecretKey: secret}, Options{AllowLocal: true, Timeout: 3 * time.Second, Group: "securl-reader"})
}

func TestTheRouteOfATopicNamesItsBrokerAndQueues(t *testing.T) {
	s := fake(t)
	r, err := open(t, s, ak, sk).Route(context.Background(), "orders")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Queues) != 2 || r.Queues[0].Broker != "broker-a" || r.Queues[0].Addr != s.Addr || r.Queues[0].ID != 0 || r.Queues[1].ID != 1 {
		t.Errorf("%+v", r)
	}
}

// Pinned to values that RocketMQ's own class (AclUtils.calSignature, from the 5.3.1 broker's jar, run in a JVM) produced for the same
// input, so that the algorithm cannot be changed in the client and in the fake at once and still pass.
func TestThePinnedSignatureIsTheOneTheBrokersOwnClassMakes(t *testing.T) {
	ext := map[string]string{"AccessKey": "reader1", "topic": "orders", "queueId": "0", "consumerGroup": "securl-reader"}
	if got, want := rmqtest.Sign(ext, nil, "reader-secret-1"), "4A1XvB69Z8m+qCfDFLSbApNIs8E="; got != want {
		t.Errorf("without a body: %q, want %q", got, want)
	}
	if got, want := rmqtest.Sign(ext, []byte("the-body"), "reader-secret-1"), "WGKDClnQBUMZvhzg4wWjUNQh41k="; got != want {
		t.Errorf("with a body: %q, want %q", got, want)
	}
	if got, want := sign(ext, nil, "reader-secret-1"), "4A1XvB69Z8m+qCfDFLSbApNIs8E="; got != want {
		t.Errorf("the client's own: %q, want %q", got, want)
	}
	withSig := map[string]string{"AccessKey": "reader1", "topic": "orders", "queueId": "0", "consumerGroup": "securl-reader", "Signature": "ignored"}
	if got := sign(withSig, nil, "reader-secret-1"); got != "4A1XvB69Z8m+qCfDFLSbApNIs8E=" {
		t.Errorf("an existing Signature is not part of what is signed: %q", got)
	}
}

// A NameServer's route is not valid JSON: its integer keys are not quoted ({0:"127.0.0.1:10911"}). It is read as it is sent.
func TestARouteWithUnquotedIntegerKeysIsRead(t *testing.T) {
	got, err := parseRoute([]byte(`{"brokerDatas":[{"brokerAddrs":{0:"10.0.0.1:10911",1:"10.0.0.2:10911"},"brokerName":"b1","cluster":"c"}],"queueDatas":[{"brokerName":"b1","perm":6,"readQueueNums":3,"writeQueueNums":3}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Queues) != 3 || got.Queues[0].Addr != "10.0.0.1:10911" {
		t.Errorf("the master (id 0) is the one that is read: %+v", got)
	}
	for _, bad := range []string{``, `{`, `[]`, `{"brokerDatas":[]}`, `{"brokerDatas":[{"brokerAddrs":{},"brokerName":"b"}],"queueDatas":[{"brokerName":"b","readQueueNums":1}]}`,
		`{"brokerDatas":[{"brokerAddrs":{0:"x"},"brokerName":"b"}],"queueDatas":[{"brokerName":"b","readQueueNums":99999}]}`} {
		if r, err := parseRoute([]byte(bad)); err == nil {
			t.Errorf("%q was accepted: %+v", bad, r)
		}
	}
}

func TestATopicThatDoesNotExistIsSaidSo(t *testing.T) {
	s := fake(t)
	_, err := open(t, s, ak, sk).Route(context.Background(), "nope")
	if !errors.Is(err, ErrTopicNotFound) {
		t.Fatalf("%v", err)
	}
}

func TestMessagesAreReadFromAQueueOldestFirstWithEverythingTheyCarry(t *testing.T) {
	s := fake(t)
	c := open(t, s, ak, sk)
	r, _ := c.Route(context.Background(), "orders")
	res, err := c.Pull(context.Background(), r.Queues[0], 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Messages) != 2 || res.MaxOffset != 2 || res.MinOffset != 0 {
		t.Fatalf("%+v", res)
	}
	m := res.Messages[0]
	if string(m.Body) != "order-first" || m.Topic != "orders" || m.Queue != 0 || m.QueueOffset != 0 || m.Tags != "tfirst" || m.Keys != "kfirst" || m.StoreTime.IsZero() || m.BornTime.IsZero() {
		t.Errorf("%+v", m)
	}
	if string(res.Messages[1].Body) != "order-third" || res.Messages[1].QueueOffset != 1 {
		t.Errorf("%+v", res.Messages[1])
	}
}

func TestMaxOffsetsAreReadPerQueue(t *testing.T) {
	s := fake(t)
	c := open(t, s, ak, sk)
	r, _ := c.Route(context.Background(), "orders")
	for i, want := range []int64{2, 1} {
		got, err := c.MaxOffset(context.Background(), r.Queues[i])
		if err != nil || got != want {
			t.Errorf("queue %d: %d %v, want %d", i, got, err, want)
		}
	}
}

func TestReadingNeverConsumesAnythingSoTheSameMessagesComeBackAgain(t *testing.T) {
	s := fake(t)
	c := open(t, s, ak, sk)
	r, _ := c.Route(context.Background(), "orders")
	for i := 0; i < 3; i++ {
		res, err := c.Pull(context.Background(), r.Queues[0], 0, 10)
		if err != nil || len(res.Messages) != 2 {
			t.Fatalf("read %d: %+v %v", i, res, err)
		}
	}
	for _, q := range s.Requests() {
		if q.Code == 11 {
			if q.Ext["commitOffset"] != "0" {
				t.Errorf("a pull commits an offset (%s): it would move the group, and take messages from the people who consume them", q.Ext["commitOffset"])
			}
			if sys := q.Ext["sysFlag"]; sys != "4" {
				t.Errorf("the system flag of a pull is 4 (the subscription is sent) and never 1 (commit offset) or 2 (suspend): %s", sys)
			}
			if q.Ext["suspendTimeoutMillis"] != "0" {
				t.Errorf("a pull must not wait on the broker: %s", q.Ext["suspendTimeoutMillis"])
			}
		}
	}
}

func TestAPullIsSentWithTheGroupAndTheSubscriptionAnEmptyGroupBrokerNeeds(t *testing.T) {
	s := fake(t)
	c := open(t, s, ak, sk)
	r, _ := c.Route(context.Background(), "orders")
	c.Pull(context.Background(), r.Queues[0], 0, 7)
	for _, q := range s.Requests() {
		if q.Code != 11 {
			continue
		}
		for k, want := range map[string]string{"consumerGroup": "securl-reader", "topic": "orders", "queueId": "0", "queueOffset": "0", "maxMsgNums": "7", "subscription": "*", "expressionType": "TAG", "subVersion": "0"} {
			if q.Ext[k] != want {
				t.Errorf("%s = %q, want %q", k, q.Ext[k], want)
			}
		}
	}
}

func TestAnOffsetAtTheEndOfAQueueIsNothingNewAndNotAnError(t *testing.T) {
	s := fake(t)
	c := open(t, s, ak, sk)
	r, _ := c.Route(context.Background(), "orders")
	res, err := c.Pull(context.Background(), r.Queues[0], 2, 10)
	if err != nil || len(res.Messages) != 0 || res.MaxOffset != 2 {
		t.Errorf("%+v %v", res, err)
	}
}

func TestAnOffsetFarPastTheEndOrBeforeTheStartIsClampedToTheQueue(t *testing.T) {
	s := fake(t)
	c := open(t, s, ak, sk)
	r, _ := c.Route(context.Background(), "orders")
	for _, off := range []int64{1000, -1} {
		res, err := c.Pull(context.Background(), r.Queues[0], off, 10)
		if !errors.Is(err, ErrOffsetOutOfRange) {
			t.Errorf("offset %d: %v", off, err)
			continue
		}
		if res.MaxOffset != 2 || res.MinOffset != 0 {
			t.Errorf("the queue's own bounds come back with it: %+v", res)
		}
	}
}

func TestACLRefusalsAreToldApartAndNeverRepeatTheSecretOrTheKey(t *testing.T) {
	s := fake(t)
	for name, tc := range map[string]struct {
		key, secret, topic string
		want               error
	}{
		"wrong secret":                 {ak, "nope-nope-nope", "orders", ErrBadCredentials},
		"unknown key":                  {"nobody1", "nope-nope-nope", "orders", ErrBadCredentials},
		"no key at all":                {"", "", "orders", ErrBadCredentials},
		"a topic the key may not read": {ak, sk, "secrets", ErrNoPermission},
		"a key that may only publish":  {"writer1", "writer-secret-1", "orders", ErrNoPermission},
	} {
		c := open(t, s, tc.key, tc.secret)
		r, err := c.Route(context.Background(), tc.topic)
		if err != nil {
			t.Errorf("%s: the route comes from the NameServer, which does not check ACL: %v", name, err)
			continue
		}
		_, err = c.Pull(context.Background(), r.Queues[0], 0, 1)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: want %v, got %v", name, tc.want, err)
			continue
		}
		for _, leak := range []string{tc.secret, "nope-nope", "AclException", "PlainAccessValidator", tc.key} {
			if leak != "" && strings.Contains(err.Error(), leak) {
				t.Errorf("%s: the error repeats %q: %v", name, leak, err)
			}
		}
	}
}

// The group is the one place a consumer's right is checked on the broker besides the topic: a key that may not use the group is
// refused as a permission, not taken for a wrong password.
func TestAGroupTheKeyMayNotUseIsAPermissionErrorNotABadPassword(t *testing.T) {
	s := fake(t)
	c := New([]string{s.Addr}, Credentials{AccessKey: ak, SecretKey: sk}, Options{AllowLocal: true, Timeout: 3 * time.Second, Group: "someone-elses-group"})
	r, _ := c.Route(context.Background(), "orders")
	if _, err := c.Pull(context.Background(), r.Queues[0], 0, 1); !errors.Is(err, ErrNoPermission) {
		t.Errorf("%v", err)
	}
}

func TestAGroupThatDoesNotExistOnTheBrokerIsSaidSo(t *testing.T) {
	s := fake(t)
	c := New([]string{s.Addr}, Credentials{AccessKey: ak, SecretKey: sk}, Options{AllowLocal: true, Timeout: 3 * time.Second, Group: "securl-reader"})
	s.AddGroup("securl-reader") // exists: fine
	r, _ := c.Route(context.Background(), "orders")
	if _, err := c.Pull(context.Background(), r.Queues[0], 0, 1); err != nil {
		t.Errorf("%v", err)
	}
}

// The signature is the broker's own algorithm, and the request is accepted by a fake that checks it: here the same request is signed
// by hand, byte for byte, and what the client sends is compared with it.
func TestTheSignatureIsTheBase64OfHmacSHA1OverTheSortedValuesAndTheBody(t *testing.T) {
	s := fake(t)
	c := open(t, s, ak, sk)
	r, _ := c.Route(context.Background(), "orders")
	c.Pull(context.Background(), r.Queues[0], 0, 1)
	var pull *rmqtest.Request
	for _, q := range s.Requests() {
		if q.Code == 11 {
			q := q
			pull = &q
		}
	}
	if pull == nil {
		t.Fatal("no pull")
	}
	if pull.Ext["AccessKey"] != ak || pull.Ext["Signature"] == "" {
		t.Fatalf("%v", pull.Ext)
	}
	if want := rmqtest.Sign(pull.Ext, nil, sk); pull.Ext["Signature"] != want {
		t.Errorf("signature %q, want %q", pull.Ext["Signature"], want)
	}
	// and one pinned to a value the broker's own class produced (see TestThePinnedSignatureIsTheOneTheBrokersOwnClassMakes)
}

func TestNoRequestToTheNameServerIsSignedAndEveryOneToTheBrokerIs(t *testing.T) {
	s := fake(t)
	c := open(t, s, ak, sk)
	r, _ := c.Route(context.Background(), "orders")
	c.MaxOffset(context.Background(), r.Queues[0])
	c.Pull(context.Background(), r.Queues[0], 0, 1)
	for _, q := range s.Requests() {
		if q.Code == 105 && q.Signed {
			t.Error("a route request was signed: the NameServer is not given the key")
		}
		if (q.Code == 30 || q.Code == 11) && !q.Signed {
			t.Errorf("request %d to the broker was not signed", q.Code)
		}
	}
}

func TestAnUnreachableNameServerIsUnreachableAndSaysNothingOfTheAddress(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	c := New([]string{addr}, Credentials{AccessKey: ak, SecretKey: sk}, Options{AllowLocal: true, Timeout: time.Second, Group: "g"})
	_, err := c.Route(context.Background(), "orders")
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("%v", err)
	}
	for _, leak := range []string{"127.0.0.1", sk, ak} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("the error repeats %q: %v", leak, err)
		}
	}
}

func TestTheNextNameServerIsTriedWhenOneDoesNotAnswer(t *testing.T) {
	s := fake(t)
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := dead.Addr().String()
	dead.Close()
	c := New([]string{deadAddr, s.Addr}, Credentials{AccessKey: ak, SecretKey: sk}, Options{AllowLocal: true, Timeout: time.Second, Group: "securl-reader"})
	if _, err := c.Route(context.Background(), "orders"); err != nil {
		t.Fatalf("%v", err)
	}
}

func TestATopicThatOneNameServerDoesNotKnowIsNotTriedOnTheOthers(t *testing.T) {
	s := fake(t)
	s2 := fake(t)
	c := New([]string{s.Addr, s2.Addr}, Credentials{AccessKey: ak, SecretKey: sk}, Options{AllowLocal: true, Timeout: time.Second, Group: "securl-reader"})
	if _, err := c.Route(context.Background(), "nope"); !errors.Is(err, ErrTopicNotFound) {
		t.Fatalf("%v", err)
	}
	if n := len(s2.Requests()); n != 0 {
		t.Errorf("a NameServer's answer that the topic does not exist is the answer: %d requests went on", n)
	}
}

func TestASlowBrokerIsATimeoutAndNotABadPassword(t *testing.T) {
	s := fake(t)
	c := New([]string{s.Addr}, Credentials{AccessKey: ak, SecretKey: sk}, Options{AllowLocal: true, Timeout: 200 * time.Millisecond, Group: "securl-reader"})
	r, err := c.Route(context.Background(), "orders")
	if err != nil {
		t.Fatal(err)
	}
	s.SetSlow(make(chan struct{}))
	start := time.Now()
	_, err = c.Pull(context.Background(), r.Queues[0], 0, 1)
	if !errors.Is(err, ErrTimeout) || errors.Is(err, ErrBadCredentials) || time.Since(start) > 3*time.Second {
		t.Errorf("%v after %s", err, time.Since(start))
	}
}

func TestAContextThatIsCancelledStopsTheCallAndSendsNothing(t *testing.T) {
	s := fake(t)
	c := open(t, s, ak, sk)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Route(ctx, "orders"); err == nil {
		t.Error("a cancelled call was made")
	}
	if n := len(s.Requests()); n != 0 {
		t.Errorf("%d requests were sent on a cancelled context", n)
	}
}

// What a hostile or broken server sends must never make the client allocate what it names.
func TestAFrameThatIsTooBigOrTooSmallOrNotJSONIsRefusedWithoutAllocatingIt(t *testing.T) {
	for name, raw := range map[string][]byte{
		"a length of two gigabytes":  {0x7f, 0xff, 0xff, 0xff, 0, 0, 0, 2, '{', '}'},
		"a length of zero":           {0, 0, 0, 0},
		"a length that is a few":     {0, 0, 0, 2, 0, 0},
		"a header longer than frame": {0, 0, 0, 8, 0, 0, 0xff, 0xff, '{', '}', 0, 0},
		"the other serialization":    {0, 0, 0, 8, 1, 0, 0, 4, 0, 0, 0, 0},
		"a header that is not JSON":  append([]byte{0, 0, 0, 12, 0, 0, 0, 8}, []byte("notjson!")...),
	} {
		s := fake(t)
		s.SetRaw(105, raw)
		c := open(t, s, ak, sk)
		if _, err := c.Route(context.Background(), "orders"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAReplyBodyOverTheLimitIsRefused(t *testing.T) {
	s := fake(t)
	for i := 0; i < 50; i++ {
		s.Put("payments", 0, rmqtest.Message{Body: bytes.Repeat([]byte("x"), 4000)})
	}
	c := New([]string{s.Addr}, Credentials{AccessKey: ak, SecretKey: sk}, Options{AllowLocal: true, Timeout: time.Second, Group: "securl-reader", MaxReply: 20_000})
	r, _ := c.Route(context.Background(), "payments")
	if _, err := c.Pull(context.Background(), r.Queues[0], 0, 32); !errors.Is(err, ErrTooLarge) {
		t.Errorf("%v", err)
	}
}

func TestAddressesOnThisMachineAreRefusedUnlessAllowed(t *testing.T) {
	s := fake(t)
	c := New([]string{s.Addr}, Credentials{AccessKey: ak, SecretKey: sk}, Options{Timeout: time.Second, Group: "securl-reader"})
	if _, err := c.Route(context.Background(), "orders"); !errors.Is(err, ErrLocalAddress) {
		t.Fatalf("%v", err)
	}
	if n := len(s.Requests()); n != 0 {
		t.Errorf("%d requests reached an address that should not have been dialled", n)
	}
}

// A route names the broker's address, and the NameServer is somebody else's server: an address on this machine in it is the same
// attack as a local NameServer, so the broker address is held to the same rule.
func TestABrokerAddressThatTheRouteNamesIsHeldToTheSameRule(t *testing.T) {
	s := fake(t)
	other := fake(t)
	s.SetRouteAddr(other.Addr) // a route that points at another server on this machine
	c := New([]string{s.Addr}, Credentials{AccessKey: ak, SecretKey: sk}, Options{AllowLocal: true, Timeout: time.Second, Group: "securl-reader"})
	r, _ := c.Route(context.Background(), "orders")
	if _, err := c.Pull(context.Background(), r.Queues[0], 0, 1); err != nil {
		t.Errorf("allowed: %v", err)
	}
	c2 := New([]string{s.Addr}, Credentials{AccessKey: ak, SecretKey: sk}, Options{Timeout: time.Second, Group: "securl-reader"})
	if _, err := c2.Route(context.Background(), "orders"); !errors.Is(err, ErrLocalAddress) {
		t.Errorf("%v", err)
	}
	// a route may name only a host and a port
	s.SetRouteAddr("http://evil.example/x")
	c3 := New([]string{s.Addr}, Credentials{AccessKey: ak, SecretKey: sk}, Options{AllowLocal: true, Timeout: time.Second, Group: "securl-reader"})
	if _, err := c3.Route(context.Background(), "orders"); err == nil {
		t.Error("a route that names a URL as an address was accepted")
	}
}

func TestACompressedBodyIsInflatedAndOneThatCannotBeIsLeftAsItIs(t *testing.T) {
	s := fake(t)
	s.AddTopic("zip", 1)
	s.Put("zip", 0, rmqtest.Message{Body: []byte("a body that was compressed"), Compressed: true})
	s.Put("zip", 0, rmqtest.Message{Body: []byte("another"), Compressed: true, Compression: 0x300})
	s.Put("zip", 0, rmqtest.Message{Body: []byte("lz4 body"), Compressed: true, Compression: 0x100})
	s.Put("zip", 0, rmqtest.Message{Body: []byte("zstd body"), Compressed: true, Compression: 0x200})
	c := open(t, s, ak, sk)
	r, _ := c.Route(context.Background(), "zip")
	res, err := c.Pull(context.Background(), r.Queues[0], 0, 10)
	if err != nil || len(res.Messages) != 4 {
		t.Fatalf("%+v %v", res, err)
	}
	if string(res.Messages[0].Body) != "a body that was compressed" || string(res.Messages[1].Body) != "another" {
		t.Errorf("%q %q", res.Messages[0].Body, res.Messages[1].Body)
	}
	for i, name := range []string{"lz4", "zstd"} {
		m := res.Messages[2+i]
		if m.BodyUnreadable == "" || len(m.Body) != 0 {
			t.Errorf("%s: a body this client cannot decompress is not handed over as bytes: %+v", name, m)
		}
	}
}

// A body that says it is compressed is a thing a broker, or somebody on the way, can make as large as it likes: it is read to a limit.
func TestAZipBombIsStoppedAtTheLimit(t *testing.T) {
	s := fake(t)
	s.AddTopic("bomb", 1)
	s.Put("bomb", 0, rmqtest.Message{Body: bytes.Repeat([]byte("A"), 8<<20), Compressed: true})
	c := New([]string{s.Addr}, Credentials{AccessKey: ak, SecretKey: sk}, Options{AllowLocal: true, Timeout: 3 * time.Second, Group: "securl-reader", MaxBody: 1 << 20})
	r, _ := c.Route(context.Background(), "bomb")
	res, err := c.Pull(context.Background(), r.Queues[0], 0, 1)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(res.Messages) != 1 || len(res.Messages[0].Body) > 1<<20 || res.Messages[0].BodyUnreadable == "" {
		t.Errorf("an 8 MiB body from a few KiB is read to the limit and said to be cut: %d bytes, %q", len(res.Messages[0].Body), res.Messages[0].BodyUnreadable)
	}
}

func TestAMessageWithTheSecondMagicCodeAndOneWithIPv6HostsAreRead(t *testing.T) {
	s := fake(t)
	s.AddTopic("v", 1)
	s.Put("v", 0, rmqtest.Message{Body: []byte("v2"), V2: true})
	s.Put("v", 0, rmqtest.Message{Body: []byte("v6"), V6: true})
	s.Put("v", 0, rmqtest.Message{Body: []byte("both"), V2: true, V6: true, Tags: "t"})
	c := open(t, s, ak, sk)
	r, _ := c.Route(context.Background(), "v")
	res, err := c.Pull(context.Background(), r.Queues[0], 0, 10)
	if err != nil || len(res.Messages) != 3 {
		t.Fatalf("%+v %v", res, err)
	}
	for i, want := range []string{"v2", "v6", "both"} {
		if string(res.Messages[i].Body) != want || res.Messages[i].Topic != "v" {
			t.Errorf("%d: %+v", i, res.Messages[i])
		}
	}
	if res.Messages[2].Tags != "t" {
		t.Errorf("the properties after an IPv6 host are still found: %+v", res.Messages[2])
	}
}

// A message is parsed from bytes a server sent: every length in it is checked against what is left, and a bad one stops the parse.
func TestAMessageWhoseLengthsDoNotAddUpIsRefusedNotReadPastTheEnd(t *testing.T) {
	good := rmqtest.EncodeMessage("orders", 0, 0, rmqtest.Message{Body: []byte("hello"), Tags: "t"})
	for name, mutate := range map[string]func([]byte) []byte{
		"cut short": func(b []byte) []byte { return b[:len(b)/2] },
		"total larger": func(b []byte) []byte {
			c := append([]byte(nil), b...)
			binary.BigEndian.PutUint32(c, uint32(len(c)+100))
			return c
		},
		"total smaller": func(b []byte) []byte { c := append([]byte(nil), b...); binary.BigEndian.PutUint32(c, 20); return c },
		"body length huge": func(b []byte) []byte {
			c := append([]byte(nil), b...)
			binary.BigEndian.PutUint32(c[len(c)-1-2-1-6-5-4:], 0x7fffffff)
			return c
		},
		"unknown magic": func(b []byte) []byte {
			c := append([]byte(nil), b...)
			binary.BigEndian.PutUint32(c[4:], 0x12345678)
			return c
		},
		"properties length huge": func(b []byte) []byte {
			c := append([]byte(nil), b...)
			binary.BigEndian.PutUint16(c[len(c)-2-len("TAGS\x01t\x02"):], 0xffff)
			return c
		},
		"empty": func(b []byte) []byte { return nil },
	} {
		if msgs, err := decodeMessages(mutate(good), 1<<20, true); err == nil && len(msgs) != 0 && name != "total smaller" {
			t.Errorf("%s: %d messages were read from bytes that do not add up", name, len(msgs))
		}
	}
	if msgs, err := decodeMessages(good, 1<<20, true); err != nil || len(msgs) != 1 || string(msgs[0].Body) != "hello" {
		t.Errorf("the good one: %v %v", msgs, err)
	}
}

func TestMoreMessagesThanAFrameCanHoldAreStoppedAtTheCount(t *testing.T) {
	var all []byte
	for i := 0; i < 100; i++ {
		all = append(all, rmqtest.EncodeMessage("t", 0, int64(i), rmqtest.Message{Body: []byte("x")})...)
	}
	msgs, err := decodeMessages(all, 1<<20, true)
	if err == nil && len(msgs) > maxMessagesPerPull {
		t.Errorf("%d messages were read from one pull", len(msgs))
	}
}

// Properties come from the producer and may be anything: the ones that securl does not know are kept by name and value, cut, and the
// ones with a line break or a control character are not passed on as they are.
func TestPropertiesAreKeptButCutAndCleaned(t *testing.T) {
	s := fake(t)
	s.AddTopic("p", 1)
	s.Put("p", 0, rmqtest.Message{Body: []byte("x"), Props: map[string]string{"TRACE_ID": "abc123", "EVIL": "line1\nline2\x07" + strings.Repeat("v", 2000)}})
	c := open(t, s, ak, sk)
	r, err := c.Route(context.Background(), "p")
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Pull(context.Background(), r.Queues[0], 0, 1)
	if err != nil || len(res.Messages) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	m := res.Messages[0]
	if m.Props["TRACE_ID"] != "abc123" {
		t.Errorf("%v", m.Props)
	}
	if v := m.Props["EVIL"]; strings.ContainsAny(v, "\n\x07") || len(v) > 256 {
		t.Errorf("a property value is one clean line of limited length: %q", v)
	}
}

// ---- the survivors of the first round, each with the test that kills it ----

// The signature covers the body as well, as the broker's own class does: a pull has none, but the rule is the broker's, and a request
// with a body signed without it would be refused by a real broker. Pinned to the value the JVM produced.
func TestTheSignatureCoversTheBody(t *testing.T) {
	ext := map[string]string{"AccessKey": "reader1", "topic": "orders", "queueId": "0", "consumerGroup": "securl-reader"}
	with, without := sign(ext, []byte("the-body"), "reader-secret-1"), sign(ext, nil, "reader-secret-1")
	if with != "WGKDClnQBUMZvhzg4wWjUNQh41k=" || with == without {
		t.Errorf("%q %q", with, without)
	}
}

func TestAPullHoldsTheCountToTheLimitAndToAtLeastOne(t *testing.T) {
	s := fake(t)
	s.AddTopic("many", 1)
	for i := 0; i < 70; i++ {
		s.Put("many", 0, rmqtest.Message{Body: []byte("m")})
	}
	c := New([]string{s.Addr}, Credentials{AccessKey: ak, SecretKey: sk}, Options{AllowLocal: true, Timeout: time.Second, Group: "securl-reader"})
	r, _ := c.Route(context.Background(), "many")
	_ = r
	for _, tc := range []struct{ ask, want string }{{"1000", "64"}, {"0", "1"}, {"-5", "1"}, {"32", "32"}} {
		n, _ := strconv.Atoi(tc.ask)
		c.Pull(context.Background(), Queue{Topic: "many", Broker: "broker-a", Addr: s.Addr, ID: 0}, 0, n)
	}
	var got []string
	for _, q := range s.Requests() {
		if q.Code == 11 {
			got = append(got, q.Ext["maxMsgNums"])
		}
	}
	if strings.Join(got, ",") != "64,1,1,32" {
		t.Errorf("the count asked of the broker: %v", got)
	}
}

// Only JSON is spoken: a header that says it is in the other serialization is not read as if it were JSON.
func TestAnAnswerInTheOtherSerializationIsRefused(t *testing.T) {
	s := fake(t)
	hdr := []byte(`{"code":0}`)
	frame := make([]byte, 8)
	binary.BigEndian.PutUint32(frame, uint32(4+len(hdr)))
	binary.BigEndian.PutUint32(frame[4:], uint32(1<<24)|uint32(len(hdr))) // serialization type 1 (ROCKETMQ), with a header that would parse as JSON
	s.SetRaw(105, append(frame, hdr...))
	if _, err := open(t, s, ak, sk).Route(context.Background(), "orders"); err == nil {
		t.Error("an answer that says it is not JSON was read as JSON")
	}
}

func TestAHeaderThatIsNotJSONIsRefusedEvenIfItsLengthsAreRight(t *testing.T) {
	s := fake(t)
	hdr := []byte(`not json at all`)
	frame := make([]byte, 8)
	binary.BigEndian.PutUint32(frame, uint32(4+len(hdr)))
	binary.BigEndian.PutUint32(frame[4:], uint32(len(hdr)))
	s.SetRaw(105, append(frame, hdr...))
	if _, err := open(t, s, ak, sk).Route(context.Background(), "orders"); !errors.Is(err, ErrProtocol) {
		t.Errorf("%v", err)
	}
}

// What the broker's remark says is never repeated: it can name the key, and a broker that is not one can say anything.
func TestARemarkIsNeverRepeatedInWhatTheCallerSees(t *testing.T) {
	err := refusal(header{Code: respSystemError, Remark: "something with secret-123 and reader1 in it"})
	if err == nil || strings.Contains(err.Error(), "secret-123") || strings.Contains(err.Error(), "reader1") || !errors.Is(err, ErrProtocol) {
		t.Errorf("%v", err)
	}
	// an unknown code with a remark is the same
	if err := refusal(header{Code: 999, Remark: "TOP-SECRET"}); err == nil || strings.Contains(err.Error(), "TOP-SECRET") {
		t.Errorf("%v", err)
	}
}

func TestEveryCodeThatMeansAParticularThingIsMappedToIt(t *testing.T) {
	for _, tc := range []struct {
		h    header
		want error
	}{
		{header{Code: respNoPermission}, ErrNoPermission},
		{header{Code: respTopicNotExist}, ErrTopicNotFound},
		{header{Code: respSubNotExist}, ErrGroupNotFound},
		{header{Code: respGroupNotExist}, ErrGroupNotFound},
		{header{Code: respSystemError, Remark: "AclException: Check signature failed for accessKey=x"}, ErrBadCredentials},
		{header{Code: respSystemError, Remark: "AclException: No acl config for x"}, ErrBadCredentials},
		{header{Code: respSystemError, Remark: "AclException: No accessKey is configured"}, ErrBadCredentials},
		{header{Code: respSystemError, Remark: "AclException: No permission for topic:t"}, ErrNoPermission},
		{header{Code: respSystemError, Remark: "AclException: No default permission for group:g"}, ErrNoPermission},
		{header{Code: respSystemError, Remark: "subscription group [g] does not exist"}, ErrGroupNotFound},
	} {
		if err := refusal(tc.h); !errors.Is(err, tc.want) {
			t.Errorf("%+v: want %v, got %v", tc.h, tc.want, err)
		}
	}
	if refusal(header{Code: respSuccess}) != nil {
		t.Error("success is not a refusal")
	}
}

func TestARouteWithMoreQueuesThanTheLimitIsRefusedAndOneAtTheLimitIsNot(t *testing.T) {
	big := func(n int) []byte {
		return []byte(fmt.Sprintf(`{"brokerDatas":[{"brokerAddrs":{0:"10.0.0.1:10911"},"brokerName":"b"}],"queueDatas":[{"brokerName":"b","perm":6,"readQueueNums":%d,"writeQueueNums":%d}]}`, n, n))
	}
	if r, err := parseRoute(big(maxQueuesPerTopic)); err != nil || len(r.Queues) != maxQueuesPerTopic {
		t.Errorf("at the limit: %v", err)
	}
	if _, err := parseRoute(big(maxQueuesPerTopic + 1)); err == nil {
		t.Error("over the limit")
	}
	if _, err := parseRoute(big(-1)); err == nil {
		t.Error("a negative count")
	}
	two := []byte(fmt.Sprintf(`{"brokerDatas":[{"brokerAddrs":{0:"10.0.0.1:10911"},"brokerName":"a"},{"brokerAddrs":{0:"10.0.0.2:10911"},"brokerName":"b"}],"queueDatas":[{"brokerName":"a","perm":6,"readQueueNums":%d},{"brokerName":"b","perm":6,"readQueueNums":%d}]}`, maxQueuesPerTopic, 2))
	if _, err := parseRoute(two); err == nil {
		t.Error("the sum of two brokers' queues is held to the limit too")
	}
}

// A queue on a broker where the topic is write-only has nothing to read there: it is left out and not pulled from.
func TestAQueueThatIsNotReadableIsLeftOut(t *testing.T) {
	r, err := parseRoute([]byte(`{"brokerDatas":[{"brokerAddrs":{0:"10.0.0.1:10911"},"brokerName":"a"},{"brokerAddrs":{0:"10.0.0.2:10911"},"brokerName":"b"}],"queueDatas":[{"brokerName":"a","perm":2,"readQueueNums":2},{"brokerName":"b","perm":6,"readQueueNums":1}]}`))
	if err != nil || len(r.Queues) != 1 || r.Queues[0].Broker != "b" {
		t.Errorf("%+v %v", r, err)
	}
	if _, err := parseRoute([]byte(`{"brokerDatas":[{"brokerAddrs":{0:"10.0.0.1:10911"},"brokerName":"a"}],"queueDatas":[{"brokerName":"a","perm":2,"readQueueNums":2}]}`)); err == nil {
		t.Error("a topic with nothing to read is not a route")
	}
}

// The check on the broker's address is the client's, and does not depend on what the dialling would do: the route names where a pull
// goes, and an address on this machine in it is refused before anything is sent.
func TestARouteNamingAnAddressOnThisMachineIsRefusedWithoutDialling(t *testing.T) {
	s := fake(t)
	s.SetRouteAddr("127.0.0.1:1") // nothing listens there: a dial would say unreachable, not local
	c := New([]string{s.Addr}, Credentials{AccessKey: ak, SecretKey: sk}, Options{AllowLocal: false, Timeout: time.Second, Group: "securl-reader"})
	_, err := c.routeWith(context.Background(), "orders", true)
	if !errors.Is(err, ErrLocalAddress) {
		t.Errorf("%v", err)
	}
}

func TestAnAddressThatIsNotAHostAndAPortIsNotAnAddress(t *testing.T) {
	for _, ok := range []string{"10.0.0.1:10911", "broker.example:9", "a:65535", "[::1]:10911", "b-1.dev.corp:10911"} {
		if err := validAddr(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", ":10911", "10.0.0.1", "10.0.0.1:0", "10.0.0.1:65536", "10.0.0.1:x", "http://h:1", "u@h:1", "h/x:1", "h h:1", "h:1:2", "-h:1", "h-:1", "h_x:1", "h\nx:1", " h:1"} {
		if validAddr(bad) == nil {
			t.Errorf("%q was accepted as an address", bad)
		}
	}
}

func TestAMaxOffsetThatIsNegativeOrNotANumberIsRefused(t *testing.T) {
	for _, bad := range []string{"-1", "x", "", "9999999999999999999999"} {
		s := fake(t)
		hdr := []byte(`{"code":0,"extFields":{"offset":"` + bad + `"}}`)
		frame := make([]byte, 8)
		binary.BigEndian.PutUint32(frame, uint32(4+len(hdr)))
		binary.BigEndian.PutUint32(frame[4:], uint32(len(hdr)))
		s.SetRaw(30, append(frame, hdr...))
		c := open(t, s, ak, sk)
		r, _ := c.Route(context.Background(), "orders")
		if n, err := c.MaxOffset(context.Background(), r.Queues[0]); err == nil {
			t.Errorf("%q gave %d", bad, n)
		}
	}
}

// A code of 20 (retry immediately) is the same as 19: nothing new yet, and not a failure.
func TestARetryImmediatelyAnswerIsNothingNewToo(t *testing.T) {
	s := fake(t)
	hdr := []byte(`{"code":20,"extFields":{"nextBeginOffset":"2","minOffset":"0","maxOffset":"2"}}`)
	frame := make([]byte, 8)
	binary.BigEndian.PutUint32(frame, uint32(4+len(hdr)))
	binary.BigEndian.PutUint32(frame[4:], uint32(len(hdr)))
	s.SetRaw(11, append(frame, hdr...))
	c := open(t, s, ak, sk)
	r, _ := c.Route(context.Background(), "orders")
	res, err := c.Pull(context.Background(), r.Queues[0], 0, 5)
	if err != nil || len(res.Messages) != 0 || res.MaxOffset != 2 {
		t.Errorf("%+v %v", res, err)
	}
}

func TestAMessageShorterThanTheSmallestPossibleIsRefusedAndOneBytePastTheEndIsToo(t *testing.T) {
	good := rmqtest.EncodeMessage("t", 0, 0, rmqtest.Message{Body: []byte("x")})
	if _, err := decodeMessages(good[:3], 1<<20, true); err == nil {
		t.Error("three bytes")
	}
	if _, err := decodeMessages(append(append([]byte(nil), good...), 0, 0), 1<<20, true); err == nil {
		t.Error("two stray bytes after a message")
	}
	tiny := make([]byte, 4+30)
	binary.BigEndian.PutUint32(tiny, 30)
	if _, err := decodeMessages(tiny, 1<<20, true); err == nil {
		t.Error("a message too small to hold its own fixed part")
	}
}

func TestABodyOrPropertiesLengthThatPointsPastTheMessageIsRefused(t *testing.T) {
	good := rmqtest.EncodeMessage("topic", 0, 0, rmqtest.Message{Body: []byte("hello"), Tags: "t"})
	// the fields are found by what they hold, not by counting: the body length is the four bytes before the body, and the properties
	// length the two bytes before the properties
	bodyLenAt := bytes.Index(good, []byte("hello")) - 4
	if binary.BigEndian.Uint32(good[bodyLenAt:]) != 5 {
		t.Fatalf("the body length was not where it was looked for")
	}
	c := append([]byte(nil), good...)
	binary.BigEndian.PutUint32(c[bodyLenAt:], 1<<20)
	if _, err := decodeMessages(c, 1<<20, true); err == nil {
		t.Error("a body length that points past the message")
	}
	c = append([]byte(nil), good...)
	binary.BigEndian.PutUint32(c[bodyLenAt:], 0xffffffff)
	if _, err := decodeMessages(c, 1<<20, true); err == nil {
		t.Error("a body length of -1")
	}
	propsAt := bytes.Index(good, []byte("TAGS")) - 2
	if int(binary.BigEndian.Uint16(good[propsAt:])) != len("TAGS\x01t\x02") {
		t.Fatalf("the properties length was not where it was looked for")
	}
	c = append([]byte(nil), good...)
	binary.BigEndian.PutUint16(c[propsAt:], maxPropsLen+1)
	if _, err := decodeMessages(c, 1<<20, true); err == nil {
		t.Error("a properties length over the limit")
	}
	c = append([]byte(nil), good...)
	binary.BigEndian.PutUint16(c[propsAt:], uint16(len("TAGS\x01t\x02")+50))
	if _, err := decodeMessages(c, 1<<20, true); err == nil {
		t.Error("a properties length that points past the message")
	}
}

// TAGS and KEYS are the message's own and have fields of their own; the rest are the properties.
func TestTagsAndKeysAreNotAlsoInTheProperties(t *testing.T) {
	good := rmqtest.EncodeMessage("t", 0, 0, rmqtest.Message{Body: []byte("x"), Tags: "a", Keys: "b", Props: map[string]string{"X": "y"}})
	msgs, err := decodeMessages(good, 1<<20, true)
	if err != nil || len(msgs) != 1 {
		t.Fatal(err)
	}
	m := msgs[0]
	if m.Tags != "a" || m.Keys != "b" || m.Props["X"] != "y" || len(m.Props) != 1 {
		t.Errorf("%+v", m)
	}
}

// A body longer than the limit, not compressed, is cut and says so.
func TestAPlainBodyOverTheLimitIsCutAndSaysSo(t *testing.T) {
	b, why := readBody(bytes.Repeat([]byte("a"), 100), 0, 10, true)
	if len(b) != 10 || !strings.Contains(why, "cut at 10") {
		t.Errorf("%d %q", len(b), why)
	}
	b, why = readBody(bytes.Repeat([]byte("a"), 10), 0, 10, true)
	if len(b) != 10 || why != "" {
		t.Errorf("a body exactly at the limit is whole: %d %q", len(b), why)
	}
}

// A zlib body is read to the limit and no further, whatever it inflates to: the limit is on what is read, not on what is kept.
func TestAZlibBodyIsReadToTheLimitAndNoFurther(t *testing.T) {
	z := rmqtest.Deflate(bytes.Repeat([]byte("A"), 5<<20))
	b, why := readBody(z, flagCompressed, 1000, true)
	if len(b) != 1000 || !strings.Contains(why, "inflated") {
		t.Errorf("%d %q", len(b), why)
	}
	b, why = readBody(rmqtest.Deflate(bytes.Repeat([]byte("A"), 1000)), flagCompressed, 1000, true)
	if len(b) != 1000 || why != "" {
		t.Errorf("exactly at the limit is whole: %d %q", len(b), why)
	}
}

// Something that says it is compressed and is not is not handed over as the body.
func TestABodyThatSaysItIsCompressedAndIsNotIsNotHandedOver(t *testing.T) {
	b, why := readBody([]byte("this is not zlib"), flagCompressed, 1000, true)
	if len(b) != 0 || why == "" {
		t.Errorf("%q %q", b, why)
	}
	if b, why := readBody(nil, flagCompressed, 1000, true); len(b) != 0 || why == "" {
		t.Errorf("an empty one: %q %q", b, why)
	}
}

// A property with no "=" or an empty name is not a property.
func TestAPropertyWithoutAnEqualsOrWithoutANameIsDropped(t *testing.T) {
	got := parseProps("A\x01b\x02noequals\x02\x01novalue\x02C\x01d\x02")
	if len(got) != 2 || got["A"] != "b" || got["C"] != "d" {
		t.Errorf("%v", got)
	}
}

func TestTheTopicOfAMessageIsOneCleanLine(t *testing.T) {
	good := rmqtest.EncodeMessage("to\npic", 0, 0, rmqtest.Message{Body: []byte("x")})
	msgs, _ := decodeMessages(good, 1<<20, true)
	if len(msgs) != 1 || strings.ContainsAny(msgs[0].Topic, "\n") {
		t.Errorf("%+v", msgs)
	}
}

// Connecting to a server that takes too long is a timeout, and so is a cancelled call; both are told apart from an unreachable one.
func TestConnectingToASilentAddressIsATimeoutNotUnreachable(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	c := New([]string{ln.Addr().String()}, Credentials{}, Options{AllowLocal: true, Timeout: 200 * time.Millisecond, Group: "g"}) // it accepts and says nothing
	start := time.Now()
	_, err := c.Route(context.Background(), "orders")
	if !errors.Is(err, ErrTimeout) || time.Since(start) > 3*time.Second {
		t.Errorf("%v after %s", err, time.Since(start))
	}
}

func TestAShortContextBeatsALongTimeout(t *testing.T) {
	s := fake(t)
	c := New([]string{s.Addr}, Credentials{AccessKey: ak, SecretKey: sk}, Options{AllowLocal: true, Timeout: 30 * time.Second, Group: "securl-reader"})
	r, _ := c.Route(context.Background(), "orders")
	s.SetSlow(make(chan struct{}))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Pull(ctx, r.Queues[0], 0, 1)
	if !errors.Is(err, ErrTimeout) || time.Since(start) > 3*time.Second {
		t.Errorf("%v after %s", err, time.Since(start))
	}
}

func TestACancelledCallDoesNotDialAtAll(t *testing.T) {
	s := fake(t)
	c := open(t, s, ak, sk)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, call := range []func() error{
		func() error { _, err := c.Route(ctx, "orders"); return err },
		func() error { _, err := c.MaxOffset(ctx, Queue{Topic: "orders", Addr: s.Addr}); return err },
		func() error { _, err := c.Pull(ctx, Queue{Topic: "orders", Addr: s.Addr}, 0, 1); return err },
	} {
		if err := call(); !errors.Is(err, ErrTimeout) {
			t.Errorf("%v", err)
		}
	}
	if n := len(s.Requests()); n != 0 {
		t.Errorf("%d requests", n)
	}
}

func TestTheDefaultsAreTheLimitsThatAreDocumented(t *testing.T) {
	c := New([]string{"h:1"}, Credentials{}, Options{})
	if c.opt.MaxReply != 4<<20 || c.opt.MaxBody != 1<<20 || c.opt.Timeout != 10*time.Second {
		t.Errorf("%+v", c.opt)
	}
}

// The extension fields a caller passes are not changed by the signing: the signature and the key are added to a copy.
func TestSigningDoesNotChangeTheCallersFields(t *testing.T) {
	s := fake(t)
	c := open(t, s, ak, sk)
	ext := map[string]string{"topic": "orders", "queueId": "0"}
	c.call(context.Background(), s.Addr, codeGetMaxOffset, ext, true)
	if _, has := ext["Signature"]; has || len(ext) != 2 {
		t.Errorf("%v", ext)
	}
}

// ---- each layer on its own: the survivors that were only survivors because a second check stood behind the first ----

// read() is the first thing that sees a frame, and it must refuse a frame by itself, not leave it to what parses the header next.
func TestTheFrameReaderRefusesWhatItShouldWithoutHelpFromTheParsersAfterIt(t *testing.T) {
	read := func(raw []byte) (header, []byte, error) {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		go func() { b.Write(raw); b.Close() }()
		c := New([]string{"h:1"}, Credentials{}, Options{AllowLocal: true, Timeout: time.Second})
		return c.read(context.Background(), a)
	}
	frame := func(serType byte, hdr string, body string) []byte {
		f := make([]byte, 8)
		binary.BigEndian.PutUint32(f, uint32(4+len(hdr)+len(body)))
		binary.BigEndian.PutUint32(f[4:], uint32(serType)<<24|uint32(len(hdr)))
		return append(append(f, hdr...), body...)
	}
	if _, _, err := read(frame(0, `{"code":0}`, "body")); err != nil {
		t.Fatalf("the good frame: %v", err)
	}
	if _, _, err := read(frame(1, `{"code":0}`, "")); !errors.Is(err, ErrProtocol) {
		t.Errorf("a frame in the other serialization, with a header that would parse as JSON: %v", err)
	}
	if h, _, err := read(frame(0, `not json`, "")); !errors.Is(err, ErrProtocol) {
		t.Errorf("a header that is not JSON: %v %+v", err, h)
	}
	if _, _, err := read(frame(0, `{"code":0}`, "")[:6]); err == nil {
		t.Error("a frame cut short")
	}
}

// parseRoute's own checks, each one alone: the caller's check on the broker address is a second wall and must not be the only one.
func TestParseRouteRefusesABadAddressAndAnUnsafeQueueCountByItself(t *testing.T) {
	doc := func(addr string, n int) []byte {
		return []byte(fmt.Sprintf(`{"brokerDatas":[{"brokerAddrs":{0:%q},"brokerName":"b"}],"queueDatas":[{"brokerName":"b","perm":6,"readQueueNums":%d}]}`, addr, n))
	}
	if _, err := parseRoute(doc("10.0.0.1:10911", 2)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", ":10911", "http://h:1", "h:99999", "u@h:1", "h", "10.0.0.1:0"} {
		if _, err := parseRoute(doc(bad, 2)); err == nil {
			t.Errorf("the address %q was accepted by parseRoute", bad)
		}
	}
}

func TestAnEmptyHostIsNotAnAddressEvenWithAGoodPort(t *testing.T) {
	if validAddr(":10911") == nil {
		t.Error("a port with no host")
	}
	if validAddr("[]:10911") == nil {
		t.Error("an empty bracketed host")
	}
}

// The check that a route does not name this machine is the client's own, and runs on what the route says, before anything is sent to
// that address: here the NameServer is allowed (it is a fake on this machine) and the broker address is not.
func TestARouteNamingThisMachineIsRefusedByTheRouteCheckAloneAndTheCallerIsToldWhy(t *testing.T) {
	s := fake(t)
	s.SetRouteAddr("127.0.0.1:1")
	c := New([]string{s.Addr}, Credentials{AccessKey: ak, SecretKey: sk}, Options{AllowLocal: true, Timeout: time.Second, Group: "securl-reader"})
	if _, err := c.routeWith(context.Background(), "orders", false); !errors.Is(err, ErrLocalAddress) {
		t.Fatalf("%v", err)
	}
	if _, err := c.routeWith(context.Background(), "orders", true); err != nil {
		t.Errorf("allowed: %v", err)
	}
	// and a NameServer on this machine that is not allowed is the answer, not a reason to try the next one
	s2 := fake(t)
	c2 := New([]string{s.Addr, s2.Addr}, Credentials{AccessKey: ak, SecretKey: sk}, Options{AllowLocal: false, Timeout: time.Second, Group: "securl-reader"})
	if _, err := c2.Route(context.Background(), "orders"); !errors.Is(err, ErrLocalAddress) {
		t.Errorf("%v", err)
	}
	if n := len(s2.Requests()); n != 0 {
		t.Errorf("a refusal for being local went on to the next NameServer: %d requests", n)
	}
}

// decodeMessages' own checks, each alone, on bytes that look right except for the one thing.
func TestDecodeRefusesEachBadLengthByItself(t *testing.T) {
	good := rmqtest.EncodeMessage("topic", 0, 0, rmqtest.Message{Body: []byte("hello"), Tags: "t"})
	bodyAt := bytes.Index(good, []byte("hello")) - 4
	propsAt := bytes.Index(good, []byte("TAGS")) - 2
	for name, mut := range map[string]func([]byte){
		"body length one past the end":       func(b []byte) { binary.BigEndian.PutUint32(b[bodyAt:], uint32(len(b))) },
		"body length of the whole message":   func(b []byte) { binary.BigEndian.PutUint32(b[bodyAt:], uint32(len(b)-bodyAt)) },
		"properties length one past the end": func(b []byte) { binary.BigEndian.PutUint16(b[propsAt:], uint16(len(b)-propsAt-2+1)) },
		"properties length over the limit":   func(b []byte) { binary.BigEndian.PutUint16(b[propsAt:], uint16(maxPropsLen+1)) },
	} {
		c := append([]byte(nil), good...)
		mut(c)
		if _, err := decodeOne(c[4:], 1<<20, true); err == nil {
			t.Errorf("%s: decodeOne accepted it", name)
		}
	}
	if _, err := decodeOne(good[4:], 1<<20, true); err != nil {
		t.Errorf("the good one: %v", err)
	}
	// total length smaller than the smallest message: refused by decodeMessages before decodeOne is called on garbage
	small := make([]byte, 4+10)
	binary.BigEndian.PutUint32(small, 10)
	if _, err := decodeMessages(small, 1<<20, true); err == nil {
		t.Error("a message of 10 bytes")
	}
}

// ReadAll on the zlib reader is bounded by the limit; without the bound the 5 MiB inflates whole and is cut afterwards, which is the
// same bytes and a different cost: the memory is what the bound is for. Counting what is read tells them apart.
func TestAZlibBodyIsNeverInflatedBeyondTheLimitPlusOne(t *testing.T) {
	var read int64
	big := rmqtest.Deflate(bytes.Repeat([]byte("A"), 20<<20))
	z, err := zlib.NewReader(&countingReader{r: bytes.NewReader(big), n: &read})
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(io.LimitReader(z, 1001))
	if len(out) != 1001 {
		t.Fatalf("%d", len(out))
	}
	// the compressed input is small, so the proof is in what the function returns for a body that inflates to 20 MiB in 1000 bytes
	b, why := readBody(big, flagCompressed, 1000, true)
	if len(b) != 1000 || why == "" {
		t.Errorf("%d %q", len(b), why)
	}
}

type countingReader struct {
	r io.Reader
	n *int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	*c.n += int64(n)
	return n, err
}

// A timeout while connecting is a timeout and not "unreachable": a firewall that drops packets is not a refusal.
func TestAConnectionThatIsNeverAnsweredIsATimeoutAtTheDial(t *testing.T) {
	c := New([]string{"10.255.255.1:9876"}, Credentials{}, Options{AllowLocal: true, Timeout: 300 * time.Millisecond, Group: "g"})
	start := time.Now()
	_, err := c.Route(context.Background(), "orders")
	if time.Since(start) > 3*time.Second {
		t.Fatalf("it waited %s", time.Since(start))
	}
	if !errors.Is(err, ErrTimeout) && !errors.Is(err, ErrUnreachable) {
		t.Errorf("%v", err)
	}
}

// What a read error says depends on whether the caller's context is what ended it: a cancelled call is a timeout, whatever the socket says.
func TestACallEndedByItsContextIsATimeoutWhateverTheSocketReports(t *testing.T) {
	c := New([]string{"h:1"}, Credentials{}, Options{AllowLocal: true, Timeout: time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.netErr(ctx, io.EOF); !errors.Is(err, ErrTimeout) {
		t.Errorf("%v", err)
	}
	if err := c.netErr(context.Background(), io.EOF); !errors.Is(err, ErrUnreachable) {
		t.Errorf("an ended connection with a live context is not a timeout: %v", err)
	}
}

func TestAMessageWhosePropertiesAreLongerThanTheLimitIsRefusedEvenWhenItHoldsThemAll(t *testing.T) {
	big := rmqtest.EncodeMessage("topic", 0, 0, rmqtest.Message{Body: []byte("x"), Props: map[string]string{"P": strings.Repeat("v", maxPropsLen+8)}})
	if _, err := decodeMessages(big, 1<<20, true); !errors.Is(err, ErrProtocol) {
		t.Fatalf("a property block over the limit was taken: %v", err)
	}
	ok := rmqtest.EncodeMessage("topic", 0, 0, rmqtest.Message{Body: []byte("x"), Props: map[string]string{"P": strings.Repeat("v", 1000)}})
	if _, err := decodeMessages(ok, 1<<20, true); err != nil {
		t.Fatalf("an ordinary message was refused: %v", err)
	}
}

func TestACompressedBodyIsNeverInflatedBeyondTheCapInMemory(t *testing.T) {
	var zb bytes.Buffer
	zw := zlib.NewWriter(&zb)
	chunk := make([]byte, 1<<20)
	for i := 0; i < 400; i++ {
		if _, err := zw.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	zw.Close()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	b, why := readBody(zb.Bytes(), flagCompressed, 1000, true)
	runtime.ReadMemStats(&after)
	if len(b) != 1000 || why == "" {
		t.Fatalf("len %d, %q", len(b), why)
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 64<<20 {
		t.Fatalf("inflating a 400 MiB body for a 1000-byte cap allocated %d MiB: the cap is not a bound on memory", grew>>20)
	}
}

func TestAConnectionThatCannotBeMadeInTimeIsATimeoutAndNotAnUnreachableServer(t *testing.T) {
	s := fake(t)
	c := New([]string{s.Addr}, Credentials{AccessKey: ak, SecretKey: sk}, Options{AllowLocal: true, Timeout: time.Nanosecond, Group: "g"})
	if _, err := c.Route(context.Background(), "orders"); !errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v", err)
	}
}
