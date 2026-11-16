package config

import (
	"strings"
	"testing"
	"time"
)

const goodRMQ = `
rocketmq:
  - name: mq-dev
    namesrv: [rmq-ns.dev.corp.example:9876]
    environment: dev
    topics: [orders, payments]
`

func TestARocketMQTargetIsReadFromTheConfigurationWithSafeDefaults(t *testing.T) {
	c, err := parseDB(t, goodRMQ)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := c.RocketMQTarget("mq-dev")
	if !ok || r.Environment != "dev" || len(r.Topics) != 2 || r.NameServers[0] != "rmq-ns.dev.corp.example:9876" {
		t.Fatalf("%+v", r)
	}
	if r.MessageLimit() != 20 || r.BodyLimit() != 4096 || r.TimeoutOrDefault() != 10*time.Second || r.TLSMode() != TLSDisable {
		t.Errorf("defaults: %d %d %s %s", r.MessageLimit(), r.BodyLimit(), r.TimeoutOrDefault(), r.TLSMode())
	}
	if !r.AllowsTopic("orders") || r.AllowsTopic("secrets") || r.AllowsTopic("") || r.AllowsTopic("ORDERS") || r.AllowsTopic("orders ") {
		t.Error("only a listed topic, spelled exactly, may be read")
	}
}

func TestANameServerWithoutAPortGetsRocketMQsOwn(t *testing.T) {
	c, err := parseDB(t, "rocketmq:\n  - {name: m, namesrv: [ns.example], environment: dev, topics: [t]}\n")
	if err != nil {
		t.Fatal(err)
	}
	r, _ := c.RocketMQTarget("m")
	if got := r.NameServerAddrs(); len(got) != 1 || got[0] != "ns.example:9876" {
		t.Errorf("%v", got)
	}
	r2 := RocketMQ{NameServers: []string{"a.example:9877", "b.example"}}
	if got := r2.NameServerAddrs(); got[0] != "a.example:9877" || got[1] != "b.example:9876" {
		t.Errorf("%v", got)
	}
}

func TestARocketMQTargetWithItsOwnLimits(t *testing.T) {
	c, err := parseDB(t, "rocketmq:\n  - {name: m, namesrv: ['a.example:9876', 'b.example:9876'], environment: staging, topics: [t], max_messages: 5, max_body_bytes: 0, timeout: 3s, tls: skip-verify}\n")
	if err != nil {
		t.Fatal(err)
	}
	r, _ := c.RocketMQTarget("m")
	if r.MessageLimit() != 5 || r.BodyLimit() != 0 || r.TimeoutOrDefault() != 3*time.Second || r.TLSMode() != TLSSkipVerify || len(r.NameServers) != 2 {
		t.Errorf("%+v", r)
	}
}

// Bodies are off when the owner says so: a limit of 0 written out means "no body", which is different from leaving it out.
func TestABodyLimitOfZeroWrittenOutMeansNoBodyAndLeavingItOutMeansTheDefault(t *testing.T) {
	c, _ := parseDB(t, "rocketmq:\n  - {name: a, namesrv: [h.example], environment: dev, topics: [t], max_body_bytes: 0}\n  - {name: b, namesrv: [h.example], environment: dev, topics: [t]}\n")
	a, _ := c.RocketMQTarget("a")
	b, _ := c.RocketMQTarget("b")
	if a.BodyLimit() != 0 || b.BodyLimit() != 4096 {
		t.Errorf("written 0: %d, left out: %d", a.BodyLimit(), b.BodyLimit())
	}
}

func TestARocketMQTargetThatIsMalformedIsRefused(t *testing.T) {
	for name, y := range map[string]string{
		"no name":              "rocketmq:\n  - {namesrv: [h.example], environment: dev, topics: [t]}\n",
		"bad name":             "rocketmq:\n  - {name: 'a b', namesrv: [h.example], environment: dev, topics: [t]}\n",
		"no nameserver":        "rocketmq:\n  - {name: a, environment: dev, topics: [t]}\n",
		"empty nameserver":     "rocketmq:\n  - {name: a, namesrv: [''], environment: dev, topics: [t]}\n",
		"nameserver scheme":    "rocketmq:\n  - {name: a, namesrv: ['http://h.example:9876'], environment: dev, topics: [t]}\n",
		"nameserver user":      "rocketmq:\n  - {name: a, namesrv: ['u@h.example:9876'], environment: dev, topics: [t]}\n",
		"nameserver path":      "rocketmq:\n  - {name: a, namesrv: ['h.example:9876/x'], environment: dev, topics: [t]}\n",
		"nameserver port 0":    "rocketmq:\n  - {name: a, namesrv: ['h.example:0'], environment: dev, topics: [t]}\n",
		"nameserver big port":  "rocketmq:\n  - {name: a, namesrv: ['h.example:70000'], environment: dev, topics: [t]}\n",
		"nameserver text port": "rocketmq:\n  - {name: a, namesrv: ['h.example:x'], environment: dev, topics: [t]}\n",
		"too many nameservers": "rocketmq:\n  - {name: a, namesrv: [a1.example, a2.example, a3.example, a4.example, a5.example, a6.example, a7.example, a8.example, a9.example], environment: dev, topics: [t]}\n",
		"no environment":       "rocketmq:\n  - {name: a, namesrv: [h.example], topics: [t]}\n",
		"production":           "rocketmq:\n  - {name: a, namesrv: [h.example], environment: production, topics: [t]}\n",
		"no topics":            "rocketmq:\n  - {name: a, namesrv: [h.example], environment: dev}\n",
		"empty topics":         "rocketmq:\n  - {name: a, namesrv: [h.example], environment: dev, topics: []}\n",
		"topic with a space":   "rocketmq:\n  - {name: a, namesrv: [h.example], environment: dev, topics: ['a b']}\n",
		"topic wildcard":       "rocketmq:\n  - {name: a, namesrv: [h.example], environment: dev, topics: ['*']}\n",
		"topic with a slash":   "rocketmq:\n  - {name: a, namesrv: [h.example], environment: dev, topics: ['a/b']}\n",
		"topic too long":       "rocketmq:\n  - {name: a, namesrv: [h.example], environment: dev, topics: [" + strings.Repeat("t", 128) + "]}\n",
		"topic duplicate":      "rocketmq:\n  - {name: a, namesrv: [h.example], environment: dev, topics: [t, t]}\n",
		"system topic":         "rocketmq:\n  - {name: a, namesrv: [h.example], environment: dev, topics: [RMQ_SYS_TRANS_HALF_TOPIC]}\n",
		"retry topic":          "rocketmq:\n  - {name: a, namesrv: [h.example], environment: dev, topics: ['%RETRY%group']}\n",
		"dlq topic":            "rocketmq:\n  - {name: a, namesrv: [h.example], environment: dev, topics: ['%DLQ%group']}\n",
		"bad tls":              "rocketmq:\n  - {name: a, namesrv: [h.example], environment: dev, topics: [t], tls: maybe}\n",
		"messages 0 negative":  "rocketmq:\n  - {name: a, namesrv: [h.example], environment: dev, topics: [t], max_messages: -1}\n",
		"messages over hard":   "rocketmq:\n  - {name: a, namesrv: [h.example], environment: dev, topics: [t], max_messages: 33}\n",
		"body negative":        "rocketmq:\n  - {name: a, namesrv: [h.example], environment: dev, topics: [t], max_body_bytes: -1}\n",
		"body over hard":       "rocketmq:\n  - {name: a, namesrv: [h.example], environment: dev, topics: [t], max_body_bytes: 1048577}\n",
		"timeout over hard":    "rocketmq:\n  - {name: a, namesrv: [h.example], environment: dev, topics: [t], timeout: 10m}\n",
		"timeout negative":     "rocketmq:\n  - {name: a, namesrv: [h.example], environment: dev, topics: [t], timeout: -1s}\n",
		"duplicate name":       "rocketmq:\n  - {name: a, namesrv: [h.example], environment: dev, topics: [t]}\n  - {name: a, namesrv: [g.example], environment: dev, topics: [t]}\n",
	} {
		if _, err := parseDB(t, y); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
}

// A topic that holds what securl must never read for an agent: the broker's own, retry and dead-letter queues. A person may want
// those for support, but they are the owner's to open, not something a listed name can slip in.
func TestTopicsOfTheBrokerItselfCannotBeListed(t *testing.T) {
	for _, tp := range []string{"RMQ_SYS_x", "SCHEDULE_TOPIC_XXXX", "TBW102", "BenchmarkTest", "OFFSET_MOVED_EVENT", "SELF_TEST_TOPIC", "DefaultCluster", "rmq_sys_lower", "%RETRY%x", "%DLQ%x"} {
		if _, err := parseDB(t, "rocketmq:\n  - {name: a, namesrv: [h.example], environment: dev, topics: ['"+tp+"']}\n"); err == nil {
			t.Errorf("%s was accepted", tp)
		}
	}
}

// The access key and the secret key are typed on a page and kept in the vault. A file that has one is refused, and the refusal does
// not repeat it.
func TestARocketMQTargetWithKeysInTheFileIsRefusedWithoutEchoingThem(t *testing.T) {
	for _, key := range []string{"access_key", "accesskey", "secret_key", "secretkey", "secret", "password", "token", "ak", "sk", "credentials"} {
		y := "rocketmq:\n  - {name: a, namesrv: [h.example], environment: dev, topics: [t], " + key + ": hunter2-VERY-secret}\n"
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

func TestOnlyAnExactNameFindsARocketMQTarget(t *testing.T) {
	c, _ := parseDB(t, goodRMQ)
	for _, n := range []string{"", "MQ-DEV", "mq-dev ", "mq", "mq-dev2"} {
		if _, ok := c.RocketMQTarget(n); ok {
			t.Errorf("%q found a target", n)
		}
	}
}

// A lookup by an empty name finds nothing, even for a target whose name was never set (which validation refuses, but a lookup must not
// depend on that).
func TestAnEmptyNameFindsNoTargetEvenIfOneHasNoName(t *testing.T) {
	c := &Config{Redis: []Redis{{Host: "h.example"}}, RocketMQ: []RocketMQ{{Topics: []string{"t"}}}}
	if _, ok := c.RedisTarget(""); ok {
		t.Error("an empty name found a Redis target")
	}
	if _, ok := c.RocketMQTarget(""); ok {
		t.Error("an empty name found a RocketMQ target")
	}
	if (RocketMQ{Topics: []string{""}}).AllowsTopic("") {
		t.Error("an empty topic is never allowed, even if the list holds an empty one")
	}
}

// host:port written with a colon and no valid port is refused as such, and a bare IPv6 address (which has colons) is a host.
func TestANameServerWithAColonThatIsNotAPortIsRefusedAndABareIPv6IsAHost(t *testing.T) {
	for _, bad := range []string{"h.example:", "h.example:9876:1", "a:b:c"} {
		if _, err := parseDB(t, "rocketmq:\n  - {name: a, namesrv: ['"+bad+"'], environment: dev, topics: [t]}\n"); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	c, err := parseDB(t, "rocketmq:\n  - {name: a, namesrv: ['::1'], environment: dev, topics: [t]}\n")
	if err != nil {
		t.Fatalf("a bare IPv6 address is a host: %v", err)
	}
	r, _ := c.RocketMQTarget("a")
	if got := r.NameServerAddrs(); got[0] != "[::1]:9876" {
		t.Errorf("%v", got)
	}
}

func TestTheTopicNameLengthLimitIsExact(t *testing.T) {
	ok := strings.Repeat("t", 127)
	if _, err := parseDB(t, "rocketmq:\n  - {name: a, namesrv: [h.example], environment: dev, topics: ["+ok+"]}\n"); err != nil {
		t.Errorf("127 characters: %v", err)
	}
	if _, err := parseDB(t, "rocketmq:\n  - {name: a, namesrv: [h.example], environment: dev, topics: ["+ok+"t]}\n"); err == nil {
		t.Error("128 characters was accepted")
	}
}
