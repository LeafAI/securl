package config

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// RocketMQ is one Apache RocketMQ cluster an agent may read messages from, through its NameServer and brokers (the remoting
// protocol, not the Dashboard). It is read only: an agent cannot send a message, create or delete a topic, or touch an offset.
//
// Only a topic the owner has listed can be read: the agent names a target and a topic, and a topic that is not in Topics is refused
// before anything is asked of the broker. The AccessKey and SecretKey are never here: a person types them on a page and they stay in
// the vault, and a file that holds one is refused.
//
// The environment is a label that stops a slip of the pen; securl cannot tell whether a cluster really is production. A message holds
// business data, which is why the topics are listed and the size of a body is limited.
type RocketMQ struct {
	Name string `yaml:"name"`
	// NameServers are host or host:port (default port 9876), up to eight.
	NameServers []string `yaml:"namesrv"`
	Environment string   `yaml:"environment"` // dev | test | staging; production is refused
	Topics      []string `yaml:"topics"`      // the topics an agent may read: required
	// ConsumerGroup is the group the reads are made as. A pull is made as a consumer group, which has to exist on the broker (or be
	// created by the pull, where the broker allows it) and which the key has to be allowed to use. Nothing is consumed under it: no
	// offset is ever committed. Left out, it is securl-reader.
	ConsumerGroup string `yaml:"consumer_group"`
	// TLS is how the connection is protected. RocketMQ's remoting port is plain unless the broker was set up for TLS, so the default
	// is disable; verify and skip-verify are for a broker that has it.
	TLS string `yaml:"tls"`
	// MaxMessages is the most messages one read returns, and MaxBodyBytes how much of a message body is returned: 0, written out,
	// returns the metadata of a message and none of its body. Left out, it is 4096.
	MaxMessages  int           `yaml:"max_messages"`
	MaxBodyBytes *int          `yaml:"max_body_bytes"`
	Timeout      time.Duration `yaml:"timeout"`
}

const (
	rmqDefaultPort     = 9876
	rmqMaxNameServers  = 8
	rmqHardMessages    = 32
	rmqHardBody        = 1 << 20
	rmqHardTimeout     = 2 * time.Minute
	rmqDefaultMessages = 20
	rmqDefaultBody     = 4096
	rmqDefaultTimeout  = 10 * time.Second
	rmqDefaultGroup    = "securl-reader"
)

var rmqGroupPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,255}$`)

var rmqTopicPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,127}$`)

// rmqSystemTopics are the broker's own topics: its queues for scheduled, transactional and retried messages, and the defaults it
// ships with. They hold what the broker needs, not what a business wrote, and a listed name must not be a way into them.
var rmqSystemPrefixes = []string{"rmq_sys_", "schedule_topic_", "tbw102", "benchmarktest", "offset_moved_event", "self_test_topic", "defaultcluster", "defaultcluster_reply_topic", "broker-"}

// TLSMode is how the connection is protected, "disable" unless the owner chose otherwise.
func (r RocketMQ) TLSMode() string {
	if r.TLS == "" {
		return TLSDisable
	}
	return r.TLS
}

// MessageLimit is the most messages one read returns.
func (r RocketMQ) MessageLimit() int {
	if r.MaxMessages > 0 {
		return r.MaxMessages
	}
	return rmqDefaultMessages
}

// BodyLimit is how many bytes of a message body are returned: 0 is none.
func (r RocketMQ) BodyLimit() int {
	if r.MaxBodyBytes != nil {
		return *r.MaxBodyBytes
	}
	return rmqDefaultBody
}

// TimeoutOrDefault is how long one call to the cluster may take.
func (r RocketMQ) TimeoutOrDefault() time.Duration {
	if r.Timeout > 0 {
		return r.Timeout
	}
	return rmqDefaultTimeout
}

// Group is the consumer group the reads are made as.
func (r RocketMQ) Group() string {
	if r.ConsumerGroup != "" {
		return r.ConsumerGroup
	}
	return rmqDefaultGroup
}

// AllowsTopic reports whether the topic is one the owner listed, spelled exactly.
func (r RocketMQ) AllowsTopic(t string) bool {
	if t == "" {
		return false
	}
	for _, x := range r.Topics {
		if x == t {
			return true
		}
	}
	return false
}

// NameServerAddrs are the NameServers as host:port, with the default port where none was given.
func (r RocketMQ) NameServerAddrs() []string {
	out := make([]string, len(r.NameServers))
	for i, s := range r.NameServers {
		if _, _, err := net.SplitHostPort(s); err == nil {
			out[i] = s
			continue
		}
		out[i] = net.JoinHostPort(strings.Trim(s, "[]"), strconv.Itoa(rmqDefaultPort))
	}
	return out
}

// RocketMQTarget finds a target by its exact name.
func (c *Config) RocketMQTarget(name string) (RocketMQ, bool) {
	if name == "" {
		return RocketMQ{}, false
	}
	for _, r := range c.RocketMQ {
		if r.Name == name {
			return r, true
		}
	}
	return RocketMQ{}, false
}

func validNameServer(s string) error {
	host, hasPort, port := s, false, ""
	if h, p, err := net.SplitHostPort(s); err == nil {
		host, hasPort, port = h, true, p // "host:" has a colon and no port, which is a mistake and not a default
	} else if strings.Contains(s, ":") && net.ParseIP(s) == nil {
		return fmt.Errorf("namesrv %q: give host or host:port", s)
	}
	if !plainHost(host) {
		return fmt.Errorf("namesrv %q: give a host name or an address, with an optional :port, and no scheme, user or path", s)
	}
	if hasPort {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("namesrv %q: the port is 1-65535", s)
		}
	}
	return nil
}

func validTopic(t string) error {
	if !rmqTopicPattern.MatchString(t) {
		return fmt.Errorf("topics: %q is not a plain topic name (letters, digits, '_', '.', '-'; no wildcard)", t)
	}
	low := strings.ToLower(t)
	for _, p := range rmqSystemPrefixes {
		if strings.HasPrefix(low, p) {
			return fmt.Errorf("topics: %q is one of the broker's own topics, which are not offered", t)
		}
	}
	return nil
}

func (r RocketMQ) validate() error {
	if !dbNamePattern.MatchString(r.Name) {
		return fmt.Errorf("name %q: use 1-64 letters, digits, '.', '_' or '-'", r.Name)
	}
	if len(r.NameServers) == 0 {
		return fmt.Errorf("namesrv: give at least one NameServer, as host or host:port")
	}
	if len(r.NameServers) > rmqMaxNameServers {
		return fmt.Errorf("namesrv: at most %d", rmqMaxNameServers)
	}
	for _, s := range r.NameServers {
		if err := validNameServer(s); err != nil {
			return err
		}
	}
	if err := validateEnvironment(r.Environment); err != nil {
		return err
	}
	if len(r.Topics) == 0 {
		return fmt.Errorf("topics: list the topics an agent may read; there is no \"all\"")
	}
	seen := map[string]bool{}
	for _, t := range r.Topics {
		if err := validTopic(t); err != nil {
			return err
		}
		if seen[t] {
			return fmt.Errorf("topics: %q is listed twice", t)
		}
		seen[t] = true
	}
	if r.ConsumerGroup != "" && (!rmqGroupPattern.MatchString(r.ConsumerGroup) || strings.HasPrefix(strings.ToLower(r.ConsumerGroup), "cid_rmq_sys_")) {
		return fmt.Errorf("consumer_group %q: use 1-255 letters, digits, '_', '.' or '-', and not one of the broker's own groups", r.ConsumerGroup)
	}
	switch r.TLS {
	case "", TLSVerify, TLSSkipVerify, TLSDisable:
	default:
		return fmt.Errorf("tls %q: use %s, %s or %s", r.TLS, TLSVerify, TLSSkipVerify, TLSDisable)
	}
	if r.MaxMessages < 0 || r.MaxMessages > rmqHardMessages {
		return fmt.Errorf("max_messages %d: use 1-%d", r.MaxMessages, rmqHardMessages)
	}
	if r.MaxBodyBytes != nil && (*r.MaxBodyBytes < 0 || *r.MaxBodyBytes > rmqHardBody) {
		return fmt.Errorf("max_body_bytes %d: use 0-%d (0: no body)", *r.MaxBodyBytes, rmqHardBody)
	}
	if r.Timeout < 0 || r.Timeout > rmqHardTimeout {
		return fmt.Errorf("timeout %s: use up to %s", r.Timeout, rmqHardTimeout)
	}
	return nil
}

func validateRocketMQ(rs []RocketMQ) error {
	seen := map[string]bool{}
	for i, r := range rs {
		if err := r.validate(); err != nil {
			return fmt.Errorf("rocketmq[%d] (%s): %w", i, r.Name, err)
		}
		if seen[r.Name] {
			return fmt.Errorf("rocketmq: the name %q is used twice", r.Name)
		}
		seen[r.Name] = true
	}
	return nil
}
