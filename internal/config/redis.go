package config

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"time"
)

// Redis is one Redis server an agent may use. Only a target the owner has written down can be reached: the agent names it, and it
// never supplies a host, a port or an address. The password is never here: a person types it on a page and it stays in the vault, and
// a file that holds one is refused.
//
// The environment is a label that stops a slip of the pen (a production host pasted into the wrong place); securl cannot tell
// whether a host really is production. The real boundary is what the password (or the ACL user) is allowed to do: give it only what
// an agent may do there.
type Redis struct {
	Name        string `yaml:"name"`
	Host        string `yaml:"host"`        // a name or an address, with no port
	Port        int    `yaml:"port"`        // default 6379
	Environment string `yaml:"environment"` // dev | test | staging; production is refused
	// Username is the Redis 6 ACL user, which is a name and not a secret. Empty: the password alone is asked for.
	Username string `yaml:"username"`
	Mode     string `yaml:"mode"` // read_only (default) | read_write
	TLS      string `yaml:"tls"`  // verify (default) | skip-verify | disable
	// MaxItems is the most elements one reply may carry to the agent, MaxReplyBytes the most bytes the server may send for one
	// command, and CommandTimeout how long one command may take.
	MaxItems       int           `yaml:"max_items"`
	MaxReplyBytes  int           `yaml:"max_reply_bytes"`
	CommandTimeout time.Duration `yaml:"command_timeout"`
}

// Limits that no configuration can raise, and the defaults.
const (
	redisHardItems   = 100000
	redisHardReply   = 64 << 20
	redisHardTimeout = 5 * time.Minute

	redisDefaultItems   = 1000
	redisDefaultReply   = 1 << 20
	redisDefaultTimeout = 10 * time.Second
	redisDefaultPort    = 6379
)

var redisUserPattern = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,64}$`)

// Writable reports whether the target takes changes.
func (r Redis) Writable() bool { return r.Mode == ModeReadWrite }

// TLSMode returns the TLS mode, defaulting to full verification.
func (r Redis) TLSMode() string {
	if r.TLS == "" {
		return TLSVerify
	}
	return r.TLS
}

// PortOrDefault is the port, or Redis's own.
func (r Redis) PortOrDefault() int {
	if r.Port > 0 {
		return r.Port
	}
	return redisDefaultPort
}

// Addr is host:port, ready to dial.
func (r Redis) Addr() string { return net.JoinHostPort(r.Host, strconv.Itoa(r.PortOrDefault())) }

// ItemLimit is the most elements of a reply an agent is given.
func (r Redis) ItemLimit() int {
	if r.MaxItems > 0 {
		return r.MaxItems
	}
	return redisDefaultItems
}

// ReplyLimit is the most bytes the server may send for one command.
func (r Redis) ReplyLimit() int {
	if r.MaxReplyBytes > 0 {
		return r.MaxReplyBytes
	}
	return redisDefaultReply
}

// CommandTimeoutOrDefault is how long one command may take.
func (r Redis) CommandTimeoutOrDefault() time.Duration {
	if r.CommandTimeout > 0 {
		return r.CommandTimeout
	}
	return redisDefaultTimeout
}

// RedisTarget finds a target by its exact name.
func (c *Config) RedisTarget(name string) (Redis, bool) {
	if name == "" {
		return Redis{}, false
	}
	for _, r := range c.Redis {
		if r.Name == name {
			return r, true
		}
	}
	return Redis{}, false
}

func (r Redis) validate() error {
	if !dbNamePattern.MatchString(r.Name) {
		return fmt.Errorf("name %q: use 1-64 letters, digits, '.', '_' or '-'", r.Name)
	}
	if !plainHost(r.Host) {
		return fmt.Errorf("host %q: give a host name or an address only, with no port, scheme or user", r.Host)
	}
	if r.Port < 0 || r.Port > 65535 {
		return fmt.Errorf("port %d: use 1-65535", r.Port)
	}
	if err := validateEnvironment(r.Environment); err != nil {
		return err
	}
	if r.Username != "" && !redisUserPattern.MatchString(r.Username) {
		return fmt.Errorf("username: one line of at most 64 characters")
	}
	switch r.Mode {
	case "", ModeReadOnly, ModeReadWrite:
	default:
		return fmt.Errorf("mode %q: use %s or %s", r.Mode, ModeReadOnly, ModeReadWrite)
	}
	switch r.TLS {
	case "", TLSVerify, TLSSkipVerify, TLSDisable:
	default:
		return fmt.Errorf("tls %q: use %s, %s or %s", r.TLS, TLSVerify, TLSSkipVerify, TLSDisable)
	}
	if r.MaxItems < 0 || r.MaxItems > redisHardItems {
		return fmt.Errorf("max_items %d: use 1-%d", r.MaxItems, redisHardItems)
	}
	if r.MaxReplyBytes < 0 || r.MaxReplyBytes > redisHardReply {
		return fmt.Errorf("max_reply_bytes %d: use 1-%d", r.MaxReplyBytes, redisHardReply)
	}
	if r.CommandTimeout < 0 || r.CommandTimeout > redisHardTimeout {
		return fmt.Errorf("command_timeout %s: use up to %s", r.CommandTimeout, redisHardTimeout)
	}
	return nil
}

func validateRedis(rs []Redis) error {
	seen := map[string]bool{}
	for i, r := range rs {
		if err := r.validate(); err != nil {
			return fmt.Errorf("redis[%d] (%s): %w", i, r.Name, err)
		}
		if seen[r.Name] {
			return fmt.Errorf("redis: the name %q is used twice", r.Name)
		}
		seen[r.Name] = true
	}
	return nil
}
