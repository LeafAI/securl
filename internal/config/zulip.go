package config

import (
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// Zulip is one Zulip server an agent may send to and read from, as one bot, in the channels the owner has named. The bot's API key is a
// secret that a person types on a page and that stays in the vault: it is never a field here, and a file that has one is refused.
//
// An agent names a server and one of its channels by the name the owner gave it; it never supplies a site, an email, a Zulip channel
// of its own. A bot that is subscribed to many channels can therefore be used only where the owner wrote it down. The topic is the
// one thing the agent does name: a topic is a conversation, and which one is meant is the agent's to say (see ValidZulipTopic).
type Zulip struct {
	Name  string `yaml:"name"`
	Site  string `yaml:"site"`  // https://yourorg.zulipchat.com: the one place the key is ever sent
	Email string `yaml:"email"` // the bot's email address, which Zulip calls its API email: not a secret
	// Channels are the channels the agent may use, each under a name of the owner's choosing.
	Channels []ZulipChannel `yaml:"channels"`
	// SendMax is how many messages the bot sends in one send_window (default 20 in a minute), across all of its channels.
	SendMax    int           `yaml:"send_limit"`
	SendPeriod time.Duration `yaml:"send_window"`
	// ReadCount is how many messages one read returns when the call does not say (default 50, at most 100).
	ReadCount int `yaml:"read_messages"`
}

// ZulipChannel is one channel the agent may name. Reading and sending are both on unless the channel says otherwise.
type ZulipChannel struct {
	Name    string `yaml:"name"`    // what the agent calls it
	Channel string `yaml:"channel"` // the channel's name in Zulip: free text, with spaces
	Read    *bool  `yaml:"read"`    // false: the agent cannot read this channel
	Send    *bool  `yaml:"send"`    // false: the agent cannot send to this channel
}

// Limits that no configuration can raise, and the defaults.
const (
	zulipHardSendLimit = 200
	zulipHardRead      = 100
	zulipDefaultSend   = 20
	zulipDefaultRead   = 50

	// zulipMaxText is how much of a message the agent may write. Zulip's own default limit is 10000 characters (a server can set another,
	// and says so when it refuses); the line that says an AI agent wrote it takes some of them.
	zulipMaxText = 9000

	// zulipMaxName bounds a channel name and zulipMaxTopic a topic: Zulip's own limits are 60 characters for each.
	zulipMaxName  = 60
	zulipMaxTopic = 60
)

var zulipNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// CanRead says whether the agent may read this channel. It may unless the channel says no.
func (c ZulipChannel) CanRead() bool { return c.Read == nil || *c.Read }

// CanSend says whether the agent may send to this channel. It may unless the channel says no.
func (c ZulipChannel) CanSend() bool { return c.Send == nil || *c.Send }

// Channel finds a channel of the server by the exact name the owner gave it. A Zulip channel name or an id is not that name: the agent
// never supplies one.
func (z Zulip) Channel(name string) (ZulipChannel, bool) {
	if name == "" {
		return ZulipChannel{}, false
	}
	for _, c := range z.Channels {
		if c.Name == name {
			return c, true
		}
	}
	return ZulipChannel{}, false
}

// SendLimit is how many messages the bot sends in a window.
func (z Zulip) SendLimit() int {
	if z.SendMax > 0 {
		return z.SendMax
	}
	return zulipDefaultSend
}

// SendWindow is the length of the window the limit counts in.
func (z Zulip) SendWindow() time.Duration {
	if z.SendPeriod > 0 {
		return z.SendPeriod
	}
	return time.Minute
}

// ReadMessages is how many messages a read returns when the call gives no number.
func (z Zulip) ReadMessages() int {
	if z.ReadCount > 0 {
		return z.ReadCount
	}
	return zulipDefaultRead
}

// MaxReadMessages is the most a read may return.
func (Zulip) MaxReadMessages() int { return zulipHardRead }

// MaxTextRunes is the most characters of text the agent may send in one message.
func (Zulip) MaxTextRunes() int { return zulipMaxText }

// ZulipServer finds a server by its exact name.
func (c *Config) ZulipServer(name string) (Zulip, bool) {
	if name == "" {
		return Zulip{}, false
	}
	for _, z := range c.Zulip {
		if z.Name == name {
			return z, true
		}
	}
	return Zulip{}, false
}

// ValidZulipTopic says whether an agent may use s as a topic: one non-blank line of at most 60 characters, the limit Zulip itself has.
// A topic is shown to everyone in the channel as the title of a conversation, so what is refused here is what would break that
// title (a line break, a control character) and not what a topic may say.
func ValidZulipTopic(s string) error {
	switch {
	case strings.TrimSpace(s) == "":
		return fmt.Errorf("a topic is needed: it is the title of the conversation")
	case len([]rune(s)) > zulipMaxTopic:
		return fmt.Errorf("a topic is at most %d characters", zulipMaxTopic)
	case !oneLine(s):
		return fmt.Errorf("a topic is one line with no control characters and no space at either end")
	}
	return nil
}

// oneLine reports whether s is text on one line, with no control character and nothing that can end a line.
func oneLine(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return false
		}
	}
	return s == strings.TrimSpace(s)
}

func (c ZulipChannel) validate() error {
	if !zulipNamePattern.MatchString(c.Name) {
		return fmt.Errorf("name %q: use 1-64 letters, digits, '.', '_' or '-'", c.Name)
	}
	n := []rune(c.Channel)
	switch {
	case len(n) == 0:
		return fmt.Errorf("channel: give the channel's name in Zulip")
	case len(n) > zulipMaxName || !oneLine(c.Channel):
		return fmt.Errorf("channel %q: one line of at most %d characters, as Zulip names it", c.Channel, zulipMaxName)
	case isNumber(c.Channel):
		return fmt.Errorf("channel %q: give the channel's name, not its number", c.Channel)
	}
	if !c.CanRead() && !c.CanSend() {
		return fmt.Errorf("a channel that can neither be read nor sent to is of no use; remove it")
	}
	return nil
}

func isNumber(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// validZulipSite checks the site the way the client does: https, a host, and nothing else, and not this machine.
func validZulipSite(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("site: give the address of the Zulip server, like https://yourorg.zulipchat.com")
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil || u.Host == "":
		return fmt.Errorf("site: that is not an address (use https://yourorg.zulipchat.com)")
	case u.Scheme != "https":
		return fmt.Errorf("site: it must start with https://: the bot's key is sent there")
	case u.User != nil:
		return fmt.Errorf("site: it must not have a user name in it")
	case (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "":
		return fmt.Errorf("site: give the server only, with no path, query or fragment")
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); host == "localhost" || ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()) {
		return fmt.Errorf("site: that is an address on this machine or its network, which is not a Zulip server to send a key to")
	}
	return nil
}

func (z Zulip) validate() error {
	if !zulipNamePattern.MatchString(z.Name) {
		return fmt.Errorf("name %q: use 1-64 letters, digits, '.', '_' or '-'", z.Name)
	}
	if err := validZulipSite(z.Site); err != nil {
		return err
	}
	if a, err := mail.ParseAddress(z.Email); err != nil || a.Address != z.Email || strings.ContainsAny(z.Email, " \t\r\n:") {
		return fmt.Errorf("email: give the bot's email address, like bot-bot@yourorg.zulipchat.com")
	}
	if len(z.Channels) == 0 {
		return fmt.Errorf("a server needs at least one channel: the agent can use only the channels written down here")
	}
	names, where := map[string]bool{}, map[string]string{}
	for i, c := range z.Channels {
		if err := c.validate(); err != nil {
			return fmt.Errorf("channels[%d] (%s): %w", i, c.Name, err)
		}
		if names[c.Name] {
			return fmt.Errorf("channels: the name %q is used twice", c.Name)
		}
		if other, dup := where[c.Channel]; dup {
			return fmt.Errorf("channels: %q and %q are the same Zulip channel", other, c.Name)
		}
		names[c.Name], where[c.Channel] = true, c.Name
	}
	if z.SendMax < 0 || z.SendMax > zulipHardSendLimit {
		return fmt.Errorf("send_limit %d: use 1-%d", z.SendMax, zulipHardSendLimit)
	}
	if z.SendPeriod < 0 || z.SendPeriod > 24*time.Hour {
		return fmt.Errorf("send_window %s: use up to 24h", z.SendPeriod)
	}
	if z.ReadCount < 0 || z.ReadCount > zulipHardRead {
		return fmt.Errorf("read_messages %d: use 1-%d", z.ReadCount, zulipHardRead)
	}
	return nil
}

func validateZulip(zs []Zulip) error {
	seen := map[string]bool{}
	for i, z := range zs {
		if err := z.validate(); err != nil {
			return fmt.Errorf("zulip[%d] (%s): %w", i, z.Name, err)
		}
		if seen[z.Name] {
			return fmt.Errorf("zulip: the name %q is used twice", z.Name)
		}
		seen[z.Name] = true
	}
	return nil
}
