package config

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Telegram lets an agent speak in, and read from, the Telegram chats the owner has named. The bot's token is a secret that a
// person types on a page and that stays in the vault: it is never a field here, and a file that has one is refused.
//
// An agent names a bot and a chat; it never supplies a chat id. A bot that is in many chats can therefore be used only
// where the owner wrote it down.
type Telegram struct {
	// Proxy is an optional http, https or socks5 proxy that reaches api.telegram.org, as http://host:port. It may carry a
	// credential (http://user:password@host:port); it is never shown with it.
	Proxy string        `yaml:"proxy"`
	Bots  []TelegramBot `yaml:"bots"`
}

// TelegramBot is one bot, and the chats it may be used in.
type TelegramBot struct {
	Name  string         `yaml:"name"`
	Chats []TelegramChat `yaml:"chats"`
	// SendMax is how many messages the bot sends in one send_window (default 20 in a minute), across all of its chats.
	SendMax    int           `yaml:"send_limit"`
	SendPeriod time.Duration `yaml:"send_window"`
	// ReadCount is how many messages one read returns when the call does not say (default 50, at most 100).
	ReadCount int `yaml:"read_messages"`
}

// TelegramChat is one chat the agent may name. Reading and sending are both on unless the chat says otherwise.
type TelegramChat struct {
	Name   string `yaml:"name"`
	ChatID int64  `yaml:"chat_id"` // a group or supergroup is negative, a private chat is positive
	Read   *bool  `yaml:"read"`    // false: the agent cannot read this chat
	Send   *bool  `yaml:"send"`    // false: the agent cannot send to this chat
}

// Limits that no configuration can raise.
const (
	telegramHardSendLimit = 200
	telegramHardRead      = 100
	telegramDefaultSend   = 20
	telegramDefaultRead   = 50

	// telegramMaxText is how much of a message the agent may write: Telegram takes 4096 characters, and the line that says an
	// AI agent wrote it takes some of them.
	telegramMaxText = 4000
)

var telegramNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// CanRead says whether the agent may read this chat. It may unless the chat says no.
func (c TelegramChat) CanRead() bool { return c.Read == nil || *c.Read }

// CanSend says whether the agent may send to this chat. It may unless the chat says no.
func (c TelegramChat) CanSend() bool { return c.Send == nil || *c.Send }

// Chat finds a chat of the bot by its exact name. An id is not a name: the agent never supplies one.
func (b TelegramBot) Chat(name string) (TelegramChat, bool) {
	if name == "" {
		return TelegramChat{}, false
	}
	for _, c := range b.Chats {
		if c.Name == name {
			return c, true
		}
	}
	return TelegramChat{}, false
}

// SendLimit is how many messages the bot sends in a window.
func (b TelegramBot) SendLimit() int {
	if b.SendMax > 0 {
		return b.SendMax
	}
	return telegramDefaultSend
}

// SendWindow is the length of the window the limit counts in.
func (b TelegramBot) SendWindow() time.Duration {
	if b.SendPeriod > 0 {
		return b.SendPeriod
	}
	return time.Minute
}

// ReadMessages is how many messages a read returns when the call gives no number.
func (b TelegramBot) ReadMessages() int {
	if b.ReadCount > 0 {
		return b.ReadCount
	}
	return telegramDefaultRead
}

// MaxReadMessages is the most a read may return.
func (TelegramBot) MaxReadMessages() int { return telegramHardRead }

// MaxTextRunes is the most characters of text the agent may send in one message.
func (TelegramBot) MaxTextRunes() int { return telegramMaxText }

// TelegramBot finds a bot by its exact name.
func (c *Config) TelegramBot(name string) (TelegramBot, bool) {
	if name == "" {
		return TelegramBot{}, false
	}
	for _, b := range c.Telegram.Bots {
		if b.Name == name {
			return b, true
		}
	}
	return TelegramBot{}, false
}

// ProxyForDisplay is the proxy as it may be shown: the credential, if there is one, is left out.
func (t Telegram) ProxyForDisplay() string {
	u, err := url.Parse(t.Proxy)
	if err != nil || u.User == nil {
		return t.Proxy
	}
	u.User = nil
	return u.String()
}

func (c TelegramChat) validate() error {
	if !telegramNamePattern.MatchString(c.Name) {
		return fmt.Errorf("name %q: use 1-64 letters, digits, '.', '_' or '-'", c.Name)
	}
	if c.ChatID == 0 {
		return fmt.Errorf("chat_id: give the chat's id (a group's is negative, like -1001234567890)")
	}
	if !c.CanRead() && !c.CanSend() {
		return fmt.Errorf("a chat that can neither be read nor sent to is of no use; remove it")
	}
	return nil
}

func (b TelegramBot) validate() error {
	if !telegramNamePattern.MatchString(b.Name) {
		return fmt.Errorf("name %q: use 1-64 letters, digits, '.', '_' or '-'", b.Name)
	}
	if len(b.Chats) == 0 {
		return fmt.Errorf("a bot needs at least one chat: the agent can use only the chats written down here")
	}
	names, ids := map[string]bool{}, map[int64]string{}
	for i, c := range b.Chats {
		if err := c.validate(); err != nil {
			return fmt.Errorf("chats[%d] (%s): %w", i, c.Name, err)
		}
		if names[c.Name] {
			return fmt.Errorf("chats: the name %q is used twice", c.Name)
		}
		if other, dup := ids[c.ChatID]; dup {
			return fmt.Errorf("chats: %q and %q have the same chat_id", other, c.Name)
		}
		names[c.Name], ids[c.ChatID] = true, c.Name
	}
	if b.SendMax < 0 || b.SendMax > telegramHardSendLimit {
		return fmt.Errorf("send_limit %d: use 1-%d", b.SendMax, telegramHardSendLimit)
	}
	if b.SendPeriod < 0 || b.SendPeriod > 24*time.Hour {
		return fmt.Errorf("send_window %s: use up to 24h", b.SendPeriod)
	}
	if b.ReadCount < 0 || b.ReadCount > telegramHardRead {
		return fmt.Errorf("read_messages %d: use 1-%d", b.ReadCount, telegramHardRead)
	}
	return nil
}

func (t Telegram) validate() error {
	if t.Proxy != "" {
		u, err := url.Parse(t.Proxy)
		switch {
		case err != nil || u.Host == "":
			return fmt.Errorf("proxy: give an address like http://127.0.0.1:1080")
		case u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5":
			return fmt.Errorf("proxy: the scheme is http, https or socks5")
		case u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "":
			return fmt.Errorf("proxy: give the address only, with no path or query")
		}
	}
	seen := map[string]bool{}
	for i, b := range t.Bots {
		if err := b.validate(); err != nil {
			return fmt.Errorf("telegram.bots[%d] (%s): %w", i, b.Name, err)
		}
		if seen[b.Name] {
			return fmt.Errorf("telegram.bots: the name %q is used twice", b.Name)
		}
		seen[b.Name] = true
	}
	return nil
}

// envTelegramProxy overrides the proxy: a machine may need one in one place and not in another. There is no variable for the
// token, on purpose: a secret that is in the environment is in every child process and in its listing.
const envTelegramProxy = "SECURL_TELEGRAM_PROXY"

func (c *Config) applyTelegramEnv(get func(string) string) {
	if v := strings.TrimSpace(get(envTelegramProxy)); v != "" {
		c.Telegram.Proxy = v
	}
}
