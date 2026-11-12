package configcli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/configedit"
)

const telegramUsage = "usage: securl config telegram add [flags] | list | remove <name>"

func cmdTelegram(env Env, args []string) error {
	if len(args) == 0 {
		return errors.New(telegramUsage)
	}
	switch args[0] {
	case "add":
		return telegramAdd(env, args[1:])
	case "list":
		return telegramList(env)
	case "remove":
		if len(args) != 2 {
			return errors.New("usage: securl config telegram remove <name>")
		}
		return telegramRemove(env, args[1])
	}
	return fmt.Errorf("unknown telegram command %q (add, list, remove)", args[0])
}

// chatFlags collects --chat name=id[:read|:send], given once per chat.
type chatFlags []string

func (c *chatFlags) String() string     { return strings.Join(*c, ",") }
func (c *chatFlags) Set(v string) error { *c = append(*c, v); return nil }

// telegramFlags are the answers that can be given instead of asked. There is no flag for a token of any kind: it is typed by a
// person on the login page and kept in the vault, never in a file, a shell history or a process listing.
type telegramFlags struct {
	scripted    bool
	name        string
	chats       chatFlags
	sendLimit   int
	sendWindow  time.Duration
	readMessage int
}

func parseTelegramFlags(args []string) (telegramFlags, error) {
	var f telegramFlags
	fs := flag.NewFlagSet("telegram add", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&f.name, "name", "", "")
	fs.Var(&f.chats, "chat", "")
	fs.IntVar(&f.sendLimit, "send-limit", 0, "")
	fs.DurationVar(&f.sendWindow, "send-window", 0, "")
	fs.IntVar(&f.readMessage, "read-messages", 0, "")
	if err := fs.Parse(args); err != nil {
		return f, fmt.Errorf("%s (flags: --name --chat name=id[:read|:send] (repeat it) --send-limit --send-window --read-messages; a bot token is never given here: a person types it when an agent opens a session)", flagProblem(err))
	}
	if fs.NArg() > 0 {
		return f, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	fs.Visit(func(*flag.Flag) { f.scripted = true })
	return f, nil
}

func telegramAdd(env Env, args []string) error {
	f, err := parseTelegramFlags(args)
	if err != nil {
		return err
	}
	p := prompter(env)
	ed, err := openEditor(env)
	if err != nil {
		return err
	}
	b, err := collectTelegramBot(p, f)
	if err != nil {
		return err
	}
	if err := confirmReplaceBot(p, ed, b.Name); err != nil {
		return err
	}
	if err := ed.SetTelegramBot(b); err != nil {
		return err
	}
	if err := commit(env, ed); err != nil {
		return err
	}
	p.Say("\nNo token is needed here: a person types the bot's token when an agent asks.")
	p.Say("The agent opens it with session_open and url telegram://%s; session_close with that url forgets the token.", b.Name)
	p.Say("Make the bot with @BotFather (/newbot), add it to each chat, and turn off its privacy mode (/setprivacy) if it should read every message of a group.")
	p.Say("Anyone in those chats can read what the agent sends, and what is said there is shown to the agent as data it must not obey.")
	return nil
}

// collectTelegramBot builds a bot from the flags and asks for what is missing. Every answer is checked with the check the
// configuration applies when it loads, so a mistake is found here and not when an agent runs.
func collectTelegramBot(p *Prompter, f telegramFlags) (config.TelegramBot, error) {
	var b config.TelegramBot
	var err error
	if b.Name, err = textOr(p, f.name, "Name an agent will call the bot (letters, digits, . _ -)", "", true, checkBotName); err != nil {
		return b, err
	}
	if len(f.chats) > 0 {
		for _, spec := range f.chats {
			c, err := parseChatSpec(spec)
			if err != nil {
				return b, err
			}
			b.Chats = append(b.Chats, c)
		}
	} else if f.scripted {
		return b, errors.New("--chat name=id is needed: the agent can use only the chats written down")
	} else if b.Chats, err = askChats(p); err != nil {
		return b, err
	}
	b.SendMax, b.SendPeriod, b.ReadCount = f.sendLimit, f.sendWindow, f.readMessage
	if err := validateBot(b); err != nil {
		return b, err
	}
	return b, nil
}

func askChats(p *Prompter) ([]config.TelegramChat, error) {
	p.Say("Chats the agent may use. A group's id is negative (like -1001234567890); @RawDataBot or the Bot API's getUpdates shows it.")
	var out []config.TelegramChat
	for {
		label := "Name an agent will call the chat"
		if len(out) > 0 {
			label += " (Enter: no more chats)"
		}
		name, err := p.Ask(label, "", func(v string) error {
			if v == "" && len(out) > 0 {
				return nil
			}
			return checkChatName(v)
		})
		if err != nil {
			return nil, err
		}
		if name == "" {
			return out, nil
		}
		idText, err := p.Require("Its chat id", "", func(v string) error {
			if n, err := strconv.ParseInt(v, 10, 64); err != nil || n == 0 {
				return errors.New("a whole number that is not 0, like -1001234567890")
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		id, _ := strconv.ParseInt(idText, 10, 64)
		c := config.TelegramChat{Name: name, ChatID: id}
		for _, q := range []struct {
			label string
			set   func(bool)
		}{
			{"May the agent read what is said in " + name + "?", func(v bool) {
				if !v {
					c.Read = &v
				}
			}},
			{"May the agent send messages to " + name + "?", func(v bool) {
				if !v {
					c.Send = &v
				}
			}},
		} {
			ok, err := p.Confirm(q.label, true)
			if err != nil {
				return nil, err
			}
			q.set(ok)
		}
		out = append(out, c)
	}
}

// parseChatSpec reads name=id, with :read or :send after the id to allow only that.
func parseChatSpec(spec string) (config.TelegramChat, error) {
	name, rest, ok := strings.Cut(spec, "=")
	if !ok {
		return config.TelegramChat{}, fmt.Errorf("--chat %q: give name=chat_id, like alerts=-1001234567890", clipArg(spec))
	}
	idText, mode, _ := strings.Cut(rest, ":")
	id, err := strconv.ParseInt(strings.TrimSpace(idText), 10, 64)
	if err != nil || id == 0 {
		return config.TelegramChat{}, fmt.Errorf("--chat %s: the chat id is a whole number that is not 0", clipArg(name))
	}
	c := config.TelegramChat{Name: strings.TrimSpace(name), ChatID: id}
	no := false
	switch mode {
	case "":
	case "read":
		c.Send = &no
	case "send":
		c.Read = &no
	default:
		return config.TelegramChat{}, fmt.Errorf("--chat %s: after the id write :read or :send, or nothing for both", clipArg(name))
	}
	return c, nil
}

// clipArg keeps what is echoed of an argument short and on one line.
func clipArg(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 40 {
		s = s[:40] + "..."
	}
	return s
}

func checkBotName(v string) error {
	if err := validateBot(config.TelegramBot{Name: v, Chats: []config.TelegramChat{{Name: "x", ChatID: 1}}}); err != nil {
		return errors.New("use 1-64 letters, digits, '.', '_' or '-'")
	}
	return nil
}

func checkChatName(v string) error {
	if err := validateBot(config.TelegramBot{Name: "x", Chats: []config.TelegramChat{{Name: v, ChatID: 1}}}); err != nil {
		return errors.New("use 1-64 letters, digits, '.', '_' or '-'")
	}
	return nil
}

// validateBot runs the configuration's own check on one bot, so the questions and the file can never disagree.
func validateBot(b config.TelegramBot) error {
	c := &config.Config{Telegram: config.Telegram{Bots: []config.TelegramBot{b}}}
	return c.Validate()
}

func confirmReplaceBot(p *Prompter, ed *configedit.Editor, name string) error {
	have, err := ed.TelegramBots()
	if err != nil {
		return err
	}
	for _, h := range have {
		if h.Name == name {
			ok, err := p.Confirm(fmt.Sprintf("A Telegram bot named %q already exists. Replace it?", name), false)
			if err != nil {
				return err
			}
			if !ok {
				return errCancelled
			}
			return nil
		}
	}
	return nil
}

func telegramList(env Env) error {
	ed, err := openEditor(env)
	if err != nil {
		return err
	}
	have, err := ed.TelegramBots()
	if err != nil {
		return err
	}
	if len(have) == 0 {
		fmt.Fprintln(env.Out, "no Telegram bots configured (add one with: securl config telegram add)")
		return nil
	}
	tw := tabwriter.NewWriter(env.Out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "BOT\tCHAT\tREAD\tSEND")
	for _, b := range have {
		for _, c := range b.Chats {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", b.Name, c.Name, yesNo(c.CanRead()), yesNo(c.CanSend()))
		}
	}
	return tw.Flush()
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func telegramRemove(env Env, name string) error {
	ed, err := openEditor(env)
	if err != nil {
		return err
	}
	if !ed.RemoveTelegramBot(name) {
		return fmt.Errorf("no Telegram bot named %q (see: securl config telegram list)", clipArg(name))
	}
	if err := commit(env, ed); err != nil {
		return err
	}
	fmt.Fprintf(env.Out, "A token saved for it stays in the vault until it is closed: ask the agent to call session_close with url telegram://%s.\n", name)
	return nil
}
