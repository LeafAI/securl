package configcli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/LeafAI/securl/internal/config"
)

const zulipUsage = "usage: securl config zulip add [flags] | list | remove <name>"

func cmdZulip(env Env, args []string) error {
	if len(args) == 0 {
		return errors.New(zulipUsage)
	}
	switch args[0] {
	case "add":
		return zulipAdd(env, args[1:])
	case "list":
		return zulipList(env)
	case "remove":
		if len(args) != 2 {
			return errors.New("usage: securl config zulip remove <name>")
		}
		return zulipRemove(env, args[1])
	}
	return fmt.Errorf("unknown zulip command %q (add, list, remove)\n%s", clipArg(args[0]), zulipUsage)
}

// zulipFlags are the answers that can be given instead of asked. There is no flag for a key of any kind: it is typed by a person on
// the login page and kept in the vault, never in a file, a shell history or a process listing. And there is none for a topic: the
// agent chooses the topic of every message it sends and reads.
type zulipFlags struct {
	scripted           bool
	name, site, email  string
	channels           chatFlags
	sendLimit, readMsg int
	sendWindow         time.Duration
}

func parseZulipFlags(args []string) (zulipFlags, error) {
	var f zulipFlags
	fs := flag.NewFlagSet("zulip add", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&f.name, "name", "", "")
	fs.StringVar(&f.site, "site", "", "")
	fs.StringVar(&f.email, "email", "", "")
	fs.Var(&f.channels, "channel", "")
	fs.IntVar(&f.sendLimit, "send-limit", 0, "")
	fs.DurationVar(&f.sendWindow, "send-window", 0, "")
	fs.IntVar(&f.readMsg, "read-messages", 0, "")
	if err := fs.Parse(args); err != nil {
		return f, fmt.Errorf("%s (flags: --name --site --email --channel name=ZulipChannel[:read|:send] (repeat it) --send-limit --send-window --read-messages; a bot's key is never given here: a person types it when an agent opens a session)", flagProblem(err))
	}
	if fs.NArg() > 0 {
		return f, fmt.Errorf("unexpected argument %q", clipArg(fs.Arg(0)))
	}
	fs.Visit(func(*flag.Flag) { f.scripted = true })
	return f, nil
}

func zulipAdd(env Env, args []string) error {
	f, err := parseZulipFlags(args)
	if err != nil {
		return err
	}
	p := prompter(env)
	ed, err := openEditor(env)
	if err != nil {
		return err
	}
	z, err := collectZulip(p, f)
	if err != nil {
		return err
	}
	if err := confirmReplaceNamed(p, "A Zulip server", z.Name, func() ([]string, error) {
		have, err := ed.ZulipServers()
		var names []string
		for _, h := range have {
			names = append(names, h.Name)
		}
		return names, err
	}); err != nil {
		return err
	}
	if err := ed.SetZulip(z); err != nil {
		return err
	}
	if err := commit(env, ed); err != nil {
		return err
	}
	p.Say("\nNo key is needed here: a person types the bot's API key when an agent asks.")
	p.Say("The agent opens it with session_open and url zulip://%s; session_close with that url forgets the key.", z.Name)
	p.Say("In Zulip, make the bot of type \"Generic bot\" (an incoming or outgoing webhook bot cannot read channels), subscribe it to each channel above, and copy its email here and its API key to the page. Only the bot's owner can see the key.")
	p.Say("The agent chooses the topic of every message; the bot sees nothing said before it was subscribed. Anyone in those channels can read what the agent sends, and what is said there is shown to the agent as data it must not obey.")
	return nil
}

// collectZulip builds a server from the flags and asks for what is missing. Every answer is checked with the check the configuration
// applies when it loads, so a mistake is found here and not when an agent runs.
func collectZulip(p *Prompter, f zulipFlags) (config.Zulip, error) {
	var z config.Zulip
	var err error
	if f.scripted {
		// A script has nobody to ask: what it left out is named, instead of the command running out of input.
		for _, need := range []struct{ flag, given string }{{"--name", f.name}, {"--site", f.site}, {"--email", f.email}} {
			if strings.TrimSpace(need.given) == "" {
				return z, fmt.Errorf("%s is needed: say it with the flag, or run `securl config zulip add` with no flags to be asked", need.flag)
			}
		}
		if len(f.channels) == 0 {
			return z, errors.New("--channel name=ZulipChannel is needed: the agent can use only the channels written down")
		}
	}
	if z.Name, err = textOr(p, f.name, "Name an agent will call the server (letters, digits, . _ -)", "", true, checkZulipName); err != nil {
		return z, err
	}
	if z.Site, err = textOr(p, f.site, "The server's address, like https://yourorg.zulipchat.com", "", true, checkZulipSite); err != nil {
		return z, err
	}
	if z.Email, err = textOr(p, f.email, "The bot's email (Zulip shows it in the bot's settings; the key is typed later, not here)", "", true, checkZulipEmail); err != nil {
		return z, err
	}
	if len(f.channels) > 0 {
		for _, spec := range f.channels {
			c, err := parseZulipChannelSpec(spec)
			if err != nil {
				return z, err
			}
			z.Channels = append(z.Channels, c)
		}
	} else if z.Channels, err = askZulipChannels(p); err != nil {
		return z, err
	}
	z.SendMax, z.SendPeriod, z.ReadCount = f.sendLimit, f.sendWindow, f.readMsg
	if err := validateZulip(z); err != nil {
		return z, err
	}
	return z, nil
}

func askZulipChannels(p *Prompter) ([]config.ZulipChannel, error) {
	p.Say("Channels the agent may use. The bot must be subscribed to each. You give Zulip's name for it (it may have spaces); the agent will use the short name you choose here.")
	var out []config.ZulipChannel
	for {
		label := "Name an agent will call the channel"
		if len(out) > 0 {
			label += " (Enter: no more channels)"
		}
		name, err := p.Ask(label, "", checkZulipChannelName) // an empty answer is not checked: it ends the list
		if err != nil {
			return nil, err
		}
		if name == "" {
			return out, nil
		}
		zname, err := p.Require("Its name in Zulip", "", checkZulipChannelTitle)
		if err != nil {
			return nil, err
		}
		c := config.ZulipChannel{Name: name, Channel: zname}
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

// parseZulipChannelSpec reads name=ZulipChannel, with :read or :send after it to allow only that. The name Zulip gives a channel can
// have a colon in it, so only a trailing :read or :send is a mode.
func parseZulipChannelSpec(spec string) (config.ZulipChannel, error) {
	name, rest, ok := strings.Cut(spec, "=")
	if !ok {
		return config.ZulipChannel{}, fmt.Errorf("--channel %q: give name=ZulipChannel, like dev=\"Dev Team\"", clipArg(spec))
	}
	c := config.ZulipChannel{Name: strings.TrimSpace(name), Channel: rest}
	no := false
	switch {
	case strings.HasSuffix(rest, ":read:send"), strings.HasSuffix(rest, ":send:read"):
		return config.ZulipChannel{}, fmt.Errorf("--channel %s: a channel that can neither be read nor sent to is of no use", clipArg(name))
	case strings.HasSuffix(rest, ":read"):
		c.Channel, c.Send = strings.TrimSuffix(rest, ":read"), &no
	case strings.HasSuffix(rest, ":send"):
		c.Channel, c.Read = strings.TrimSuffix(rest, ":send"), &no
	case strings.HasSuffix(rest, ":both"):
		return config.ZulipChannel{}, fmt.Errorf("--channel %s: after the channel write :read or :send, or nothing for both", clipArg(name))
	}
	return c, nil
}

func checkZulipName(v string) error {
	if err := validateZulip(config.Zulip{Name: v, Site: "https://x.example.com", Email: "b@x.example.com", Channels: []config.ZulipChannel{{Name: "x", Channel: "x"}}}); err != nil {
		return errors.New("use 1-64 letters, digits, '.', '_' or '-'")
	}
	return nil
}

func checkZulipSite(v string) error {
	if err := validateZulip(config.Zulip{Name: "x", Site: v, Email: "b@x.example.com", Channels: []config.ZulipChannel{{Name: "x", Channel: "x"}}}); err != nil {
		return errors.New("use the server's address only, starting with https:// (not a path, a user name or an address on this machine)")
	}
	return nil
}

func checkZulipEmail(v string) error {
	if err := validateZulip(config.Zulip{Name: "x", Site: "https://x.example.com", Email: v, Channels: []config.ZulipChannel{{Name: "x", Channel: "x"}}}); err != nil {
		return errors.New("an email address like bot-bot@yourorg.zulipchat.com, with no space")
	}
	return nil
}

func checkZulipChannelName(v string) error {
	if err := validateZulip(config.Zulip{Name: "x", Site: "https://x.example.com", Email: "b@x.example.com", Channels: []config.ZulipChannel{{Name: v, Channel: "x"}}}); err != nil {
		return errors.New("use 1-64 letters, digits, '.', '_' or '-'")
	}
	return nil
}

func checkZulipChannelTitle(v string) error {
	if err := validateZulip(config.Zulip{Name: "x", Site: "https://x.example.com", Email: "b@x.example.com", Channels: []config.ZulipChannel{{Name: "x", Channel: v}}}); err != nil {
		return errors.New("the channel's name as Zulip shows it: one line of at most 60 characters, and not a number")
	}
	return nil
}

// validateZulip runs the configuration's own check on one server, so the questions and the file can never disagree.
func validateZulip(z config.Zulip) error {
	c := &config.Config{Zulip: []config.Zulip{z}}
	return c.Validate()
}

func zulipList(env Env) error {
	ed, err := openEditor(env)
	if err != nil {
		return err
	}
	have, err := ed.ZulipServers()
	if err != nil {
		return err
	}
	if len(have) == 0 {
		fmt.Fprintln(env.Out, "no Zulip servers configured (add one with: securl config zulip add)")
		return nil
	}
	tw := tabwriter.NewWriter(env.Out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SERVER\tSITE\tCHANNEL\tZULIP NAME\tREAD\tSEND")
	for _, z := range have {
		for _, c := range z.Channels {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", z.Name, strings.TrimPrefix(z.Site, "https://"), c.Name, c.Channel, yesNo(c.CanRead()), yesNo(c.CanSend()))
		}
	}
	return tw.Flush()
}

func zulipRemove(env Env, name string) error {
	ed, err := openEditor(env)
	if err != nil {
		return err
	}
	if !ed.RemoveZulip(name) {
		return fmt.Errorf("no Zulip server named %q (see: securl config zulip list)", clipArg(name))
	}
	if err := commit(env, ed); err != nil {
		return err
	}
	fmt.Fprintf(env.Out, "A key saved for it stays in the vault until it is closed: ask the agent to call session_close with url zulip://%s.\n", name)
	return nil
}
