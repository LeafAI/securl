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
	"github.com/LeafAI/securl/internal/configedit"
)

const dingtalkUsage = "usage: securl config dingtalk group add [flags] | list | remove <name>"

// cmdDingTalk is the groups an agent may speak in. The robot that carries login links to a person is set up by `securl config init`
// and is not this: it has one webhook for one purpose, and the groups each have their own.
func cmdDingTalk(env Env, args []string) error {
	if len(args) == 0 || args[0] != "group" || len(args) == 1 {
		return errors.New(dingtalkUsage)
	}
	rest := args[2:]
	switch args[1] {
	case "add":
		return dingtalkGroupAdd(env, rest)
	case "list":
		return dingtalkGroupList(env)
	case "remove":
		if len(rest) != 1 {
			return errors.New("usage: securl config dingtalk group remove <name>")
		}
		return dingtalkGroupRemove(env, rest[0])
	}
	return fmt.Errorf("unknown dingtalk group command %q (add, list, remove)\n%s", clipArg(args[1]), dingtalkUsage)
}

// dingtalkFlags are the answers that can be given instead of asked. There is no flag for a webhook or a signing secret of any kind: a
// person pastes them on the login page and they are kept in the vault, never in a file, a shell history or a process listing.
type dingtalkFlags struct {
	scripted   bool
	name       string
	sign       bool
	keyword    string
	sendLimit  int
	sendWindow time.Duration
}

func parseDingTalkFlags(args []string) (dingtalkFlags, error) {
	var f dingtalkFlags
	fs := flag.NewFlagSet("dingtalk group add", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&f.name, "name", "", "")
	fs.BoolVar(&f.sign, "sign", false, "")
	fs.StringVar(&f.keyword, "keyword", "", "")
	fs.IntVar(&f.sendLimit, "send-limit", 0, "")
	fs.DurationVar(&f.sendWindow, "send-window", 0, "")
	if err := fs.Parse(args); err != nil {
		return f, fmt.Errorf("%s (flags: --name --sign --keyword --send-limit --send-window; a webhook or a signing secret is never given here: a person pastes it when an agent opens a session)", flagProblem(err))
	}
	if fs.NArg() > 0 {
		return f, fmt.Errorf("unexpected argument %q", clipArg(fs.Arg(0)))
	}
	fs.Visit(func(*flag.Flag) { f.scripted = true })
	return f, nil
}

func dingtalkGroupAdd(env Env, args []string) error {
	f, err := parseDingTalkFlags(args)
	if err != nil {
		return err
	}
	p := prompter(env)
	ed, err := openEditor(env)
	if err != nil {
		return err
	}
	g, err := collectDingTalkGroup(p, f)
	if err != nil {
		return err
	}
	if err := confirmReplaceGroup(p, ed, g.Name); err != nil {
		return err
	}
	if err := ed.SetDingTalkGroup(g); err != nil {
		return err
	}
	if err := commit(env, ed); err != nil {
		return err
	}
	p.Say("\nNo webhook is needed here: a person pastes the group robot's webhook when an agent asks.")
	p.Say("The agent opens it with session_open and url dingtalk://%s; session_close with that url forgets the webhook.", g.Name)
	p.Say("Make the robot in the group (group settings, Robots, Custom robot) and copy its webhook from its settings.")
	if g.Sign {
		p.Say("Its signing secret (starts with SEC) is asked for on the same page.")
	}
	p.Say("Everyone in the group can read what the agent sends. There is no way to read the group: a custom robot only sends.")
	return nil
}

// collectDingTalkGroup builds a group from the flags and asks for what is missing. Every answer is checked with the check the
// configuration applies when it loads, so a mistake is found here and not when an agent runs.
func collectDingTalkGroup(p *Prompter, f dingtalkFlags) (config.DingTalkGroup, error) {
	var g config.DingTalkGroup
	var err error
	if g.Name, err = textOr(p, f.name, "Name an agent will call the group (letters, digits, . _ -)", "", true, checkGroupName); err != nil {
		return g, err
	}
	g.Sign, g.Keyword = f.sign, f.keyword
	if !f.scripted {
		if g.Sign, err = p.Confirm("Does the robot sign its messages (its security setting is \"sign\")? A signing secret is then asked for with the webhook", false); err != nil {
			return g, err
		}
		if g.Keyword, err = p.Ask("The robot's keyword, if its security setting has one (Enter: none)", "", checkGroupKeyword); err != nil {
			return g, err
		}
	}
	g.SendMax, g.SendPeriod = f.sendLimit, f.sendWindow
	if err := validateGroup(g); err != nil {
		return g, err
	}
	return g, nil
}

func checkGroupName(v string) error {
	if err := validateGroup(config.DingTalkGroup{Name: v}); err != nil {
		return errors.New("use 1-64 letters, digits, '.', '_' or '-'")
	}
	return nil
}

func checkGroupKeyword(v string) error {
	if err := validateGroup(config.DingTalkGroup{Name: "x", Keyword: v}); err != nil {
		return errors.New("one line of at most 64 characters")
	}
	return nil
}

// validateGroup runs the configuration's own check on one group, so the questions and the file can never disagree.
func validateGroup(g config.DingTalkGroup) error {
	c := &config.Config{DingTalk: config.DingTalk{Groups: []config.DingTalkGroup{g}}}
	return c.Validate()
}

func confirmReplaceGroup(p *Prompter, ed *configedit.Editor, name string) error {
	have, err := ed.DingTalkGroups()
	if err != nil {
		return err
	}
	for _, h := range have {
		if h.Name == name {
			ok, err := p.Confirm(fmt.Sprintf("A DingTalk group named %q already exists. Replace it?", name), false)
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

func dingtalkGroupList(env Env) error {
	ed, err := openEditor(env)
	if err != nil {
		return err
	}
	have, err := ed.DingTalkGroups()
	if err != nil {
		return err
	}
	if len(have) == 0 {
		fmt.Fprintln(env.Out, "no DingTalk groups configured (add one with: securl config dingtalk group add)")
		return nil
	}
	tw := tabwriter.NewWriter(env.Out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "GROUP\tSIGN\tKEYWORD\tLIMIT")
	for _, g := range have {
		kw := g.Keyword
		if kw == "" {
			kw = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d per %s\n", g.Name, yesNo(g.Sign), strings.Join(strings.Fields(kw), " "), g.SendLimit(), g.SendWindow())
	}
	return tw.Flush()
}

func dingtalkGroupRemove(env Env, name string) error {
	ed, err := openEditor(env)
	if err != nil {
		return err
	}
	if !ed.RemoveDingTalkGroup(name) {
		return fmt.Errorf("no DingTalk group named %q (see: securl config dingtalk group list)", clipArg(name))
	}
	if err := commit(env, ed); err != nil {
		return err
	}
	fmt.Fprintf(env.Out, "A webhook saved for it stays in the vault until it is closed: ask the agent to call session_close with url dingtalk://%s.\n", name)
	return nil
}
