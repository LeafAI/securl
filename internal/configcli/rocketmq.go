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

const rocketmqUsage = "usage: securl config rocketmq add [flags] | list | remove <name>"

func cmdRocketMQ(env Env, args []string) error {
	if len(args) == 0 {
		return errors.New(rocketmqUsage)
	}
	switch args[0] {
	case "add":
		return rocketmqAdd(env, args[1:])
	case "list":
		return rocketmqList(env)
	case "remove":
		if len(args) != 2 {
			return errors.New("usage: securl config rocketmq remove <name>")
		}
		return rocketmqRemove(env, args[1])
	}
	return fmt.Errorf("unknown rocketmq command %q (add, list, remove)\n%s", clipArg(args[0]), rocketmqUsage)
}

// rocketmqFlags are the answers that can be given instead of asked. There is no flag for an AccessKey or a SecretKey: they are typed
// by a person on the login page and kept in the vault, never in a file, a shell history or a process listing.
type rocketmqFlags struct {
	scripted                                       bool
	name, namesrv, environment, topics, tls, group string
	maxMessages                                    int
	maxBody                                        int
	maxBodySet                                     bool
	timeout                                        time.Duration
}

func parseRocketMQFlags(args []string) (rocketmqFlags, error) {
	var f rocketmqFlags
	fs := flag.NewFlagSet("rocketmq add", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&f.name, "name", "", "")
	fs.StringVar(&f.namesrv, "namesrv", "", "")
	fs.StringVar(&f.environment, "environment", "", "")
	fs.StringVar(&f.topics, "topics", "", "")
	fs.StringVar(&f.tls, "tls", "", "")
	fs.StringVar(&f.group, "consumer-group", "", "")
	fs.IntVar(&f.maxMessages, "max-messages", 0, "")
	fs.IntVar(&f.maxBody, "max-body-bytes", 0, "")
	fs.DurationVar(&f.timeout, "timeout", 0, "")
	if err := fs.Parse(args); err != nil {
		return f, fmt.Errorf("%s (flags: --name --namesrv --environment --topics --tls --consumer-group --max-messages --max-body-bytes --timeout; an access key or a secret key is never given here: a person types them when an agent opens a session)", flagProblem(err))
	}
	if fs.NArg() > 0 {
		return f, fmt.Errorf("unexpected argument %q", clipArg(fs.Arg(0)))
	}
	fs.Visit(func(fl *flag.Flag) {
		f.scripted = true
		if fl.Name == "max-body-bytes" {
			f.maxBodySet = true // 0 written out means "no body", which is not the same as not saying
		}
	})
	return f, nil
}

func rocketmqAdd(env Env, args []string) error {
	f, err := parseRocketMQFlags(args)
	if err != nil {
		return err
	}
	p := prompter(env)
	ed, err := openEditor(env)
	if err != nil {
		return err
	}
	r, err := collectRocketMQ(p, f)
	if err != nil {
		return err
	}
	if err := confirmReplaceNamed(p, "A RocketMQ target", r.Name, func() ([]string, error) {
		have, err := ed.RocketMQTargets()
		var names []string
		for _, h := range have {
			names = append(names, h.Name)
		}
		return names, err
	}); err != nil {
		return err
	}
	if err := ed.SetRocketMQ(r); err != nil {
		return err
	}
	if err := commit(env, ed); err != nil {
		return err
	}
	p.Say("\nNo key is needed here: a person types the AccessKey and the SecretKey when an agent asks.")
	p.Say("The agent opens it with session_open and url rocketmq://%s; session_close with that url forgets the keys.", r.Name)
	p.Say("An agent can only read messages, and only from the topics listed here. Give the key a subscribe permission on those topics and nothing else: that is the boundary that holds.")
	return nil
}

// collectRocketMQ builds a target from the flags and asks for what is missing. Every answer is checked with the check the
// configuration applies when it loads, so a mistake is found here and not when an agent runs.
func collectRocketMQ(p *Prompter, f rocketmqFlags) (config.RocketMQ, error) {
	var r config.RocketMQ
	var err error
	if f.scripted {
		// A script has nobody to ask: what it left out is named, instead of the command running out of input.
		for flagName, given := range map[string]string{"--name": f.name, "--namesrv": f.namesrv, "--topics": f.topics} {
			if strings.TrimSpace(given) == "" {
				return r, fmt.Errorf("%s is needed: say it with the flag, or run `securl config rocketmq add` with no flags to be asked", flagName)
			}
		}
	}
	if r.Name, err = textOr(p, f.name, "Name an agent will call it (letters, digits, . _ -)", "", true, checkRMQName); err != nil {
		return r, err
	}
	ns, err := textOr(p, f.namesrv, "NameServer address(es), comma separated, as host or host:port (default port 9876)", "", true, checkRMQNameServers)
	if err != nil {
		return r, err
	}
	r.NameServers = splitList(ns)
	p.Say("Production clusters are not offered here.")
	if r.Environment, err = choiceOr(p, f.environment, "Which environment is it?", []string{"dev", "test", "staging"}, "dev"); err != nil {
		return r, err
	}
	p.Say("An agent can read only the topics you list here; there is no wildcard and no \"every topic\". The broker's own topics (RMQ_SYS_*, %%RETRY%%*, %%DLQ%%*) are not offered.")
	tp, err := textOr(p, f.topics, "Topics an agent may read, comma separated", "", true, checkRMQTopics)
	if err != nil {
		return r, err
	}
	r.Topics = splitList(tp)
	if f.scripted && f.tls == "" {
		r.TLS = ""
	} else if r.TLS, err = rmqTLSOr(p, f.tls); err != nil {
		return r, err
	}
	r.ConsumerGroup = strings.TrimSpace(f.group)
	r.MaxMessages, r.Timeout = f.maxMessages, f.timeout
	if f.maxBodySet {
		n := f.maxBody
		r.MaxBodyBytes = &n
	}
	if err := validateRMQOne(r); err != nil {
		return r, err
	}
	return r, nil
}

// rmqTLSOr asks how the connection is protected. RocketMQ's remoting port is plain unless the broker was set up for TLS, so the
// default here is the opposite of the databases': disable.
func rmqTLSOr(p *Prompter, given string) (string, error) {
	choices := []string{config.TLSDisable, config.TLSVerify, config.TLSSkipVerify}
	if given == "" {
		p.Say("RocketMQ's port is plain unless the broker was set up for TLS. disable is the usual; verify checks the server's certificate; skip-verify encrypts without checking who answers.")
	}
	v, err := choiceOr(p, given, "How should the connection be protected?", choices, config.TLSDisable)
	if err != nil || v == config.TLSDisable {
		return "", err
	}
	return v, nil
}

func validateRMQOne(r config.RocketMQ) error {
	c := &config.Config{RocketMQ: []config.RocketMQ{r}}
	return c.Validate()
}

func rmqBase() config.RocketMQ {
	return config.RocketMQ{Name: "x", NameServers: []string{"h.example"}, Environment: "dev", Topics: []string{"t"}}
}

func checkRMQName(v string) error {
	r := rmqBase()
	r.Name = v
	if err := validateRMQOne(r); err != nil {
		return errors.New("use 1-64 letters, digits, '.', '_' or '-'")
	}
	return nil
}

func checkRMQNameServers(v string) error {
	r := rmqBase()
	r.NameServers = splitList(v)
	if err := validateRMQOne(r); err != nil {
		return errors.New("give host or host:port, up to eight, separated by commas, with no scheme, user or path")
	}
	return nil
}

func checkRMQTopics(v string) error {
	r := rmqBase()
	r.Topics = splitList(v)
	if err := validateRMQOne(r); err != nil {
		return errors.New("plain topic names (letters, digits, _ . -), separated by commas; no wildcard and none of the broker's own")
	}
	return nil
}

func rocketmqList(env Env) error {
	ed, err := openEditor(env)
	if err != nil {
		return err
	}
	have, err := ed.RocketMQTargets()
	if err != nil {
		return err
	}
	if len(have) == 0 {
		fmt.Fprintln(env.Out, "no RocketMQ targets configured (add one with: securl config rocketmq add)")
		return nil
	}
	tw := tabwriter.NewWriter(env.Out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tENV\tNAMESRV\tTOPICS")
	for _, r := range have {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.Name, r.Environment, strings.Join(r.NameServerAddrs(), ","), strings.Join(r.Topics, ","))
	}
	return tw.Flush()
}

func rocketmqRemove(env Env, name string) error {
	ed, err := openEditor(env)
	if err != nil {
		return err
	}
	if !ed.RemoveRocketMQ(name) {
		return fmt.Errorf("no RocketMQ target named %q (see: securl config rocketmq list)", clipArg(name))
	}
	if err := commit(env, ed); err != nil {
		return err
	}
	fmt.Fprintf(env.Out, "The keys saved for it stay in the vault until it is closed: ask the agent to call session_close with url rocketmq://%s.\n", strings.TrimSpace(name))
	return nil
}
