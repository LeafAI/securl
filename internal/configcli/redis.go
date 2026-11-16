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
)

const redisUsage = "usage: securl config redis add [flags] | list | remove <name>"

func cmdRedis(env Env, args []string) error {
	if len(args) == 0 {
		return errors.New(redisUsage)
	}
	switch args[0] {
	case "add":
		return redisAdd(env, args[1:])
	case "list":
		return redisList(env)
	case "remove":
		if len(args) != 2 {
			return errors.New("usage: securl config redis remove <name>")
		}
		return redisRemove(env, args[1])
	}
	return fmt.Errorf("unknown redis command %q (add, list, remove)\n%s", clipArg(args[0]), redisUsage)
}

// redisFlags are the answers that can be given instead of asked. There is no flag for a password of any kind: it is typed by a person
// on the login page and kept in the vault, never in a file, a shell history or a process listing. A user name is a name, so it may be
// given.
type redisFlags struct {
	scripted                                     bool
	name, host, environment, username, mode, tls string
	port, maxItems, maxReply                     int
	timeout                                      time.Duration
	yesWrites                                    bool
}

func parseRedisFlags(args []string) (redisFlags, error) {
	var f redisFlags
	fs := flag.NewFlagSet("redis add", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&f.name, "name", "", "")
	fs.StringVar(&f.host, "host", "", "")
	fs.IntVar(&f.port, "port", 0, "")
	fs.StringVar(&f.environment, "environment", "", "")
	fs.StringVar(&f.username, "username", "", "")
	fs.StringVar(&f.mode, "mode", "", "")
	fs.StringVar(&f.tls, "tls", "", "")
	fs.IntVar(&f.maxItems, "max-items", 0, "")
	fs.IntVar(&f.maxReply, "max-reply-bytes", 0, "")
	fs.DurationVar(&f.timeout, "command-timeout", 0, "")
	fs.BoolVar(&f.yesWrites, "yes-allow-writes", false, "")
	if err := fs.Parse(args); err != nil {
		return f, fmt.Errorf("%s (flags: --name --host --port --environment --username --mode --tls --max-items --max-reply-bytes --command-timeout --yes-allow-writes; a password is never given here: a person types it when an agent opens a session)", flagProblem(err))
	}
	if fs.NArg() > 0 {
		return f, fmt.Errorf("unexpected argument %q", clipArg(fs.Arg(0)))
	}
	fs.Visit(func(*flag.Flag) { f.scripted = true })
	return f, nil
}

func redisAdd(env Env, args []string) error {
	f, err := parseRedisFlags(args)
	if err != nil {
		return err
	}
	p := prompter(env)
	ed, err := openEditor(env)
	if err != nil {
		return err
	}
	r, err := collectRedis(p, f)
	if err != nil {
		return err
	}
	if err := confirmReplaceNamed(p, "A Redis target", r.Name, func() ([]string, error) {
		have, err := ed.RedisTargets()
		var names []string
		for _, h := range have {
			names = append(names, h.Name)
		}
		return names, err
	}); err != nil {
		return err
	}
	if err := ed.SetRedis(r); err != nil {
		return err
	}
	if err := commit(env, ed); err != nil {
		return err
	}
	p.Say("\nNo password is needed here: a person types the Redis password when an agent asks.")
	p.Say("The agent opens it with session_open and url redis://%s; session_close with that url forgets the password.", r.Name)
	if r.Writable() {
		p.Say("This target takes changes: give the password (or the ACL user) only the rights an agent should have there. securl allows a short list of ordinary commands and refuses the rest, but Redis's own ACL is the boundary that holds.")
	} else {
		p.Say("An agent can only read from this target. Give the password (or the ACL user) read rights only: that is the boundary that holds.")
	}
	return nil
}

// collectRedis builds a target from the flags and asks for what is missing. Every answer is checked with the check the configuration
// applies when it loads, so a mistake is found here and not when an agent runs.
func collectRedis(p *Prompter, f redisFlags) (config.Redis, error) {
	var r config.Redis
	var err error
	if f.scripted {
		// A script has nobody to ask: what it left out is named, instead of the command running out of input.
		for flagName, given := range map[string]string{"--name": f.name, "--host": f.host} {
			if strings.TrimSpace(given) == "" {
				return r, fmt.Errorf("%s is needed: say it with the flag, or run `securl config redis add` with no flags to be asked", flagName)
			}
		}
	}
	if r.Name, err = textOr(p, f.name, "Name an agent will call it (letters, digits, . _ -)", "", true, checkRedisName); err != nil {
		return r, err
	}
	if r.Host, err = textOr(p, f.host, "Host name or address (no port, no scheme)", "", true, checkRedisHost); err != nil {
		return r, err
	}
	if r.Port, err = portOr(p, f.port, "6379", f.scripted); err != nil {
		return r, err
	}
	p.Say("Production servers are not offered here.")
	if r.Environment, err = choiceOr(p, f.environment, "Which environment is it?", []string{"dev", "test", "staging"}, "dev"); err != nil {
		return r, err
	}
	r.Username = f.username
	if !f.scripted {
		if r.Username, err = p.Ask("ACL user name, if the server uses one (Enter: none; the password is typed later, not here)", "", checkRedisUser); err != nil {
			return r, err
		}
	} else if r.Username != "" {
		if err := checkRedisUser(r.Username); err != nil {
			return r, fmt.Errorf("username: %w", err)
		}
	}
	if f.scripted && f.mode == "" {
		r.Mode = config.ModeReadOnly
	} else if r.Mode, err = choiceOr(p, f.mode, "May the agent change data?", []string{config.ModeReadOnly, config.ModeReadWrite}, config.ModeReadOnly); err != nil {
		return r, err
	}
	if r.Mode == config.ModeReadWrite {
		if err := askRedisWrites(p, f); err != nil {
			return r, err
		}
	} else if f.yesWrites {
		return r, errors.New("--yes-allow-writes belongs to a read_write target: add --mode read_write, or leave it out")
	}
	if f.scripted && f.tls == "" {
		r.TLS = ""
	} else if r.TLS, err = tlsOr(p, f.tls); err != nil {
		return r, err
	}
	r.MaxItems, r.MaxReplyBytes, r.CommandTimeout = f.maxItems, f.maxReply, f.timeout
	if err := validateRedisOne(r); err != nil {
		return r, err
	}
	return r, nil
}

// askRedisWrites confirms the one answer that is a decision about risk, and makes a script say so.
func askRedisWrites(p *Prompter, f redisFlags) error {
	if f.yesWrites {
		return nil
	}
	if f.scripted {
		return errors.New("mode read_write lets an agent change data on this server: add --yes-allow-writes to say that is intended")
	}
	ok, err := p.Confirm("An agent will be able to change data on this server (SET, DEL, INCR, HSET, EXPIRE and similar; never FLUSHALL, CONFIG, EVAL or KEYS; the team is told afterwards). Allow it?", false)
	if err != nil {
		return err
	}
	if !ok {
		return errCancelled
	}
	return nil
}

func validateRedisOne(r config.Redis) error {
	c := &config.Config{Redis: []config.Redis{r}}
	return c.Validate()
}

func checkRedisName(v string) error {
	if err := validateRedisOne(config.Redis{Name: v, Host: "h.example", Environment: "dev"}); err != nil {
		return errors.New("use 1-64 letters, digits, '.', '_' or '-'")
	}
	return nil
}

func checkRedisHost(v string) error {
	if err := validateRedisOne(config.Redis{Name: "x", Host: v, Environment: "dev"}); err != nil {
		return errors.New("give a host name or an address only, with no port, scheme or user")
	}
	return nil
}

func checkRedisUser(v string) error {
	if err := validateRedisOne(config.Redis{Name: "x", Host: "h.example", Environment: "dev", Username: v}); err != nil {
		return errors.New("one line of at most 64 characters")
	}
	return nil
}

// confirmReplaceNamed asks before a target with the same name is overwritten.
func confirmReplaceNamed(p *Prompter, what, name string, existing func() ([]string, error)) error {
	names, err := existing()
	if err != nil {
		return err
	}
	for _, n := range names {
		if n == name {
			ok, err := p.Confirm(fmt.Sprintf("%s named %q already exists. Replace it?", what, name), false)
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

func redisList(env Env) error {
	ed, err := openEditor(env)
	if err != nil {
		return err
	}
	have, err := ed.RedisTargets()
	if err != nil {
		return err
	}
	if len(have) == 0 {
		fmt.Fprintln(env.Out, "no Redis targets configured (add one with: securl config redis add)")
		return nil
	}
	tw := tabwriter.NewWriter(env.Out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tENV\tMODE\tHOST")
	for _, r := range have {
		mode := r.Mode
		if mode == "" {
			mode = config.ModeReadOnly
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.Name, r.Environment, mode, r.Host+":"+strconv.Itoa(r.PortOrDefault()))
	}
	return tw.Flush()
}

func redisRemove(env Env, name string) error {
	ed, err := openEditor(env)
	if err != nil {
		return err
	}
	if !ed.RemoveRedis(name) {
		return fmt.Errorf("no Redis target named %q (see: securl config redis list)", clipArg(name))
	}
	if err := commit(env, ed); err != nil {
		return err
	}
	fmt.Fprintf(env.Out, "A password saved for it stays in the vault until it is closed: ask the agent to call session_close with url redis://%s.\n", strings.TrimSpace(name))
	return nil
}
