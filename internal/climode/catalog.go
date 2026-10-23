package climode

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// A catalog is the tools of the server, as commands. It is built by asking the server for its tool list, which is what any
// MCP client does, so the commands are exactly the tools that exist.
type catalog_ struct {
	cmds map[string]*command // by "group sub" ("request" for a tool with no group)
}

func catalog(env Env) (*catalog_, error) {
	cs, closeFn, _, err := connectApp(context.Background(), env, false)
	if err != nil {
		return nil, err
	}
	defer closeFn()
	list, err := cs.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		return nil, fmt.Errorf("listing the tools: %w", err)
	}
	c := &catalog_{cmds: map[string]*command{}}
	var names []string
	for _, t := range list.Tools {
		names = append(names, t.Name)
	}
	skip := map[string]bool{}
	for n := range notCommands {
		skip[n] = true
	}
	for _, t := range list.Tools {
		if _, left := notCommands[t.Name]; left {
			continue
		}
		schema, err := inputSchemaOf(t)
		if err != nil {
			return nil, err
		}
		cmd, err := newCommand(t.Name, t.Title, commandNames(t.Description, names, skip), schema)
		if err != nil {
			return nil, err
		}
		g, s := commandPath(t.Name)
		cmd.words = 1
		key := g
		if s != "" {
			cmd.words, key = 2, g+" "+s
		}
		cmd.group, cmd.sub = g, s
		c.cmds[key] = cmd
	}
	return c, nil
}

// find picks the command named by the first words of args and returns the rest.
func (c *catalog_) find(args []string) (*command, []string, error) {
	if len(args) == 0 {
		return nil, nil, fmt.Errorf("no command given")
	}
	if cmd, ok := c.cmds[args[0]]; ok && cmd.words == 1 {
		return cmd, args[1:], nil
	}
	if len(args) > 1 {
		if cmd, ok := c.cmds[args[0]+" "+args[1]]; ok {
			return cmd, args[2:], nil
		}
	}
	if len(args) == 1 || strings.HasPrefix(args[1], "-") {
		if subs := c.subcommands(args[0]); len(subs) > 0 {
			return nil, nil, fmt.Errorf("%q needs one of: %s", args[0], strings.Join(subs, ", "))
		}
	}
	return nil, nil, fmt.Errorf("%w: %q", errNoTool, strings.Join(firstN(args, 2), " "))
}

func firstN(s []string, n int) []string {
	if len(s) < n {
		return s
	}
	return s[:n]
}

func (c *catalog_) subcommands(group string) []string {
	var out []string
	for _, cmd := range c.cmds {
		if cmd.group == group && cmd.sub != "" {
			out = append(out, cmd.sub)
		}
	}
	sort.Strings(out)
	return out
}

// usage lists the commands, grouped.
func (c *catalog_) usage() string {
	var b strings.Builder
	b.WriteString("Commands (each is one MCP tool; add --help for its flags):\n")
	for _, k := range sortedKeys(c.cmds) {
		fmt.Fprintf(&b, "  securl %-26s %s\n", k, c.cmds[k].title)
	}
	return b.String()
}

// SplitOwnFlags takes the program's own flags (-config <path>, --no-daemon) out of the arguments and returns the rest. They may
// stand anywhere, but not where a tool flag has just asked for its value: `--sql --no-daemon` gives the text "--no-daemon" to
// --sql. The command is found from the first words, and its flags tell which of them take a value.
func (c *catalog_) SplitOwnFlags(args []string) (rest []string, configPath string, noDaemon bool) {
	rest = make([]string, 0, len(args))
	var cmd *command
	words := 0 // words of the command name seen so far
	for i := 0; i < len(args); i++ {
		a := args[i]
		if cmd == nil || words < cmd.words {
			// still in the name of the command: a flag of ours may stand here, and the words are the name
			if own, skip, path := ownFlag(args, i); own {
				if path != "" {
					configPath = path
				}
				if skip == 0 {
					noDaemon = true
				}
				i += skip
				continue
			}
			rest = append(rest, a)
			if !strings.HasPrefix(a, "-") {
				words++
				cmd = c.lookupPrefix(rest)
			}
			continue
		}
		if own, skip, path := ownFlag(args, i); own {
			if path != "" {
				configPath = path
			}
			if skip == 0 {
				noDaemon = true
			}
			i += skip
			continue
		}
		rest = append(rest, a)
		if takesValue(cmd, a) && i+1 < len(args) {
			i++
			rest = append(rest, args[i]) // the value belongs to the tool, whatever it looks like
		}
	}
	return rest, configPath, noDaemon
}

// ownFlag reports whether args[i] is a flag of the program, how many arguments after it belong to it, and the path of -config.
func ownFlag(args []string, i int) (own bool, extra int, path string) {
	a := args[i]
	switch {
	case a == "--no-daemon" || a == "-no-daemon":
		return true, 0, ""
	case (a == "-config" || a == "--config") && i+1 < len(args):
		return true, 1, args[i+1]
	case strings.HasPrefix(a, "-config=") || strings.HasPrefix(a, "--config="):
		_, p, _ := strings.Cut(a, "=")
		return true, 0, p
	}
	return false, 0, ""
}

// takesValue reports whether the flag a, as given to cmd, is one that is followed by its value in the next argument.
func takesValue(cmd *command, a string) bool {
	if !strings.HasPrefix(a, "--") || strings.Contains(a, "=") {
		return false
	}
	f := cmd.lookup(a[2:])
	return f != nil && f.kind != kBool
}

// lookupPrefix finds the command named by the words so far, or nil while they do not name one yet.
func (c *catalog_) lookupPrefix(words []string) *command {
	var name []string
	for _, w := range words {
		if !strings.HasPrefix(w, "-") {
			name = append(name, w)
		}
	}
	switch {
	case len(name) >= 2:
		if cmd, ok := c.cmds[name[0]+" "+name[1]]; ok {
			return cmd
		}
	case len(name) == 1:
		if cmd, ok := c.cmds[name[0]]; ok && cmd.words == 1 {
			return cmd
		}
	}
	return nil
}
