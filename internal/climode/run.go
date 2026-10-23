package climode

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/mcpserver"
	"github.com/LeafAI/securl/internal/vault"
)

// Exit codes. 0 is a tool that answered; the others say which kind of failure it was, so a script can tell a typo from a
// refusal from a person who did not answer.
const (
	exitToolError = 1 // the tool ran and answered with an error (its JSON is on stdout)
	exitUsage     = 2 // the command line was wrong: nothing ran
	exitSetup     = 3 // the configuration or the vault could not be set up: nothing ran
	exitPending   = 4 // the tool is still waiting for a person; its answer says how to continue
)

// Env is everything a command needs from the process around it. Tests give their own.
type Env struct {
	Config *config.Config
	Vault  *vault.Vault
	In     io.Reader
	Out    io.Writer // the answer: one JSON document
	Err    io.Writer // everything else: progress, prompts, messages
	// Secret reads one line without echo. It is set only when standard input is a terminal: it is the one and only way
	// this program reads the vault passphrase locally. With no terminal the vault is opened remotely, like for an agent.
	Secret func() (string, error)
	Server mcpserver.Options
	// NoDaemon makes the command run in its own process even when a daemon is running (--no-daemon).
	NoDaemon bool
	// AfterConnect, when set, is called once the command is connected to its backend: a test uses it to make the daemon go
	// away at the one moment that matters.
	AfterConnect func()
	// DaemonHandshake is how long to wait for a daemon to answer the start of the session (default 10 s). Something that
	// accepts a connection and says nothing is not a daemon, and a command must not wait for ever for it.
	DaemonHandshake time.Duration
}

// Prepare takes the program's own flags (-config <path>, --no-daemon) out of the arguments and returns the rest with them. It
// needs no configuration: the tools, and so which words are the value of a tool's flag, do not depend on it. The command line
// is read before the configuration is, because -config says which one to read.
func Prepare(args []string) (rest []string, configPath string, noDaemon bool, err error) {
	cfg := &config.Config{}
	cat, err := catalog(Env{Config: cfg, Vault: vault.New(os.TempDir() + "/securl-prepare-unused"), Err: io.Discard, NoDaemon: true})
	if err != nil {
		return nil, "", false, err
	}
	rest, configPath, noDaemon = cat.SplitOwnFlags(args)
	return rest, configPath, noDaemon, nil
}

// Run executes `securl <group> <command> --flags ...` and returns the exit code.
func Run(ctx context.Context, args []string, env Env) int {
	tools, err := catalog(env)
	if err != nil {
		fmt.Fprintf(env.Err, "securl: %v\n", err)
		return exitSetup
	}
	// The program's own flags are taken out with the catalog at hand: it knows which words are the value of a tool's flag.
	var noDaemon bool
	args, _, noDaemon = tools.SplitOwnFlags(args)
	env.NoDaemon = env.NoDaemon || noDaemon
	cmd, rest, err := tools.find(args)
	if err != nil {
		fmt.Fprintf(env.Err, "securl: %v\n\n%s", err, tools.usage())
		return exitUsage
	}
	if wantsHelp(rest) {
		fmt.Fprint(env.Out, cmd.help())
		return 0
	}
	input, err := cmd.parse(rest, env.In)
	if err != nil {
		fmt.Fprintf(env.Err, "securl %s: %v (see --help)\n", strings.Join(args[:cmd.words], " "), err)
		return exitUsage
	}
	return tools.call(ctx, env, cmd, input)
}

func wantsHelp(args []string) bool {
	for _, a := range args {
		if a == "-h" || a == "--help" || a == "-help" {
			return true
		}
	}
	return false
}

// callTool runs one tool on the in-process server and returns its answer.
func callTool(ctx context.Context, cs *mcp.ClientSession, tool string, input map[string]any) (map[string]any, bool, error) {
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: input})
	if err != nil {
		return nil, false, err
	}
	var out map[string]any
	if res.StructuredContent != nil {
		b, err := json.Marshal(res.StructuredContent)
		if err != nil {
			return nil, false, err
		}
		if err := json.Unmarshal(b, &out); err != nil {
			return nil, false, err
		}
	}
	return out, res.IsError, nil
}

var errNoTool = errors.New("no such command")

// sortedKeys is a stable order for listings.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
