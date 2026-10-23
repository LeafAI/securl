// Package climode runs the MCP tools from the command line. It does not reimplement any tool: it starts the same server
// in this process, talks to it over an in-memory MCP connection like any other client, and prints the answer. A tool
// therefore behaves the same from the shell as from an agent: the same validation, the same limits, the same audit trail,
// and no answer ever carries a credential.
package climode

import (
	"sort"
	"strings"
)

// commandPath turns a tool name into the words of its command: session_open is `session open`, archery_run_sql is
// `archery run-sql`, and a tool with no group (request) is a command by itself.
func commandPath(tool string) (group, sub string) {
	g, s, found := strings.Cut(tool, "_")
	if !found {
		return tool, ""
	}
	return g, flagName(s)
}

// flagName turns a field name into a flag name: max_block_seconds is --max-block-seconds.
func flagName(field string) string { return strings.ReplaceAll(field, "_", "-") }

// notCommands are the tools that have no command, with the reason. Every other tool is a command; a tool that is added and
// is neither fails a test, so nothing is left out by accident.
var notCommands = map[string]string{
	"vault_status": "`securl vault status` already exists and prints whether the vault is there, locked or open; a published command is " +
		"not changed to print JSON, and what the tool adds (a pending unlock, the count of wrong passphrases) belongs to a server that " +
		"keeps running, not to a process that ends with the command",
	"vault_unlock": "a command-line process opens the vault for itself and locks it again when it ends, so an unlock command " +
		"would open nothing that outlives it; every command that needs the vault asks for the passphrase (or sends the remote " +
		"unlock) by itself, and `securl vault` keeps its own commands",
}

// commandNames rewrites the tool names in a description into the commands that run them: a person at a terminal reads
// "call session_open", and there is no such thing to type. A name that is part of a longer word is not touched, a name in
// backticks keeps one pair, and a tool with no command (skip) is left as the tool's name, which is all it has. The bare word
// "request" is not rewritten: it is also an ordinary English word, and the description says what it means.
func commandNames(text string, tools []string, skip map[string]bool) string {
	sorted := append([]string(nil), tools...)
	sort.Slice(sorted, func(i, j int) bool { return len(sorted[i]) > len(sorted[j]) })
	for _, tool := range sorted {
		if skip[tool] || !strings.Contains(tool, "_") {
			continue
		}
		g, s := commandPath(tool)
		repl := "`securl " + g + " " + s + "`"
		text = replaceWord(text, tool, repl)
	}
	return text
}

// replaceWord replaces whole-word occurrences of word, and a pair of backticks around one.
func replaceWord(text, word, repl string) string {
	var b strings.Builder
	for i := 0; i < len(text); {
		j := strings.Index(text[i:], word)
		if j < 0 {
			b.WriteString(text[i:])
			break
		}
		start, end := i+j, i+j+len(word)
		before := byte(' ')
		if start > 0 {
			before = text[start-1]
		}
		after := byte(' ')
		if end < len(text) {
			after = text[end]
		}
		if isWordByte(before) || isWordByte(after) {
			b.WriteString(text[i:end])
			i = end
			continue
		}
		b.WriteString(text[i:start])
		if before == '`' && after == '`' {
			// the backticks were the writer's: take them over instead of doubling them
			s := b.String()
			b.Reset()
			b.WriteString(s[:len(s)-1])
			b.WriteString(repl)
			i = end + 1
			continue
		}
		b.WriteString(repl)
		i = end
	}
	return b.String()
}

func isWordByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}
