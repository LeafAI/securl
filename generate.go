//go:build ignore

// generate builds securl with login drivers that live in other repositories (a private one, say), by adding them to the main
// package for the length of one command:
//
//	go run generate.go --driver gitlab.example.com/group/repo@v1.2.3 -- go build -o securl .
//	SECURL_DRIVERS="gitlab.example.com/group/repo@<40-digit commit>" go run generate.go -- make rpm
//
// A driver is host/path@revision, cloned over ssh, and the revision is pinned: a version tag or a full commit hash. Nothing in
// the repository is changed (the module file the build uses is a separate one) and what was added is removed afterwards.
// See docs/DRIVERS.md.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/LeafAI/securl/internal/driverbuild"
)

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, " ") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	var drivers listFlag
	fs.Var(&drivers, "driver", "a driver to build in: host/group/repo@revision (repeatable; SECURL_DRIVERS is read too)")
	key := fs.String("ssh-key", os.Getenv("SECURL_DRIVERS_SSH_KEY"), "an ssh key to clone with, instead of the agent's (an absolute path)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	command := fs.Args()
	if len(command) == 0 {
		fmt.Fprintln(os.Stderr, "generate: give the build command after --, like: go run generate.go --driver host/g/r@v1.0.0 -- make rpm")
		return 2
	}
	specs, err := driverbuild.ParseList(os.Getenv("SECURL_DRIVERS") + " " + strings.Join(drivers, " "))
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate:", err)
		return 2
	}
	gitEnv, err := driverbuild.GitEnvFor(*key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate:", err)
		return 2
	}
	dir, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate: cannot tell the current directory")
		return 2
	}
	// SECURL_SOURCE_DIR names the tree to build when it is not the one this is run in. A test uses it; a person has no need to.
	if d := os.Getenv("SECURL_SOURCE_DIR"); d != "" {
		dir = d
	}
	res, err := driverbuild.Build(driverbuild.Options{Dir: dir, Specs: specs, Command: command, GitEnv: gitEnv, Stdout: os.Stdout, Stderr: os.Stderr})
	if res != nil && len(res.Drivers) > 0 {
		fmt.Fprintln(os.Stderr, "generate: built in:", res.Summary())
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate:", err)
		if ee := exitCodeOf(err); ee != 0 {
			return ee
		}
		return 1
	}
	return 0
}

// exitCodeOf carries the status of the build command through: a failing build fails the same way with or without drivers.
func exitCodeOf(err error) int {
	var ee *driverbuild.ExitError
	if errors.As(err, &ee) {
		return ee.Code
	}
	return 0
}
