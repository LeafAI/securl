//go:build unix

package main

import "github.com/LeafAI/securl/internal/daemonlog"

func daemonlogResolve(spec, home string) (string, error) { return daemonlog.Resolve(spec, home) }
