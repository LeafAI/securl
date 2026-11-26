package driverbuild

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ExtraFile is the name of the Go file the build adds to the main package while it runs.
const ExtraFile = "drivers_extra.go"

// BuiltEnv is the environment variable the build command is told which drivers were linked in, as module@commit separated by
// spaces. A build script passes it on to the linker so that `securl version` can say which drivers the binary holds.
const BuiltEnv = "SECURL_DRIVERS_BUILT"

// Options say what to build.
type Options struct {
	Dir      string            // securl's source directory (where go.mod is)
	Specs    []Spec            // the external drivers; none means an ordinary build
	CloneURL func(Spec) string // where a driver is cloned from; nil means the ssh address of the Spec
	Command  []string          // the build command, run in Dir once the drivers are in place
	Stdout   io.Writer
	Stderr   io.Writer
	Env      []string // added to the environment of the build command (not of git)
	GitEnv   []string // added to the environment of git (the ssh command)
}

// Result says what was built in.
type Result struct {
	Drivers []Fetched
}

// Summary is one line per driver, "module@commit", the form BuiltEnv carries.
func (r *Result) Summary() string {
	parts := make([]string, 0, len(r.Drivers))
	for _, d := range r.Drivers {
		parts = append(parts, d.Spec.Module()+"@"+d.Commit)
	}
	return strings.Join(parts, " ")
}

// Build fetches the drivers, adds them to the main package for the length of one command, and runs the command. Everything is
// fetched and checked before anything is written, and what was written (the generated file and the module file the build uses) is
// removed again whether or not the command succeeds. The repository's own go.mod and go.sum are never changed.
func Build(o Options) (*Result, error) {
	if len(o.Command) == 0 {
		return nil, errors.New("driverbuild: no build command given")
	}
	// os.Stat of "" already fails, so the check below would stop this too; this one says the real reason.
	if o.Dir == "" {
		return nil, errors.New("driverbuild: no source directory given")
	}
	if st, err := os.Stat(o.Dir); err != nil || !st.IsDir() {
		return nil, errors.New("driverbuild: the source directory is not there")
	}
	res := &Result{}
	if len(o.Specs) == 0 {
		return res, run(o, nil, "")
	}
	work, err := os.MkdirTemp("", "securl-drivers-")
	if err != nil {
		return nil, errors.New("driverbuild: could not make a build directory")
	}
	defer os.RemoveAll(work)
	clone := o.CloneURL
	if clone == nil {
		clone = Spec.CloneURL
	}
	for i, s := range o.Specs {
		f, err := Fetch(s, clone(s), filepath.Join(work, fmt.Sprintf("d%d", i)), o.GitEnv)
		if err != nil {
			return nil, err
		}
		if err := f.CheckModule(); err != nil {
			return nil, err
		}
		res.Drivers = append(res.Drivers, *f)
	}
	extra := filepath.Join(o.Dir, ExtraFile)
	if _, err := os.Lstat(extra); err == nil {
		return nil, fmt.Errorf("driverbuild: %s already exists in the source directory; it is not overwritten", ExtraFile)
	}
	base, err := os.ReadFile(filepath.Join(o.Dir, "go.mod"))
	if err != nil {
		return nil, errors.New("driverbuild: the source directory has no go.mod")
	}
	mod, err := Modfile(string(base), res.Drivers)
	if err != nil {
		return nil, err
	}
	modPath := filepath.Join(work, "go.mod")
	if err := os.WriteFile(modPath, []byte(mod), 0o600); err != nil {
		return nil, errors.New("driverbuild: could not write the module file")
	}
	if sum, err := os.ReadFile(filepath.Join(o.Dir, "go.sum")); err == nil {
		if err := os.WriteFile(filepath.Join(work, "go.sum"), sum, 0o600); err != nil {
			return nil, errors.New("driverbuild: could not write the checksum file")
		}
	}
	if err := os.WriteFile(extra, []byte(Source(res.Drivers, recordPackage(o.Dir, string(base)))), 0o600); err != nil {
		return nil, errors.New("driverbuild: could not write " + ExtraFile)
	}
	defer os.Remove(extra)
	return res, run(o, res, modPath)
}

// recordPackage is the import path of securl's mcpserver package when the source directory is securl itself: the module's own path
// and internal/mcpserver, if that directory is there. Another tree (a test's, say) has none, and the drivers are then only linked in.
func recordPackage(dir, gomod string) string {
	mod := ""
	for _, line := range strings.Split(gomod, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			mod = strings.Trim(strings.TrimSpace(rest), `"`)
			break
		}
	}
	if mod == "" {
		return ""
	}
	if st, err := os.Stat(filepath.Join(dir, "internal", "mcpserver")); err != nil || !st.IsDir() {
		return ""
	}
	return mod + "/internal/mcpserver"
}

func run(o Options, res *Result, modfile string) error {
	cmd := exec.Command(o.Command[0], o.Command[1:]...)
	cmd.Dir = o.Dir
	cmd.Stdout, cmd.Stderr = o.Stdout, o.Stderr
	env := append(os.Environ(), o.Env...)
	if modfile != "" {
		// -mod=mod lets go write the checksums of what the drivers need into the build's own go.sum, which is thrown away with it.
		env = append(env, "GOFLAGS="+strings.TrimSpace(os.Getenv("GOFLAGS")+" -mod=mod -modfile="+modfile), BuiltEnv+"="+res.Summary())
	}
	cmd.Env = env
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("driverbuild: the build command failed: %w", exitOnly(err))
	}
	return nil
}

// ExitError is a failure of the build command that kept its exit status, so that a caller can end with the same one.
type ExitError struct{ Code int }

func (e *ExitError) Error() string { return fmt.Sprintf("exit status %d", e.Code) }

// exitOnly keeps what the failure was (an exit status) and drops anything else the error carries.
func exitOnly(err error) error {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return &ExitError{Code: ee.ExitCode()}
	}
	return errors.New("it could not be started")
}
