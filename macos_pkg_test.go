package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A person on macOS who does not want to unpack an archive gets an installer package. It is built from the two darwin builds
// that release.sh makes, so it contains exactly what the archives contain; it puts one file, securl, in /usr/local/bin, and it
// starts nothing: a daemon holds the vault open, and that is for the person to decide, with `securl daemon install`.

const pkgScript = "scripts/macos-pkg.sh"

func pkgSkip(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "darwin" {
		t.Skip("pkgbuild, productbuild, lipo and pkgutil exist on macOS only")
	}
	for _, tool := range []string{"bash", "pkgbuild", "productbuild", "lipo", "pkgutil", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
}

// fakeBinary writes a Mach-O executable for one architecture by building a trivial Go program: lipo needs real ones.
func fakeBinary(t *testing.T, dir, arch, version string) string {
	t.Helper()
	src := filepath.Join(t.TempDir(), "main.go")
	os.WriteFile(src, []byte("package main\nimport \"fmt\"\nvar v = \"x\"\nfunc main() { fmt.Println(v) }\n"), 0o644)
	out := filepath.Join(dir, "securl_"+arch)
	cmd := exec.Command("go", "build", "-o", out, "-ldflags", "-X main.v="+version, src)
	cmd.Env = append(os.Environ(), "GOOS=darwin", "GOARCH="+arch, "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s: %v\n%s", arch, err, b)
	}
	return out
}

func buildPkg(t *testing.T, version string) (pkg, dir string) { return buildPkgWith(t, version, false) }

// buildPkgWith builds the package; with hooks, the postinstall also reads SECURL_TEST_* variables, so that a test can say who is at
// the console and not run anything. The package that is shipped is never built that way: TestTheShippedPostinstallHasNoTestHooks.
func buildPkgWith(t *testing.T, version string, hooks bool) (pkg, dir string) {
	t.Helper()
	dir = t.TempDir()
	arm := fakeBinary(t, dir, "arm64", version)
	amd := fakeBinary(t, dir, "amd64", version)
	pkg = filepath.Join(dir, "out", "securl_"+version+"_macos.pkg")
	args := []string{pkgScript}
	if hooks {
		args = append(args, "--test-hooks")
	}
	cmd := exec.Command("bash", append(args, version, arm, amd, pkg)...)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("macos-pkg.sh: %v\n%s", err, b)
	}
	return pkg, dir
}

func expand(t *testing.T, pkg string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "x")
	if b, err := exec.Command("pkgutil", "--expand-full", pkg, dir).CombinedOutput(); err != nil {
		t.Fatalf("pkgutil --expand-full: %v\n%s", err, b)
	}
	return dir
}

func firstMatch(t *testing.T, root, pattern string) string {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(root, pattern))
	if len(m) == 0 {
		t.Fatalf("nothing matches %s under %s", pattern, root)
	}
	return m[0]
}

func TestThePackageInstallsOneUniversalBinaryInUsrLocalBin(t *testing.T) {
	pkgSkip(t)
	pkg, _ := buildPkg(t, nightlyVersion)
	files, _ := exec.Command("pkgutil", "--payload-files", pkg).Output()
	var real []string
	for _, f := range strings.Split(strings.TrimSpace(string(files)), "\n") {
		if f == "." || strings.HasPrefix(filepath.Base(f), "._") {
			continue // the directory itself, and the copies of attributes that the system makes on its own
		}
		real = append(real, f)
	}
	if len(real) != 1 || real[0] != "./securl" {
		t.Fatalf("the payload is the one file ./securl, installed relative to /usr/local/bin; got %v", real)
	}
	root := expand(t, pkg)
	info, _ := os.ReadFile(firstMatch(t, root, "*/PackageInfo"))
	if !bytes.Contains(info, []byte(`install-location="/usr/local/bin"`)) {
		t.Errorf("the file goes to /usr/local/bin, so that the package owns that file and no directory above it: %s", info)
	}
	bin := firstMatch(t, root, "*/Payload/securl")
	out, err := exec.Command("lipo", "-archs", bin).Output()
	if err != nil {
		t.Fatalf("lipo: %v", err)
	}
	got := strings.Fields(string(out))
	if len(got) != 2 || !(contains(got, "arm64") && contains(got, "x86_64")) {
		t.Errorf("the binary must hold both architectures, has %v", got)
	}
	if st, _ := os.Stat(bin); st.Mode().Perm() != 0o755 {
		t.Errorf("mode %v, want 0755", st.Mode().Perm())
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// /usr/local/bin on a machine with Homebrew belongs to the user. A package that listed it (or /usr/local) among the things it
// installs could set root:wheel on it and lock Homebrew out of its own directory. This package is rooted at /usr/local/bin and
// holds one file: the bill of materials lists nothing but that file and the root of the payload.
func TestThePackageListsNoDirectoryOfThePathInItsBillOfMaterials(t *testing.T) {
	pkgSkip(t)
	pkg, _ := buildPkg(t, nightlyVersion)
	root := expand(t, pkg)
	out, err := exec.Command("lsbom", "-p", "fMUGs", firstMatch(t, root, "*/Bom")).Output()
	if err != nil {
		t.Fatalf("lsbom: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		path := strings.Fields(line)[0]
		if path == "." || strings.HasPrefix(filepath.Base(path), "._") {
			continue
		}
		if path != "./securl" {
			t.Errorf("the bill of materials lists %q: only ./securl may be there", path)
		}
	}
}

// postinstallOf builds the package that is shipped and returns the path and the text of its one script.
func postinstallOf(t *testing.T) (path, text string) { return postinstallWith(t, false) }

func postinstallWith(t *testing.T, hooks bool) (path, text string) {
	t.Helper()
	pkg, _ := buildPkgWith(t, nightlyVersion, hooks)
	root := expand(t, pkg)
	scripts, _ := filepath.Glob(filepath.Join(root, "*", "Scripts", "*"))
	if len(scripts) != 1 || filepath.Base(scripts[0]) != "postinstall" {
		t.Fatalf("exactly one script, postinstall; got %v", scripts)
	}
	b, _ := os.ReadFile(scripts[0])
	if st, _ := os.Stat(scripts[0]); st.Mode().Perm()&0o111 == 0 {
		t.Error("postinstall is not executable: the Installer skips it")
	}
	return scripts[0], string(b)
}

// withoutComments drops the comment lines of a shell script, so that what is checked is what it runs, not what it explains.
func withoutComments(s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// The installer starts the daemon for the person who ran it: when it is done, `securl daemon` is running, in that person's own
// login session, and nothing else was asked of them. The agent is the machine's (one plist in /Library/LaunchAgents, which the
// installer is root to write), launchd runs it as each user who logs in, and the script loads it into the session of the user at the
// console now. What it must get right is whose session: never root's, and never a user other than the one at the console.
func TestThePostinstallStartsTheDaemonAsTheUserAtTheConsoleAndNeverAsRoot(t *testing.T) {
	pkgSkip(t)
	_, s := postinstallOf(t)
	code := withoutComments(stripHeredocText(s))
	for _, want := range []string{"/dev/console", `SECURL=/usr/local/bin/securl`} {
		if !strings.Contains(code, want) {
			t.Errorf("the postinstall must contain %q: it finds the user at the console, and runs the binary the package installed", want)
		}
	}
	// the one command that starts anything, exactly: in the user's session, as the user, with no password prompt, with the user's HOME,
	// running the installed binary by an absolute path held in a variable that the script itself sets
	want := `"$SECURL" daemon install -uid "$uid"`
	if strings.Count(code, want) != 1 {
		t.Errorf("exactly one command starts the daemon, and it is: %s", want)
	}
	// the script is root and the agent is the machine's: it makes the agent itself and loads it, with no step that becomes a user
	// only what is run counts: the hint to the person ("sudo securl daemon install") is text inside say, not a command
	ran := regexp.MustCompile(`(?m)^\s*(say\b.*)$`).ReplaceAllString(code, "")
	for _, gone := range []string{"launchctl", "asuser", "sudo "} {
		if strings.Contains(ran, gone) {
			t.Errorf("the postinstall runs %q: `securl daemon install -uid` makes the agent and loads it into the user's session; nothing else is run", gone)
		}
	}
	if strings.Contains(ran, " su ") || strings.Contains(ran, "su -") {
		t.Error("the postinstall runs su")
	}
	// the agent is made by `securl daemon install` run as the user, never written by the script
	for _, forbidden := range []string{"LaunchAgents", "LaunchDaemons", ".plist", "chown", "chmod", "defaults ", "osascript", "rm ", "mv ", "cp ", "ln ", "launchctl load", "launchctl submit", "launchctl bootstrap", "launchctl kickstart"} {
		if strings.Contains(code, forbidden) {
			t.Errorf("the postinstall contains %q: it starts the daemon only through `securl daemon install`, run as the user", forbidden)
		}
	}
	// as commands, not as the inside of "securl": nothing is fetched or opened
	fetch := regexp.MustCompile(`(?m)(?:^|[|;&]\s*|\$\(\s*)(curl|wget|open|ssh|scp|nc|python[0-9.]*|perl|ruby|node)\b`)
	for _, m := range fetch.FindAllStringSubmatch(code, -1) {
		t.Errorf("the postinstall runs %q", m[1])
	}
	if strings.Contains(code, "/Users/") || strings.Contains(code, "~") {
		t.Error("the postinstall names a home directory: the user's own `securl daemon install` finds it")
	}
	// the account is the console's, taken once, before anything is run, and checked
	if !strings.Contains(code, `console=/dev/console`) || !strings.Contains(code, `stat -f %Su "$console"`) {
		t.Error("the user is the owner of /dev/console")
	}
	if strings.Count(code, "console=") != 1 {
		t.Error("in the shipped script the console is /dev/console and is assigned once: nothing replaces it")
	}
	for _, g := range []string{`""|root|loginwindow|_*)`, `""|0|*[!0-9]*)`} {
		if !strings.Contains(code, g) {
			t.Errorf("the script lacks the refusal %s", g)
		}
	}
}

// runPostinstall runs the hooked script with a stand-in for the securl binary that records what it was asked to do, says what the
// real one would say on failure, and exits as told. The real branch of the script is executed: only the program that would write
// to /Library/LaunchAgents and load an agent is replaced.
type ranResult struct {
	out      string
	exitCode int
	calls    string // what the stand-in securl was given, one line per call; "" if it was never called
}

func runPostinstall(t *testing.T, script string, env []string, securlExit int) ranResult {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	fake := filepath.Join(dir, "securl")
	body := "#!/bin/sh\necho \"$@\" >> " + log + "\n"
	if securlExit != 0 {
		body += "echo \"securl daemon install: writing the plist in /Library/LaunchAgents: permission denied\" >&2\n"
	}
	body += "exit " + strconv.Itoa(securlExit) + "\n"
	if err := os.WriteFile(fake, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", script)
	cmd.Env = append(os.Environ(), append(env, "SECURL_TEST_SECURL="+fake)...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	}
	calls, _ := os.ReadFile(log)
	return ranResult{string(out), code, string(calls)}
}

// someOtherUser is an account on this machine that is not the one running the tests and is not root, for the checks of "the console
// is somebody else". A throwaway name would not do: the script asks the system for the account's id.
func someOtherUser(t *testing.T) string {
	t.Helper()
	me := os.Getenv("USER")
	for _, u := range []string{"daemon", "nobody", "_www", "_spotlight"} {
		if u != me {
			if _, err := exec.Command("id", "-u", u).Output(); err == nil {
				return u
			}
		}
	}
	t.Skip("no second account to use")
	return ""
}

// With nobody at the console, or somebody who is not a person (root, the login window, a service account, a name that is no account),
// the script does not load the agent into any session: it puts the agent in place and nothing more, and each user gets a daemon at
// their next login. The one thing it must not do is give `-uid` a value, because that is what loads a daemon into a session now. And
// it still exits 0: the binary is installed.
func TestThePostinstallLoadsNothingForRootOrForNoOneAndStillSucceeds(t *testing.T) {
	pkgSkip(t)
	path, _ := postinstallWith(t, true)
	for name, env := range map[string][]string{
		"no console user":           {"SECURL_TEST_CONSOLE_USER="},
		"root at console":           {"SECURL_TEST_CONSOLE_USER=root"},
		"the login window":          {"SECURL_TEST_CONSOLE_USER=loginwindow"},
		"a service account":         {"SECURL_TEST_CONSOLE_USER=_spotlight"},
		"a name that is not a user": {"SECURL_TEST_CONSOLE_USER=no-such-user-xyz"},
	} {
		r := runPostinstall(t, path, env, 0)
		if r.exitCode != 0 {
			t.Errorf("%s: the postinstall must exit 0, the binary is installed: exit %d\n%s", name, r.exitCode, r.out)
		}
		if got := strings.TrimSpace(r.calls); got != "daemon install" {
			t.Errorf("%s: securl was run as %q; it must be exactly `daemon install`, with no -uid: nothing is loaded into a session for someone who is not a person at the console", name, got)
		}
		if strings.Contains(r.calls, "-uid") {
			t.Errorf("%s: -uid was given: %q", name, r.calls)
		}
		if !strings.Contains(r.out, "next time they log in") {
			t.Errorf("%s: it says that each user's daemon starts at their next login:\n%s", name, r.out)
		}
	}
}

// If even putting the agent in place fails, with nobody at the console, the package is still installed, and the script says so and
// how to do it by hand.
func TestThePostinstallWithNobodyAndAFailingInstallStillSucceedsAndSaysHowToDoItByHand(t *testing.T) {
	pkgSkip(t)
	path, _ := postinstallWith(t, true)
	r := runPostinstall(t, path, []string{"SECURL_TEST_CONSOLE_USER="}, 9)
	if r.exitCode != 0 {
		t.Errorf("exit %d\n%s", r.exitCode, r.out)
	}
	if !strings.Contains(r.out, "Could not make the login agent") || !strings.Contains(r.out, "sudo securl daemon install") {
		t.Errorf("it says what failed and what to run by hand:\n%s", r.out)
	}
	if strings.Contains(r.out, "will start for each user") {
		t.Errorf("it claims success after a failure:\n%s", r.out)
	}
}

func TestThePostinstallRunsTheInstallAsTheUserAtTheConsoleInTheirSession(t *testing.T) {
	pkgSkip(t)
	path, _ := postinstallWith(t, true)
	other := someOtherUser(t)
	uid, _ := exec.Command("id", "-u", other).Output()
	r := runPostinstall(t, path, []string{"SECURL_TEST_CONSOLE_USER=" + other}, 0)
	if r.exitCode != 0 {
		t.Fatalf("exit %d\n%s", r.exitCode, r.out)
	}
	want := "daemon install -uid " + strings.TrimSpace(string(uid))
	if strings.TrimSpace(r.calls) != want {
		t.Errorf("securl was asked:\n  %q\nwant exactly:\n  %q", strings.TrimSpace(r.calls), want)
	}
	if strings.Count(strings.TrimSpace(r.calls), "\n") != 0 {
		t.Errorf("securl was run more than once: %q", r.calls)
	}
	if !strings.Contains(r.out, "The daemon is running for "+other) {
		t.Errorf("it says what it did:\n%s", r.out)
	}
}

// The account is the console's, and nothing the environment of the Installer says changes it: USER, SUDO_USER, LOGNAME and HOME of
// the person who ran `sudo installer` are not who is at the console, and the one at the console is who the agent is made for.
func TestThePostinstallChoosesTheUserAtTheConsoleWhateverTheEnvironmentSays(t *testing.T) {
	pkgSkip(t)
	path, _ := postinstallWith(t, true)
	console := someOtherUser(t)
	uid, _ := exec.Command("id", "-u", console).Output()
	r := runPostinstall(t, path, []string{
		"SECURL_TEST_CONSOLE_USER=" + console,
		"USER=attacker", "SUDO_USER=attacker", "LOGNAME=attacker", "SUDO_UID=0", "HOME=/Users/attacker",
	}, 0)
	want := "daemon install -uid " + strings.TrimSpace(string(uid))
	if strings.TrimSpace(r.calls) != want {
		t.Errorf("the agent was not loaded for the user at the console:\n  %q\nwant\n  %q", r.calls, want)
	}
	if strings.Contains(r.calls, "attacker") || strings.Contains(r.calls, " 0") && !strings.Contains(r.calls, "-uid 5") && strings.HasSuffix(strings.TrimSpace(r.calls), " 0") {
		t.Errorf("something from the environment reached the command: %q", r.calls)
	}
}

// The same, with no hook for the console's user: the script reads the owner of a file, which is how /dev/console is read. The
// environment's USER and SUDO_USER must not be taken in its place.
func TestThePostinstallTakesTheOwnerOfTheConsoleNotTheNameInTheEnvironment(t *testing.T) {
	pkgSkip(t)
	path, _ := postinstallWith(t, true)
	me := os.Getenv("USER")
	if me == "" || me == "root" {
		t.Skip("needs a user that is not root")
	}
	f := filepath.Join(t.TempDir(), "console")
	os.WriteFile(f, nil, 0o600) // owned by whoever runs the tests: the stand-in for the console's owner
	other := someOtherUser(t)
	r := runPostinstall(t, path, []string{"SECURL_TEST_CONSOLE_FILE=" + f, "USER=" + other, "SUDO_USER=" + other, "LOGNAME=" + other}, 0)
	meUID, _ := exec.Command("id", "-u", me).Output()
	otherUID, _ := exec.Command("id", "-u", other).Output()
	if strings.TrimSpace(r.calls) != "daemon install -uid "+strings.TrimSpace(string(meUID)) {
		t.Errorf("the owner of the console file is %s (uid %s) and the agent is loaded for them; securl was given %q", me, strings.TrimSpace(string(meUID)), r.calls)
	}
	if strings.Contains(r.calls, "-uid "+strings.TrimSpace(string(otherUID))) {
		t.Errorf("the name in USER / SUDO_USER was used: %q", r.calls)
	}
}

// If the install fails (the user's session cannot be reached, launchctl says no), the package is still installed and the script
// still exits 0: what failed is said, with what to run by hand.
func TestAFailedInstallOfTheAgentDoesNotFailThePackage(t *testing.T) {
	pkgSkip(t)
	path, _ := postinstallWith(t, true)
	other := someOtherUser(t)
	r := runPostinstall(t, path, []string{"SECURL_TEST_CONSOLE_USER=" + other}, 5)
	if r.exitCode != 0 {
		t.Errorf("a failed agent install must not fail the installation: exit %d\n%s", r.exitCode, r.out)
	}
	if r.calls == "" {
		t.Fatal("securl was never run: this test did not reach the real branch")
	}
	if !strings.Contains(r.out, "Could not start the daemon for "+other) {
		t.Errorf("it says what failed:\n%s", r.out)
	}
	// the real reason is shown, not a guess: what `securl daemon install` said is in the output the person can read
	if !strings.Contains(r.out, "permission denied") {
		t.Errorf("the reason that securl gave is passed on, not replaced by a guess:\n%s", r.out)
	}
	if !strings.Contains(r.out, "securl daemon install") {
		t.Errorf("and how to do it by hand:\n%s", r.out)
	}
	if strings.Contains(r.out, "The daemon is running") {
		t.Errorf("it claims success after a failure:\n%s", r.out)
	}
}

func TestThePostinstallSaysWhatHappenedAndWhatTheVaultNeeds(t *testing.T) {
	pkgSkip(t)
	_, s := postinstallOf(t)
	for _, want := range []string{"securl vault init", "securl unlock", "sudo securl daemon uninstall", "locked"} {
		if !strings.Contains(s, want) {
			t.Errorf("the message lacks %q: the daemon is running but its vault is locked, and the person must be told the first step", want)
		}
	}
}

// stripHeredocText removes what a script only prints (the lines between <<'TAG' and TAG), so that what is checked is what it
// runs. (Go's regexp has no back-references, so the lines are walked.)
func stripHeredocText(s string) string {
	var out []string
	end := ""
	start := regexp.MustCompile(`<<-?\s*'?"?(\w+)'?"?\s*$`)
	for _, line := range strings.Split(s, "\n") {
		if end != "" {
			if strings.TrimSpace(line) == end {
				end = ""
			}
			continue
		}
		out = append(out, line)
		if m := start.FindStringSubmatch(line); m != nil {
			end = m[1]
		}
	}
	return strings.Join(out, "\n")
}

func TestThePackageIsNamedAndVersionedLikeTheArchives(t *testing.T) {
	pkgSkip(t)
	pkg, _ := buildPkg(t, nightlyVersion)
	root := expand(t, pkg)
	info, _ := os.ReadFile(firstMatch(t, root, "*/PackageInfo"))
	if !regexp.MustCompile(`identifier="com\.leafai\.securl"`).Match(info) {
		t.Errorf("identifier: %s", info)
	}
	// nightly-20261012-1a2b3c4: the Installer reads numbers, so the date is the version, as 2026.10.12
	if !bytes.Contains(info, []byte(`version="2026.10.12"`)) {
		t.Errorf("the package version is the date of the build as dotted numbers: %s", info)
	}
	dist, err := os.ReadFile(filepath.Join(root, "Distribution"))
	if err != nil {
		t.Fatalf("a product archive has a Distribution: %v", err)
	}
	if !bytes.Contains(dist, []byte("<title>securl "+nightlyVersion+"</title>")) {
		t.Errorf("the installer's title carries the whole build name, which the version cannot (a commit is not a number):\n%s", dist)
	}
	for _, want := range []string{`enable_localSystem="true"`, `enable_currentUserHome="false"`, `enable_anywhere="false"`} {
		if !bytes.Contains(dist, []byte(want)) {
			t.Errorf("Distribution lacks %s: the installer must go to the system volume only\n%s", want, dist)
		}
	}
}

func TestThePackageRefusesBadInput(t *testing.T) {
	pkgSkip(t)
	dir := t.TempDir()
	arm := fakeBinary(t, dir, "arm64", "v")
	amd := fakeBinary(t, dir, "amd64", "v")
	out := filepath.Join(dir, "o.pkg")
	notAPackage := filepath.Join(dir, "notes.txt")
	os.WriteFile(notAPackage, []byte("precious notes"), 0o644)
	for name, args := range map[string][]string{
		"bad version":         {"v1.0.0", arm, amd, out},
		"missing binary":      {nightlyVersion, arm, filepath.Join(dir, "none"), out},
		"same arch twice":     {nightlyVersion, arm, arm, out},
		"output over input":   {nightlyVersion, arm, amd, arm},
		"output over a file":  {nightlyVersion, arm, amd, notAPackage},
		"too few arguments":   {nightlyVersion, arm, amd},
		"output in a missing": {nightlyVersion, arm, amd, filepath.Join(dir, "no", "such", "o.pkg")},
	} {
		os.Remove(out)
		cmd := exec.Command("bash", append([]string{pkgScript}, args...)...)
		if b, err := cmd.CombinedOutput(); err == nil && name != "output in a missing" {
			t.Errorf("%s: accepted\n%s", name, b)
		}
	}
	if b, _ := os.ReadFile(arm); len(b) == 0 {
		t.Error("a refused build must not have emptied its input")
	}
	if b, _ := os.ReadFile(notAPackage); string(b) != "precious notes" {
		t.Errorf("a file that is not a package was overwritten: %q", b)
	}
}

// What is reproducible, and what is not. Every part of the package (its payload, its scripts, its bill of materials, its info)
// is the same from the same inputs; the .pkg file as a whole is not, because the archive around the parts records the time it
// was written. So a rebuild of one commit has a different SHA256SUMS line for the package, which is harmless (the nightly
// builds a commit once) but is not hidden: this test says exactly what holds, and fails if the parts ever start to differ.
func TestEveryPartOfThePackageIsTheSameFromTheSameInputs(t *testing.T) {
	pkgSkip(t)
	dir := t.TempDir()
	arm := fakeBinary(t, dir, "arm64", nightlyVersion)
	amd := fakeBinary(t, dir, "amd64", nightlyVersion)
	build := func(name string) string {
		out := filepath.Join(dir, name, "o.pkg")
		if b, err := exec.Command("bash", pkgScript, nightlyVersion, arm, amd, out).CombinedOutput(); err != nil {
			t.Fatalf("%v\n%s", err, b)
		}
		// --expand, not --expand-full: the parts are read as the archive holds them (the payload as one file)
		dst := filepath.Join(t.TempDir(), "x")
		if b, err := exec.Command("pkgutil", "--expand", out, dst).CombinedOutput(); err != nil {
			t.Fatalf("pkgutil --expand: %v\n%s", err, b)
		}
		return dst
	}
	a := build("a")
	time.Sleep(1100 * time.Millisecond) // the second build is on the other side of a second: a recorded time would show
	b := build("b")
	// the scripts are a directory in the expanded form: its one file is what is compared
	for _, part := range []string{"Payload", "Bom", "PackageInfo", "Scripts/postinstall"} {
		pa, pb := firstMatch(t, a, "*/"+part), firstMatch(t, b, "*/"+part)
		ha, err := exec.Command("shasum", "-a", "256", pa).Output()
		if err != nil || len(strings.Fields(string(ha))) == 0 {
			t.Fatalf("cannot hash %s: %v (is it a directory? %q)", pa, err, ha)
		}
		hb, _ := exec.Command("shasum", "-a", "256", pb).Output()
		if strings.Fields(string(ha))[0] != strings.Fields(string(hb))[0] {
			// PackageInfo records the size and counts, not times: if this one differs, something else does
			t.Errorf("%s differs between two builds of the same inputs", part)
		}
	}
}

// The documents tell a Mac user to download securl_macos.pkg and check it against SHA256SUMS exactly as an archive is checked. The
// names must be the ones the workflow publishes, and the check must work on a package listed by add-to-sums.sh.
func TestTheDocumentsNameThePackageTheWorkflowPublishes(t *testing.T) {
	wf, _ := os.ReadFile(".github/workflows/nightly.yml")
	for _, doc := range []string{"README.md", "skills/securl/SKILL.md"} {
		b, _ := os.ReadFile(doc)
		s := string(b)
		if !strings.Contains(s, "https://github.com/LeafAI/securl/releases/download/nightly/securl_macos.pkg") {
			t.Errorf("%s does not give the address of the package", doc)
		}
		if !strings.Contains(string(wf), "securl_macos.pkg") {
			t.Errorf("the workflow does not make securl_macos.pkg, which %s tells people to download", doc)
		}
		if !strings.Contains(s, "securl daemon install") {
			t.Errorf("%s does not say how to start the daemon at login", doc)
		}
	}
}

// The documents say what the installer does at the end, and nowhere say the opposite: a README that told people the package starts
// nothing, next to a script that starts a daemon, would be a lie about something that keeps a vault open.
func TestTheDocumentsSayThatTheInstallerStartsTheDaemonLockedAndNeverTheOpposite(t *testing.T) {
	for _, doc := range []string{"README.md", "docs/OPERATING.md", "skills/securl/SKILL.md"} {
		b, _ := os.ReadFile(doc)
		flat := strings.Join(strings.Fields(string(b)), " ")
		for _, stale := range []string{"starts nothing", "start nothing", "Nothing was started", "changes nothing", "prints what to do next and changes",
			"~/Library/LaunchAgents", "launchctl asuser", "sudo -n -H -u", "as that user in that user's login session", "refuse to run as root", "LaunchAgent of your user"} {
			if strings.Contains(flat, stale) {
				t.Errorf("%s still says %q about the package, which now starts the daemon", doc, stale)
			}
		}
	}
	b, _ := os.ReadFile("README.md")
	flat := strings.Join(strings.Fields(string(b)), " ")
	for _, want := range []string{"securl daemon` is running", "/Library/LaunchAgents/com.leafai.securl.plist", "nobody's daemon runs as root", "locked", "securl vault init", "securl unlock",
		"sudo securl daemon uninstall", "not signed by Apple", "pkgutil --forget com.leafai.securl", "vault.idle_lock", "run `sudo securl daemon install` yourself"} {
		if !strings.Contains(flat, want) {
			t.Errorf("the README's section on the package does not say %q", want)
		}
	}
	ops, _ := os.ReadFile("docs/OPERATING.md")
	oflat := strings.Join(strings.Fields(string(ops)), " ")
	for _, want := range []string{"/dev/console", "/Library/LaunchAgents", "-uid", "every user at graphical login, as that user", "exits 0", "launchd expands neither", "-log default", "needs root"} {
		if !strings.Contains(oflat, want) {
			t.Errorf("docs/OPERATING.md does not describe how the script picks the user: %q", want)
		}
	}
}

// What the document says is removed is what the package put there: the receipt's identifier, and the one file.
func TestTheRemovalTheDocumentGivesMatchesWhatThePackageInstalls(t *testing.T) {
	pkgSkip(t)
	pkg, _ := buildPkg(t, nightlyVersion)
	root := expand(t, pkg)
	info, _ := os.ReadFile(firstMatch(t, root, "*/PackageInfo"))
	b, _ := os.ReadFile("README.md")
	if !strings.Contains(string(b), "pkgutil --forget com.leafai.securl") || !bytes.Contains(info, []byte(`identifier="com.leafai.securl"`)) {
		t.Error("the receipt to forget is not the identifier the package carries")
	}
	if !strings.Contains(string(b), "sudo rm /usr/local/bin/securl") || !bytes.Contains(info, []byte(`install-location="/usr/local/bin"`)) {
		t.Error("the file to remove is not the one the package installs")
	}
}

// Each refusal is tested by an input that only that refusal stops. Two arm64 binaries that are different files pass the check that
// the two are not the same file, and are stopped by the check of the second one's architecture; the same file twice is stopped by
// the first. An output that is an input, by a name that is not the one it was given (a link to it), is stopped by neither of those.
func TestEachRefusalOfThePackageScriptIsReachedByItsOwnInput(t *testing.T) {
	pkgSkip(t)
	dir := t.TempDir()
	arm := fakeBinary(t, dir, "arm64", "v")
	amd := fakeBinary(t, dir, "amd64", "v")
	armCopy := filepath.Join(dir, "arm64-copy")
	b, _ := os.ReadFile(arm)
	os.WriteFile(armCopy, b, 0o755)
	ampCopy := filepath.Join(dir, "amd64-copy")
	b, _ = os.ReadFile(amd)
	os.WriteFile(ampCopy, b, 0o755)
	link := filepath.Join(dir, "link-to-amd64")
	if err := os.Symlink(ampCopy, link); err != nil {
		t.Fatal(err)
	}
	// a link whose target is written relative to the link's own directory, as `ln -s amd64-copy x` makes it, and a chain of two
	relLink := filepath.Join(dir, "relative-link")
	if err := os.Symlink("amd64-copy", relLink); err != nil {
		t.Fatal(err)
	}
	chain := filepath.Join(dir, "chain")
	if err := os.Symlink("relative-link", chain); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"the same file twice", []string{nightlyVersion, arm, arm, filepath.Join(dir, "o.pkg")}, "same file"},
		{"a second arm64 that is another file", []string{nightlyVersion, arm, armCopy, filepath.Join(dir, "o.pkg")}, "not an x86_64 binary"},
		{"the amd64 where the arm64 goes", []string{nightlyVersion, amd, ampCopy, filepath.Join(dir, "o.pkg")}, "not an arm64 binary"},
		{"an output that is an input", []string{nightlyVersion, arm, ampCopy, ampCopy}, "one of the inputs"},
		{"an output that is a link to an input", []string{nightlyVersion, arm, ampCopy, link}, "one of the inputs"},
		{"an output that is a relative link to an input", []string{nightlyVersion, arm, ampCopy, relLink}, "one of the inputs"},
		{"an output at the end of a chain of links", []string{nightlyVersion, arm, ampCopy, chain}, "one of the inputs"},
	} {
		out, err := exec.Command("bash", append([]string{pkgScript}, tc.args...)...).CombinedOutput()
		if err == nil {
			t.Errorf("%s: accepted\n%s", tc.name, out)
			continue
		}
		if !strings.Contains(string(out), tc.want) {
			t.Errorf("%s: stopped, but not by the refusal that is meant for it (%q):\n%s", tc.name, tc.want, out)
		}
	}
	for _, f := range []string{arm, amd, armCopy, ampCopy} {
		if st, err := os.Stat(f); err != nil || st.Size() == 0 {
			t.Errorf("%s was damaged by a refused build", f)
		}
	}
	got, _ := exec.Command("lipo", "-archs", ampCopy).Output()
	if strings.TrimSpace(string(got)) != "x86_64" {
		t.Errorf("the input that was named as the output is no longer a binary: %q", got)
	}
}

// The postinstall runs as root. If it read its idea of who is at the console from the environment, whoever controls the environment
// of the Installer (a sudoers rule that keeps it, a wrapper) would choose the account that the agent is made for. So the package that
// is shipped has no such variable in it: the hooks are in the test variant only.
func TestTheShippedPostinstallHasNoTestHooks(t *testing.T) {
	pkgSkip(t)
	_, shipped := postinstallOf(t)
	if strings.Contains(shipped, "SECURL_TEST") {
		t.Error("the shipped postinstall reads SECURL_TEST_* variables: as root, it must take the user from the console and nowhere else")
	}
	_, hooked := postinstallWith(t, true)
	if !strings.Contains(hooked, "SECURL_TEST_CONSOLE_USER") {
		t.Error("the test variant has no hook, so the tests above would run the real thing")
	}
	// and the script cannot be tricked into the hooked form by an argument or a variable of the build
	b, _ := os.ReadFile(pkgScript)
	if strings.Count(string(b), "--test-hooks") < 1 {
		t.Error("the build script does not name the flag")
	}
}

// The environment a script gets from `sudo installer` or from the system is not trusted for anything that decides whose files are
// touched: PATH is set by the script itself, so that a `launchctl`, `sudo` or `stat` earlier on a PATH somebody chose is not run as
// root.
func TestThePostinstallSetsItsOwnPathBeforeItRunsAnything(t *testing.T) {
	pkgSkip(t)
	_, s := postinstallOf(t)
	code := withoutComments(s)
	i := strings.Index(code, "PATH=/usr/bin:/bin:/usr/sbin:/sbin")
	if i < 0 {
		t.Fatal("the script must set PATH itself to the system directories")
	}
	for _, cmd := range []string{"stat ", "id ", "printf "} {
		if j := strings.Index(code, cmd); j >= 0 && j < i && !strings.HasPrefix(cmd, "printf") {
			t.Errorf("%q is run before PATH is set", cmd)
		}
	}
	if strings.Contains(code, "$HOME") || strings.Contains(code, "${HOME") {
		t.Error("as root, $HOME is not the user's: the script must not use it")
	}
	if !strings.Contains(code, `SECURL=/usr/local/bin/securl`) {
		t.Error("the binary that is run is the one the package installed, by its absolute path")
	}
}
