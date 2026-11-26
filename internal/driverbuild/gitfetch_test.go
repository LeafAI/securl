package driverbuild

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// repo makes a git repository of a driver, with two commits and an annotated tag on the second, and returns its address and the two
// commit hashes. Git is run with no global configuration: a developer's own settings (commit signing, say) must not matter here.
type repo struct {
	dir         string
	first, last string
}

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func newRepo(t *testing.T, module string) *repo {
	t.Helper()
	dir := t.TempDir()
	gitIn(t, dir, "init", "-q", "-b", "main")
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module "+module+"\n\ngo 1.26.9\n")
	write("driver.go", "package drv\n")
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-q", "-m", "one")
	r := &repo{dir: dir, first: gitIn(t, dir, "rev-parse", "HEAD")}
	gitIn(t, dir, "tag", "v1.0.0")
	write("driver.go", "package drv\n\n// two\n")
	gitIn(t, dir, "commit", "-q", "-am", "two")
	r.last = gitIn(t, dir, "rev-parse", "HEAD")
	gitIn(t, dir, "tag", "-a", "v1.1.0", "-m", "annotated")
	return r
}

func TestACommitIsFetchedByItsFullHashAndTheCheckoutIsThatCommit(t *testing.T) {
	r := newRepo(t, "example.test/g/drv")
	dest := filepath.Join(t.TempDir(), "drv")
	got, err := Fetch(Spec{Host: "example.test", Path: "g/drv", Rev: r.first}, "file://"+r.dir, dest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Commit != r.first {
		t.Errorf("fetched %s, asked for %s", got.Commit, r.first)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "driver.go")); strings.Contains(string(b), "two") {
		t.Errorf("the working tree is not the first commit: %q", b)
	}
	if _, err := os.Stat(filepath.Join(dest, ".git")); err == nil {
		t.Error("the history is not needed once the tree is checked out, and it is not kept")
	}
}

func TestATagIsFollowedToTheCommitItNamesAndTheCommitIsWhatIsReported(t *testing.T) {
	r := newRepo(t, "example.test/g/drv")
	for tag, want := range map[string]string{"v1.0.0": r.first, "v1.1.0": r.last} {
		got, err := Fetch(Spec{Host: "example.test", Path: "g/drv", Rev: tag}, "file://"+r.dir, filepath.Join(t.TempDir(), "d"), nil)
		if err != nil {
			t.Errorf("%s: %v", tag, err)
			continue
		}
		if got.Commit != want {
			t.Errorf("%s is %s, the fetch says %s (an annotated tag is not a commit: its target is)", tag, want, got.Commit)
		}
	}
}

func TestARevisionThatIsNotThereIsAnErrorThatSaysSoWithoutGitsOwnWords(t *testing.T) {
	r := newRepo(t, "example.test/g/drv")
	for _, rev := range []string{"v9.9.9", strings.Repeat("a", 40)} {
		_, err := Fetch(Spec{Host: "example.test", Path: "g/drv", Rev: rev}, "file://"+r.dir, filepath.Join(t.TempDir(), "d"), nil)
		if err == nil || !strings.Contains(err.Error(), "could not fetch") {
			t.Errorf("%s: %v", rev, err)
		}
	}
}

// What git prints can hold a user name, a path or, with a careless remote, a token. A build log is shared, so none of it is repeated.
func TestWhatGitSaysIsNotRepeated(t *testing.T) {
	_, err := Fetch(Spec{Host: "example.test", Path: "g/drv", Rev: "v1.0.0"}, "file:///nonexistent-path-xyz-SECRET", filepath.Join(t.TempDir(), "d"), nil)
	if err == nil {
		t.Fatal("a missing repository was fetched")
	}
	for _, leak := range []string{"nonexistent-path-xyz", "SECRET", "/tmp", "fatal:"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("the error repeats git's words (%q): %v", leak, err)
		}
	}
}

func TestTheFetchRunsGitWithTheEnvironmentItWasGivenAndNothingFromTheCallers(t *testing.T) {
	r := newRepo(t, "example.test/g/drv")
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "url.file:///nowhere/.insteadOf")
	t.Setenv("GIT_CONFIG_VALUE_0", "file://"+r.dir)
	_, err := Fetch(Spec{Host: "example.test", Path: "g/drv", Rev: "v1.0.0"}, "file://"+r.dir, filepath.Join(t.TempDir(), "d"), []string{"GIT_TERMINAL_PROMPT=0"})
	if err != nil {
		t.Errorf("the caller's own git settings must not leak into the fetch: %v", err)
	}
}

func TestAnExistingDestinationIsNotReused(t *testing.T) {
	r := newRepo(t, "example.test/g/drv")
	dest := filepath.Join(t.TempDir(), "d")
	os.MkdirAll(dest, 0o700)
	os.WriteFile(filepath.Join(dest, "keep.txt"), []byte("mine"), 0o600)
	if _, err := Fetch(Spec{Host: "example.test", Path: "g/drv", Rev: "v1.0.0"}, "file://"+r.dir, dest, nil); err == nil {
		t.Error("a directory that is already there was fetched into")
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "keep.txt")); string(b) != "mine" {
		t.Error("what was there is left alone, also after the refusal")
	}
}

func TestAFailedFetchLeavesNothingBehind(t *testing.T) {
	r := newRepo(t, "example.test/g/drv")
	dest := filepath.Join(t.TempDir(), "d")
	if _, err := Fetch(Spec{Host: "example.test", Path: "g/drv", Rev: "v9.9.9"}, "file://"+r.dir, dest, nil); err == nil {
		t.Fatal("a tag that is not there was fetched")
	}
	if _, err := os.Stat(dest); err == nil {
		t.Error("the half-made checkout is removed")
	}
}

// A tag that points at another commit than the one a person reviewed would run unreviewed code; so would a fetch that follows a
// branch. The commit that comes back is the one the revision names, and for a hash it is that hash and no other.
func TestOnlyTheNamedRevisionIsFetchedAndNoHistory(t *testing.T) {
	r := newRepo(t, "example.test/g/drv")
	dest := filepath.Join(t.TempDir(), "d")
	if _, err := Fetch(Spec{Host: "example.test", Path: "g/drv", Rev: "v1.0.0"}, "file://"+r.dir, dest, nil); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "driver.go")); strings.Contains(string(b), "two") {
		t.Errorf("a tag on the first commit gives the first commit's files, not the branch tip's: %q", b)
	}
}

func TestGitIsRunWithNoConfigurationOfTheCallersAndNoPrompt(t *testing.T) {
	env := gitEnv([]string{"GIT_SSH_COMMAND=ssh -o BatchMode=yes"})
	has := func(k string) bool {
		for _, e := range env {
			if strings.HasPrefix(e, k) {
				return true
			}
		}
		return false
	}
	for _, want := range []string{"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "GIT_SSH_COMMAND=ssh -o BatchMode=yes", "PATH="} {
		if !has(want) {
			t.Errorf("%s is not in git's environment: %v", want, env)
		}
	}
	for _, e := range env {
		if strings.HasPrefix(e, "GIT_CONFIG_COUNT") || strings.HasPrefix(e, "GIT_CONFIG_KEY") || strings.HasPrefix(e, "GIT_ASKPASS") || strings.HasPrefix(e, "GITHUB_TOKEN") {
			t.Errorf("the caller's %s leaks into git", e)
		}
	}
}

func TestTheSshAgentOfTheCallerReachesGitAndNothingElseOfTheirs(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
	t.Setenv("SECURL_TEST_SECRET", "hunter2")
	t.Setenv("GITLAB_TOKEN", "glpat-secret")
	env := strings.Join(gitEnv(nil), "\n")
	if !strings.Contains(env, "SSH_AUTH_SOCK=/tmp/agent.sock") {
		t.Error("the agent that holds the key is how the clone is authenticated")
	}
	if strings.Contains(env, "hunter2") || strings.Contains(env, "glpat") {
		t.Errorf("git is given what it needs and no more: %s", env)
	}
	t.Setenv("SSH_AUTH_SOCK", "")
	if strings.Contains(strings.Join(gitEnv(nil), "\n"), "SSH_AUTH_SOCK") {
		t.Error("an empty agent is not passed on")
	}
}

func TestAnErrorFromTheFetchNamesTheDriverAndNotGitsOutput(t *testing.T) {
	_, err := Fetch(Spec{Host: "example.test", Path: "g/drv", Rev: "v1.0.0"}, "file:///nonexistent", filepath.Join(t.TempDir(), "d"), nil)
	if err == nil || !strings.HasPrefix(err.Error(), "driver example.test/g/drv: ") {
		t.Errorf("%v", err)
	}
}

// A branch and a tag may carry the same name, and a plain "v1.0.0" is then the branch's to take. The version a person pinned is the
// tag, so the tag is what is fetched: otherwise whoever can push a branch of that name decides what the build runs.
func TestAVersionIsTheTagEvenWhenABranchHasTheSameName(t *testing.T) {
	r := newRepo(t, "example.test/g/drv")
	gitIn(t, r.dir, "checkout", "-q", "-b", "v1.0.0")
	os.WriteFile(filepath.Join(r.dir, "driver.go"), []byte("package drv\n\n// the branch, not the tag\n"), 0o644)
	gitIn(t, r.dir, "commit", "-q", "-am", "branch")
	got, err := Fetch(Spec{Host: "example.test", Path: "g/drv", Rev: "v1.0.0"}, "file://"+r.dir, filepath.Join(t.TempDir(), "d"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Commit != r.first {
		t.Errorf("the tag v1.0.0 is %s and the branch of that name is another commit; the fetch took %s", r.first, got.Commit)
	}
	if b, _ := os.ReadFile(filepath.Join(got.Dir, "driver.go")); strings.Contains(string(b), "branch") {
		t.Errorf("the working tree is the branch's: %q", b)
	}
}

// A hash is fetched as a hash. A hash that does not exist in the repository is an error, and a repository cannot hand back a
// different commit under it.
func TestAHashThatIsNotInTheRepositoryIsAnError(t *testing.T) {
	r := newRepo(t, "example.test/g/drv")
	_, err := Fetch(Spec{Host: "example.test", Path: "g/drv", Rev: strings.Repeat("0", 40)}, "file://"+r.dir, filepath.Join(t.TempDir(), "d"), nil)
	if err == nil {
		t.Error("a hash that is not there was fetched")
	}
}
