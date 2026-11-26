package driverbuild

import (
	"strings"
	"testing"
)

func TestTheSshCommandOfTheBuildNeverAsksAndNeverLearnsHosts(t *testing.T) {
	got, err := SSHCommand("")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ssh", "BatchMode=yes", "StrictHostKeyChecking=yes", "ConnectTimeout=", "UpdateHostKeys=no"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q is not in %q", want, got)
		}
	}
	for _, bad := range []string{"StrictHostKeyChecking=no", "accept-new", " -i ", "-o IdentityFile", "ForwardAgent=yes", "UserKnownHostsFile=/dev/null"} {
		if strings.Contains(got, bad) {
			t.Errorf("a build does not trust a host it has not seen or use a key it was not given (%q): %q", bad, got)
		}
	}
}

func TestANamedKeyIsTheOnlyKeyUsed(t *testing.T) {
	k, err := SSHCommand("/home/me/.ssh/id_build")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"-i /home/me/.ssh/id_build", "IdentitiesOnly=yes"} {
		if !strings.Contains(k, want) {
			t.Errorf("%q is not in %q", want, k)
		}
	}
}

// The command is read by a shell: a path with a space, a quote or a $ would end the word it is in and begin another.
func TestAKeyPathThatAShellCouldReadAsMoreThanAPathIsRefused(t *testing.T) {
	for name, p := range map[string]string{
		"a space": "/home/me/my key", "a quote": "/home/me/k'ey", "a double quote": "/home/me/k\"ey", "a dollar": "/home/me/$HOME/k",
		"a semicolon": "/home/me/k;rm", "a backtick": "/home/me/`id`", "a newline": "/home/me/k\nx", "a pipe": "/home/me/k|x",
		"an ampersand": "/home/me/k&x", "a parenthesis": "/home/me/(k)", "a glob": "/home/me/*", "a backslash": "/home/me/k\\x",
		"relative": "id_build", "a tilde": "~/.ssh/id_build", "an option": "-oProxyCommand=x", "a hash": "/home/me/k#x", "an angle": "/home/me/k>x",
	} {
		if _, err := SSHCommand(p); err == nil {
			t.Errorf("%s: %q was accepted", name, p)
		}
	}
	if _, err := SSHCommand("/home/me/.ssh/id_ed25519-build_2"); err != nil {
		t.Errorf("an ordinary path is fine: %v", err)
	}
}

func TestARefusedKeyPathIsNotRepeated(t *testing.T) {
	_, err := SSHCommand("/home/me/hunter2-SECRET key")
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("%v", err)
	}
}

func TestTheGitEnvironmentOfABuildCarriesTheSshCommand(t *testing.T) {
	env, err := GitEnvFor("")
	if err != nil || len(env) != 1 || !strings.HasPrefix(env[0], "GIT_SSH_COMMAND=ssh ") {
		t.Errorf("%v %v", env, err)
	}
	if _, err := GitEnvFor("bad key"); err == nil {
		t.Error("a bad key path is an error here too")
	}
}
