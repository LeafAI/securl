package driverbuild

import (
	"errors"
	"strings"
)

// sshOptions are what every clone of a driver is run with. The build must never wait for an answer (BatchMode), must never learn
// a host it has not been told about (the host key has to be in known_hosts already, so a clone cannot be redirected to another
// machine by whoever can change a name), and must not forward the agent to the server it clones from.
var sshOptions = []string{
	"-o BatchMode=yes",
	"-o StrictHostKeyChecking=yes",
	"-o UpdateHostKeys=no",
	"-o ForwardAgent=no",
	"-o ConnectTimeout=20",
}

// SSHCommand is the value of GIT_SSH_COMMAND for a build. With a key path, that key and no other is offered (IdentitiesOnly);
// without one, ssh uses the agent in SSH_AUTH_SOCK and the keys it would use anyway. The path is read by a shell, so only a plain
// absolute path is taken.
func SSHCommand(keyPath string) (string, error) {
	parts := append([]string{"ssh"}, sshOptions...)
	if keyPath != "" {
		if !plainKeyPath(keyPath) {
			return "", errors.New("the ssh key path must be an absolute path of letters, digits and / . _ - only")
		}
		parts = append(parts, "-o IdentitiesOnly=yes", "-i "+keyPath)
	}
	return strings.Join(parts, " "), nil
}

func plainKeyPath(p string) bool {
	if len(p) < 2 || p[0] != '/' || strings.Contains(p, "//") || strings.Contains(p, "..") {
		return false
	}
	for _, r := range p {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '/' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

// GitEnvFor is the environment a build gives git beyond what Fetch always gives it.
func GitEnvFor(keyPath string) ([]string, error) {
	c, err := SSHCommand(keyPath)
	if err != nil {
		return nil, err
	}
	return []string{"GIT_SSH_COMMAND=" + c}, nil
}
