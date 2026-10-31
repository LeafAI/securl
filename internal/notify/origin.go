package notify

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/user"
	"runtime"
	"strings"
	"unicode"
)

// Origin identifies the securl process, not the destination site or the requesting MCP client.
type Origin struct {
	Hostname string `json:"hostname"`
	User     string `json:"user"`
	PID      int    `json:"pid"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
}

func LocalOrigin() (Origin, error) { return detectOrigin(os.Hostname, user.Current) }

func detectOrigin(hostname func() (string, error), currentUser func() (*user.User, error)) (Origin, error) {
	host, hostErr := hostname()
	account, userErr := currentUser()
	name := ""
	if account != nil {
		name = account.Username
	}
	o := Origin{Hostname: host, User: name, PID: os.Getpid(), OS: runtime.GOOS, Arch: runtime.GOARCH}
	return o.normalized(), errors.Join(originError("hostname", hostErr), originError("account", userErr))
}

func originError(field string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("detect securl origin %s: %w", field, err)
}

func cleanOrigin(s string) string {
	var b strings.Builder
	for n, r := range []rune(s) {
		if n == 128 {
			break
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("._-", r) {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

func (o Origin) normalized() Origin {
	pid := o.PID
	if pid < 0 {
		pid = 0
	}
	return Origin{Hostname: cleanOrigin(o.Hostname), User: cleanOrigin(o.User), PID: pid,
		OS: cleanOrigin(o.OS), Arch: cleanOrigin(o.Arch)}
}

func (o Origin) Description() string {
	n := o.normalized()
	return fmt.Sprintf("host %s; account %s; PID %d; %s/%s", n.Hostname, n.User, n.PID, n.OS, n.Arch)
}

type Sender interface {
	Markdown(context.Context, string, string) error
}

type originSender struct {
	next   Sender
	origin Origin
}

func WithOrigin(next Sender, origin Origin) Sender {
	return originSender{next: next, origin: origin.normalized()}
}

func WithLocalOrigin(next Sender) Sender {
	o, err := LocalOrigin()
	if err != nil {
		log.Printf("securl: request origin metadata incomplete: %v", err)
	}
	return WithOrigin(next, o)
}

func (s originSender) Markdown(ctx context.Context, title, text string) error {
	o := s.origin
	footer := "\n\n---\n\n**Request origin (securl host)**\n\n" + Escape(o.Description(), 512)
	return s.next.Markdown(ctx, title+" ["+o.Hostname+"]", text+footer)
}
