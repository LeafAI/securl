package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/netguard"
)

// doctorDataTargets says what is configured for Redis and RocketMQ, by name and with the limits that matter. It never prints a
// password or a key (there is none in the configuration), and it says nothing when nothing is configured.
func doctorDataTargets(cfg *config.Config, report func(bool, string, string)) {
	for _, r := range cfg.Redis {
		mode := "read only"
		if r.Writable() {
			mode = "READ AND WRITE (redis_exec changes data, with a reason, and tells the team)"
		}
		report(true, "redis "+r.Name, fmt.Sprintf("%s, %s, tls %s; a person types the password at the first session_open", r.Environment, mode, r.TLSMode()))
	}
	for _, r := range cfg.RocketMQ {
		report(true, "rocketmq "+r.Name, fmt.Sprintf("%s, reads %d topic(s) (%s) as consumer group %s, tls %s; a person types the AccessKey and SecretKey at the first session_open",
			r.Environment, len(r.Topics), strings.Join(r.Topics, ", "), r.Group(), r.TLSMode()))
	}
}

// doctorDataReach connects (TCP only) to every configured Redis server and to every NameServer, the way securl will: it proves the
// network path and nothing else. No password or key is used, and nothing is sent: doctor does not open the vault, so whether a
// credential is accepted is only known when one is typed.
func doctorDataReach(ctx context.Context, cfg *config.Config, report func(bool, string, string)) {
	if len(cfg.Redis) == 0 && len(cfg.RocketMQ) == 0 {
		report(false, "redis / rocketmq", "nothing is configured: add one with `securl config redis add` or `securl config rocketmq add`")
		return
	}
	for _, r := range cfg.Redis {
		reach(ctx, cfg, report, "redis "+r.Name, []string{r.Addr()})
	}
	for _, r := range cfg.RocketMQ {
		reach(ctx, cfg, report, "rocketmq "+r.Name, r.NameServerAddrs())
	}
}

func reach(ctx context.Context, cfg *config.Config, report func(bool, string, string), what string, addrs []string) {
	var up, local int
	for _, a := range addrs {
		dctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		c, err := netguard.DialContext(cfg.Security.AllowLocalAddresses)(dctx, "tcp", a)
		cancel()
		switch {
		case err == nil:
			c.Close()
			up++
		case errors.Is(err, netguard.ErrBlocked):
			local++
		}
	}
	switch {
	case up > 0:
		report(true, what+" reachable", fmt.Sprintf("%d of %d address(es) accept a connection (nothing is sent; the credential is checked only when a person types it)", up, len(addrs)))
	case local > 0:
		report(false, what+" reachable", "the address is on this machine, which securl refuses unless security.allow_local_addresses is true")
	default:
		report(false, what+" reachable", fmt.Sprintf("none of %d address(es) accept a connection: check the host, the port, the network and any VPN", len(addrs)))
	}
}
