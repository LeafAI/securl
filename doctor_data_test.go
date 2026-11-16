package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDoctorSaysNothingAboutRedisOrRocketMQWhenNoneIsConfigured(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "c.yaml")
	os.WriteFile(cfgPath, []byte("limits: {per_site: 3}\n"), 0o600)
	out, _ := capture(t, func() int { return runDoctor([]string{"-config", cfgPath}) })
	out = strings.ReplaceAll(out, dir, "<dir>")
	for _, w := range []string{"redis ", "rocketmq "} {
		if strings.Contains(strings.ToLower(out), w) {
			t.Errorf("a setup with none has nothing to say about %q:\n%s", w, out)
		}
	}
}

func TestDoctorReportsEachRedisAndRocketMQTargetByNameAndNeverACredential(t *testing.T) {
	cfgPath := writeCfg(t, "redis:\n  - {name: cache, host: redis.dev.example, environment: dev, tls: disable}\n  - {name: queue, host: redis2.dev.example, environment: test, mode: read_write}\n"+
		"rocketmq:\n  - {name: mq, namesrv: [ns1.dev.example], environment: dev, topics: [orders, payments], consumer_group: my-group}\n")
	out, _ := capture(t, func() int { return runDoctor([]string{"-config", cfgPath}) })
	for _, want := range []string{"redis cache", "redis queue", "read only", "READ AND WRITE", "tls disable", "tls verify", "rocketmq mq", "orders, payments", "consumer group my-group", "a person types the password", "AccessKey and SecretKey"} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor lacks %q:\n%s", want, out)
		}
	}
	var cache string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "redis cache") {
			cache = l
		}
	}
	if strings.Contains(cache, "READ AND WRITE") {
		t.Errorf("a read-only target does not say it can write: %s", cache)
	}
}

func listener(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return l.Addr().String()
}

func TestDoctorDataTargetsChecksTheNetworkPathAndSaysItChecksNoCredential(t *testing.T) {
	addr := listener(t)
	host, port, _ := strings.Cut(addr, ":")
	cfgPath := writeCfg(t, "security: {allow_local_addresses: true}\nredis:\n  - {name: cache, host: "+host+", port: "+port+", environment: dev, tls: disable}\n"+
		"rocketmq:\n  - {name: mq, namesrv: ['"+addr+"', '127.0.0.1:1'], environment: dev, topics: [orders]}\n")
	out, _ := capture(t, func() int { return runDoctor([]string{"-config", cfgPath, "-data-targets"}) })
	for _, want := range []string{"[ok  ] redis cache reachable", "[ok  ] rocketmq mq reachable", "1 of 2 address(es)", "nothing is sent"} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor lacks %q:\n%s", want, out)
		}
	}
}

func TestDoctorDataTargetsFailsWhenNothingAnswersAndWhenTheAddressIsOnThisMachine(t *testing.T) {
	cfgPath := writeCfg(t, "security: {allow_local_addresses: true}\nredis:\n  - {name: cache, host: 127.0.0.1, port: 1, environment: dev, tls: disable}\n")
	out, _ := capture(t, func() int { return runDoctor([]string{"-config", cfgPath, "-data-targets"}) })
	if !strings.Contains(out, "[FAIL] redis cache reachable") || !strings.Contains(out, "none of 1 address(es) accept a connection") {
		t.Errorf("%s", out)
	}
	cfgPath = writeCfg(t, "rocketmq:\n  - {name: mq, namesrv: ['127.0.0.1:9876'], environment: dev, topics: [orders]}\n")
	out, _ = capture(t, func() int { return runDoctor([]string{"-config", cfgPath, "-data-targets"}) })
	if !strings.Contains(out, "[FAIL] rocketmq mq reachable") || !strings.Contains(out, "allow_local_addresses") {
		t.Errorf("a local address is refused as the product refuses it, and says how:\n%s", out)
	}
}

func TestDoctorDataTargetsWithNothingConfiguredSaysSoInsteadOfCheckingNothing(t *testing.T) {
	cfgPath := writeCfg(t, "limits: {per_site: 3}\n")
	out, _ := capture(t, func() int { return runDoctor([]string{"-config", cfgPath, "-data-targets"}) })
	if !strings.Contains(out, "[FAIL] redis / rocketmq") || !strings.Contains(out, "securl config redis add") {
		t.Errorf("%s", out)
	}
}

func TestDoctorWithoutTheDataTargetsFlagMakesNoConnection(t *testing.T) {
	var accepted atomic.Int32
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			c.Close()
		}
	}()
	h2, p2, _ := strings.Cut(l.Addr().String(), ":")
	cfgPath := writeCfg(t, "security: {allow_local_addresses: true}\nredis:\n  - {name: cache, host: "+h2+", port: "+p2+", environment: dev, tls: disable}\n")
	capture(t, func() int { return runDoctor([]string{"-config", cfgPath}) })
	if n := accepted.Load(); n != 0 {
		t.Errorf("doctor connected without being asked to: %d", n)
	}
}
