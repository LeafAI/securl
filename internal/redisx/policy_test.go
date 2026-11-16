package redisx

import (
	"errors"
	"strings"
	"testing"
)

func has(m map[string]arity, k string) bool { _, ok := m[k]; return ok }

func TestReadCommandsAreAllowedInTheReadModeAndNothingElseIs(t *testing.T) {
	for _, c := range [][]string{
		{"GET", "k"}, {"get", "k"}, {"MGET", "a", "b"}, {"EXISTS", "a"}, {"TYPE", "k"}, {"TTL", "k"}, {"PTTL", "k"}, {"STRLEN", "k"},
		{"HGET", "h", "f"}, {"HGETALL", "h"}, {"HMGET", "h", "a", "b"}, {"HLEN", "h"}, {"HEXISTS", "h", "f"}, {"HKEYS", "h"},
		{"LRANGE", "l", "0", "10"}, {"LLEN", "l"}, {"LINDEX", "l", "0"}, {"SMEMBERS", "s"}, {"SCARD", "s"}, {"SISMEMBER", "s", "m"},
		{"ZRANGE", "z", "0", "10"}, {"ZCARD", "z"}, {"ZSCORE", "z", "m"}, {"ZRANK", "z", "m"},
		{"SCAN", "0"}, {"SCAN", "0", "MATCH", "user:*", "COUNT", "100"}, {"DBSIZE"}, {"PING"}, {"TYPE", "k"},
	} {
		if err := Check(c, ModeRead); err != nil {
			t.Errorf("%v must be allowed to read: %v", c, err)
		}
	}
}

// Commands that change data are refused in read mode, each for being a write.
func TestWriteCommandsAreRefusedInReadModeAsWrites(t *testing.T) {
	for _, c := range [][]string{
		{"SET", "k", "v"}, {"DEL", "k"}, {"INCR", "k"}, {"EXPIRE", "k", "1"}, {"HSET", "h", "f", "v"}, {"LPUSH", "l", "x"}, {"SADD", "s", "m"},
		{"ZADD", "z", "1", "m"}, {"APPEND", "k", "v"}, {"GETDEL", "k"}, {"GETSET", "k", "v"}, {"MSET", "a", "1"}, {"RENAME", "a", "b"},
		{"UNLINK", "k"}, {"PERSIST", "k"}, {"SETEX", "k", "1", "v"}, {"LPOP", "l"}, {"RPOP", "l"}, {"SPOP", "s"}, {"HDEL", "h", "f"},
	} {
		err := Check(c, ModeRead)
		if !errors.Is(err, ErrWriteCommand) {
			t.Errorf("%v in read mode: want ErrWriteCommand, got %v", c, err)
		}
	}
}

// A write mode allows the ordinary data commands, and still not the rest.
func TestWriteModeAllowsOrdinaryWritesAndStillReads(t *testing.T) {
	for _, c := range [][]string{{"SET", "k", "v"}, {"DEL", "k"}, {"INCR", "k"}, {"HSET", "h", "f", "v"}, {"EXPIRE", "k", "60"}, {"LPUSH", "l", "x"}, {"GET", "k"}} {
		if err := Check(c, ModeWrite); err != nil {
			t.Errorf("%v in write mode: %v", c, err)
		}
	}
}

// What can run code, change the server, read the whole keyspace in one go, block the server, or leave the connection in a state the
// next command does not expect: refused in every mode, with nothing that makes it allowable.
func TestWhatCanHarmTheServerOrTheConnectionIsRefusedInEveryMode(t *testing.T) {
	for _, c := range [][]string{
		{"FLUSHALL"}, {"FLUSHDB"}, {"FLUSHALL", "ASYNC"}, {"CONFIG", "SET", "dir", "/tmp"}, {"CONFIG", "GET", "*"}, {"EVAL", "return 1", "0"},
		{"EVALSHA", "abc", "0"}, {"EVAL_RO", "return 1", "0"}, {"FCALL", "f", "0"}, {"FUNCTION", "LOAD", "x"}, {"SCRIPT", "LOAD", "x"},
		{"KEYS", "*"}, {"DEBUG", "SLEEP", "10"}, {"SHUTDOWN"}, {"SHUTDOWN", "NOSAVE"}, {"REPLICAOF", "evil", "6379"}, {"SLAVEOF", "evil", "6379"},
		{"MODULE", "LOAD", "/x.so"}, {"CLIENT", "KILL", "ID", "1"}, {"CLIENT", "SETNAME", "x"}, {"MONITOR"}, {"SUBSCRIBE", "c"}, {"PSUBSCRIBE", "*"},
		{"PUBLISH", "c", "m"}, {"BLPOP", "l", "0"}, {"BRPOP", "l", "0"}, {"BRPOPLPUSH", "a", "b", "0"}, {"WAIT", "1", "0"}, {"SAVE"}, {"BGSAVE"},
		{"BGREWRITEAOF"}, {"ACL", "SETUSER", "x"}, {"ACL", "WHOAMI"}, {"AUTH", "x"}, {"HELLO", "3"}, {"SELECT", "1"}, {"MULTI"}, {"EXEC"},
		{"WATCH", "k"}, {"MIGRATE", "h", "1", "k", "0", "1"}, {"RESTORE", "k", "0", "x"}, {"DUMP", "k"}, {"OBJECT", "FREQ", "k"}, {"MEMORY", "USAGE", "k"},
		{"SLOWLOG", "GET"}, {"LATENCY", "DOCTOR"}, {"INFO"}, {"COMMAND"}, {"RANDOMKEY"}, {"SORT", "l", "STORE", "x"}, {"MOVE", "k", "1"},
		{"COPY", "a", "b"}, {"SWAPDB", "0", "1"}, {"PSYNC", "x", "1"}, {"SYNC"}, {"FAILOVER"}, {"CLUSTER", "RESET"}, {"READONLY"}, {"QUIT"}, {"RESET"},
		{"XREAD", "STREAMS", "s", "0"}, {"XADD", "s", "*", "f", "v"}, {"PFADD", "h", "x"}, {"GEOADD", "g", "1", "1", "m"}, {"LCS", "a", "b"},
		{"TOTALLYUNKNOWN"}, {""}, {" GET"}, {"GET\n"},
	} {
		for _, mode := range []Mode{ModeRead, ModeWrite} {
			if err := Check(c, mode); err == nil {
				t.Errorf("%q in mode %d was allowed", c, mode)
			}
		}
	}
}

func TestRefusalsSayWhyWithoutRepeatingTheArguments(t *testing.T) {
	err := Check([]string{"SET", "secret-key-xyz", "secret-value-abc"}, ModeRead)
	if err == nil || strings.Contains(err.Error(), "secret-key-xyz") || strings.Contains(err.Error(), "secret-value-abc") {
		t.Errorf("%v", err)
	}
	err = Check([]string{"FLUSHALL"}, ModeWrite)
	if !errors.Is(err, ErrRefusedCommand) {
		t.Errorf("%v", err)
	}
	if err := Check([]string{"NOSUCH" + strings.Repeat("A", 5000)}, ModeRead); err == nil || len(err.Error()) > 300 {
		t.Errorf("a very long command name is not repeated: %v", err)
	}
}

func TestACommandNameIsMatchedExactlyNotByPrefixOrCase(t *testing.T) {
	for _, n := range []string{"GETX", "GE", "SETT", "MGETS", "get ", "\tGET", "G\x00ET", "ＧＥＴ"} {
		if err := Check([]string{n, "k"}, ModeWrite); err == nil {
			t.Errorf("%q was allowed", n)
		}
	}
	if err := Check([]string{"gEt", "k"}, ModeRead); err != nil {
		t.Errorf("case does not matter to Redis, so it does not matter here: %v", err)
	}
}

func TestOnlyTheOptionsOfASafeFormAreAllowed(t *testing.T) {
	for _, tc := range []struct {
		c  []string
		ok bool
	}{
		{[]string{"SCAN", "0", "COUNT", "100"}, true},
		{[]string{"SCAN", "0", "COUNT", "100000"}, false},
		{[]string{"SCAN", "0", "COUNT", "abc"}, false},
		{[]string{"SCAN", "0", "COUNT", "-1"}, false},
		{[]string{"SCAN", "x"}, false},
		{[]string{"SCAN", "0", "TYPE", "string"}, true},
		{[]string{"SCAN", "0", "BOGUS", "1"}, false},
		{[]string{"SCAN"}, false},
		{[]string{"SCAN", "0", "MATCH"}, false},
		{[]string{"SSCAN", "s", "0"}, true},
		{[]string{"HSCAN", "h", "0", "COUNT", "50"}, true},
		{[]string{"ZSCAN", "z", "0", "COUNT", "999999"}, false},
		{[]string{"ZRANGE", "z", "0", "-1", "WITHSCORES"}, true},
		{[]string{"ZRANGE", "z", "0", "-1", "BYSCORE"}, true},
		{[]string{"ZRANGE", "z", "0", "-1", "STORE", "x"}, false},
		{[]string{"ZRANGESTORE", "d", "z", "0", "1"}, false},
		{[]string{"LRANGE", "l", "0", "-1"}, true},
		{[]string{"LRANGE", "l", "0"}, false},
		{[]string{"GET"}, false},
		{[]string{"GET", "a", "b"}, false},
		{[]string{"MGET"}, false},
		{[]string{"SET", "k"}, false},
		{[]string{"SET", "k", "v", "EX", "60"}, true},
		{[]string{"SET", "k", "v", "GET"}, true},
		{[]string{"SET", "k", "v", "BOGUS"}, false},
		{[]string{"EXPIRE", "k", "abc"}, false},
		{[]string{"EXPIRE", "k", "-1"}, true},
	} {
		mode := ModeWrite
		err := Check(tc.c, mode)
		if (err == nil) != tc.ok {
			t.Errorf("%q: allowed=%v, want %v (%v)", tc.c, err == nil, tc.ok, err)
		}
	}
}

func TestTheNumberOfKeysAndArgumentsIsCapped(t *testing.T) {
	many := []string{"MGET"}
	for i := 0; i < MaxKeys+1; i++ {
		many = append(many, "k")
	}
	if err := Check(many, ModeRead); !errors.Is(err, ErrTooManyArgs) {
		t.Errorf("%v", err)
	}
	ok := many[:MaxKeys+1] // the name and exactly MaxKeys keys
	if err := Check(ok, ModeRead); err != nil {
		t.Errorf("exactly the cap is allowed: %v", err)
	}
	long := []string{"GET", strings.Repeat("k", MaxArgBytes+1)}
	if err := Check(long, ModeRead); !errors.Is(err, ErrTooManyArgs) {
		t.Errorf("an argument over the byte cap: %v", err)
	}
	if err := Check([]string{"SET", "k", strings.Repeat("v", MaxArgBytes)}, ModeWrite); err != nil {
		t.Errorf("an argument at the cap is allowed: %v", err)
	}
}

func TestEveryAllowedCommandIsInExactlyOneListAndEveryWriteNeedsWriteMode(t *testing.T) {
	for n := range readCommands {
		if has(writeCommands, n) || refusedAlways[n] {
			t.Errorf("%s is in more than one list", n)
		}
	}
	for n := range writeCommands {
		if refusedAlways[n] {
			t.Errorf("%s is a write and refused", n)
		}
		if err := Check([]string{n, "a", "b", "c"}, ModeRead); err != nil && !errors.Is(err, ErrWriteCommand) && !errors.Is(err, ErrBadArgs) {
			t.Errorf("%s in read mode: %v", n, err)
		}
	}
	if len(readCommands) < 20 || len(writeCommands) < 10 {
		t.Errorf("the lists look empty: %d reads, %d writes", len(readCommands), len(writeCommands))
	}
}

func TestACommandThatCanBlockOrRunForeverIsNeverAllowed(t *testing.T) {
	for _, n := range []string{"BLPOP", "BRPOP", "BLMOVE", "BZPOPMIN", "BZPOPMAX", "WAIT", "SUBSCRIBE", "MONITOR", "SYNC", "PSYNC", "XREAD", "XREADGROUP", "BRPOPLPUSH"} {
		if has(readCommands, n) || has(writeCommands, n) {
			t.Errorf("%s can block the connection and is allowed", n)
		}
	}
}

// A refused command says which command it was, in the words of the refusal; and a command that is only unknown says that it is not on
// the list. The two reasons are told apart, since one is "never" and the other is "not on the list".
func TestARefusedCommandIsNamedAndAnUnknownOneIsNotOnTheList(t *testing.T) {
	err := Check([]string{"flushall"}, ModeWrite)
	if !errors.Is(err, ErrRefusedCommand) || !strings.Contains(err.Error(), "FLUSHALL") || strings.Contains(err.Error(), "not on the list") {
		t.Errorf("%v", err)
	}
	err = Check([]string{"NOSUCHCOMMAND"}, ModeWrite)
	if !errors.Is(err, ErrRefusedCommand) || !strings.Contains(err.Error(), "not on the list") {
		t.Errorf("%v", err)
	}
	if err := Check([]string{""}, ModeRead); !errors.Is(err, ErrEmptyCommand) {
		t.Errorf("an empty name is empty, not unknown: %v", err)
	}
	if err := Check(nil, ModeRead); !errors.Is(err, ErrEmptyCommand) {
		t.Errorf("%v", err)
	}
}

func TestMoreArgumentsThanTheCapIsRefusedBeforeAnyCommandIsLookedAt(t *testing.T) {
	cmd := []string{"DEL"}
	for i := 0; i < MaxArgs+1; i++ {
		cmd = append(cmd, "k")
	}
	if err := Check(cmd, ModeWrite); !errors.Is(err, ErrTooManyArgs) {
		t.Errorf("%v", err)
	}
}

func TestACursorAndACountAreNumbersAndZeroCountIsNotOne(t *testing.T) {
	if err := Check([]string{"SCAN", "0", "COUNT", "0"}, ModeRead); err == nil {
		t.Error("COUNT 0 is not a count")
	}
	if err := Check([]string{"SCAN", "0", "COUNT", "1"}, ModeRead); err != nil {
		t.Errorf("COUNT 1 is the smallest: %v", err)
	}
	if err := Check([]string{"SCAN", "0", "COUNT", "1000"}, ModeRead); err != nil {
		t.Errorf("COUNT at the cap: %v", err)
	}
	if err := Check([]string{"SCAN", "0", "COUNT", "1001"}, ModeRead); err == nil {
		t.Error("COUNT over the cap")
	}
}

func TestOnlyScanHasATypeFilter(t *testing.T) {
	if err := Check([]string{"SSCAN", "s", "0", "TYPE", "set"}, ModeRead); err == nil {
		t.Error("SSCAN has no TYPE")
	}
	if err := Check([]string{"HSCAN", "h", "0", "TYPE", "x"}, ModeRead); err == nil {
		t.Error("HSCAN has no TYPE")
	}
	if err := Check([]string{"SCAN", "0", "TYPE", "hash"}, ModeRead); err != nil {
		t.Errorf("SCAN has: %v", err)
	}
}

func TestAnOptionThatNeedsValuesMustHaveThemAll(t *testing.T) {
	if err := Check([]string{"ZRANGE", "z", "0", "-1", "LIMIT", "0", "10"}, ModeRead); err != nil {
		t.Errorf("a LIMIT with its two values: %v", err)
	}
	for _, c := range [][]string{
		{"ZRANGE", "z", "0", "-1", "LIMIT"},
		{"ZRANGE", "z", "0", "-1", "LIMIT", "0"},
	} {
		if err := Check(c, ModeRead); err == nil {
			t.Errorf("%q: a LIMIT without its values was allowed", c)
		}
	}
	if err := Check([]string{"ZRANGE", "z", "0", "-1", "LIMIT", "0", "10", "WITHSCORES"}, ModeRead); err != nil {
		t.Errorf("a flag after the values: %v", err)
	}
}

func TestAnExpiryOfASetIsANumber(t *testing.T) {
	for _, o := range []string{"EX", "PX", "EXAT", "PXAT"} {
		if err := Check([]string{"SET", "k", "v", o, "abc"}, ModeWrite); err == nil {
			t.Errorf("%s abc", o)
		}
		if err := Check([]string{"SET", "k", "v", o}, ModeWrite); err == nil {
			t.Errorf("%s with no value", o)
		}
		if err := Check([]string{"SET", "k", "v", o, "60"}, ModeWrite); err != nil {
			t.Errorf("%s 60: %v", o, err)
		}
	}
	if err := Check([]string{"SET", "k", "v", "NX", "EX", "60", "GET"}, ModeWrite); err != nil {
		t.Errorf("%v", err)
	}
}

func TestANumberWhereANumberIsExpectedIsRefused(t *testing.T) {
	for _, c := range [][]string{
		{"EXPIRE", "k", "x"}, {"PEXPIRE", "k", "x"}, {"INCRBY", "k", "x"}, {"DECRBY", "k", "x"}, {"SETEX", "k", "x", "v"},
		{"LRANGE", "l", "x", "1"}, {"LRANGE", "l", "0", "x"}, {"LTRIM", "l", "x", "1"}, {"GETRANGE", "k", "0", "x"}, {"LINDEX", "l", "x"},
	} {
		if err := Check(c, ModeWrite); err == nil {
			t.Errorf("%q was allowed", c)
		}
	}
}

func TestARefusalNamesTheCommandAndNeverTheArguments(t *testing.T) {
	err := Check([]string{"CONFIG", "SET", "requirepass", "hunter2-secret"}, ModeWrite)
	if err == nil || strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "requirepass") || !strings.Contains(err.Error(), "CONFIG") {
		t.Errorf("%v", err)
	}
}

// MaxArgs is the backstop over each command's own limit. A command with no limit of its own, or one above the backstop, would make
// the backstop the only thing that stops it: that is allowed to be true only on purpose.
func TestNoCommandsOwnLimitIsAboveTheBackstopOrMissing(t *testing.T) {
	for _, tab := range []map[string]arity{readCommands, writeCommands} {
		for n, a := range tab {
			if a.max < 0 || a.max > MaxArgs {
				t.Errorf("%s: its own limit (%d) is missing or above the backstop of %d", n, a.max, MaxArgs)
			}
		}
	}
}
