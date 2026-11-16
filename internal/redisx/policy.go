package redisx

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Mode is what a target lets an agent do.
type Mode int

const (
	// ModeRead allows the commands that read.
	ModeRead Mode = iota
	// ModeWrite allows those and the ordinary commands that change data.
	ModeWrite
)

// Why a command was not run.
var (
	ErrWriteCommand   = errors.New("that command changes data, and this target is read-only")
	ErrRefusedCommand = errors.New("that command is not one an agent may run")
	ErrBadArgs        = errors.New("the arguments of that command are not in a form that is allowed")
	ErrTooManyArgs    = errors.New("the command has too many arguments, or one that is too long")
	ErrEmptyCommand   = errors.New("the command is empty")
)

// Caps on what one command may carry. A command is built from the agent's words and goes to a server that may be shared: how much it
// can name is bounded here, apart from what the server would do with it.
const (
	MaxKeys     = 100     // keys one command may name
	MaxArgs     = 300     // arguments after the name: a backstop over every command's own limit, which a test holds under this
	MaxArgBytes = 1 << 20 // bytes in one argument
	MaxScanSize = 1000    // COUNT of a SCAN
)

// arity says how many arguments (after the name) a command takes: min, and max (-1: no limit).
type arity struct{ min, max int }

// readCommands are the commands that read one value, or a bounded range of one, and change nothing. A command that reads the whole
// keyspace (KEYS), the server's own state (INFO, CONFIG, CLIENT, SLOWLOG), or can run code or block is not here, whatever else it does.
var readCommands = map[string]arity{
	"PING": {0, 1}, "GET": {1, 1}, "MGET": {1, MaxKeys}, "EXISTS": {1, MaxKeys}, "TYPE": {1, 1}, "TTL": {1, 1}, "PTTL": {1, 1},
	"STRLEN": {1, 1}, "GETRANGE": {3, 3},
	"HGET": {2, 2}, "HGETALL": {1, 1}, "HMGET": {2, MaxKeys + 1}, "HLEN": {1, 1}, "HEXISTS": {2, 2}, "HKEYS": {1, 1}, "HVALS": {1, 1}, "HSTRLEN": {2, 2},
	"LRANGE": {3, 3}, "LLEN": {1, 1}, "LINDEX": {2, 2},
	"SMEMBERS": {1, 1}, "SCARD": {1, 1}, "SISMEMBER": {2, 2}, "SMISMEMBER": {2, MaxKeys + 1},
	"ZRANGE": {3, 8}, "ZCARD": {1, 1}, "ZSCORE": {2, 2}, "ZRANK": {2, 2}, "ZREVRANK": {2, 2}, "ZCOUNT": {3, 3}, "ZREVRANGE": {3, 4},
	"SCAN": {1, 7}, "SSCAN": {2, 6}, "HSCAN": {2, 6}, "ZSCAN": {2, 6}, "DBSIZE": {0, 0},
}

// writeCommands are the ordinary commands that change one key or a few. Only a target that says so lets an agent run them.
var writeCommands = map[string]arity{
	"SET": {2, 8}, "SETEX": {3, 3}, "SETNX": {2, 2}, "MSET": {2, MaxKeys * 2}, "APPEND": {2, 2}, "GETDEL": {1, 1}, "GETSET": {2, 2},
	"DEL": {1, MaxKeys}, "UNLINK": {1, MaxKeys}, "INCR": {1, 1}, "DECR": {1, 1}, "INCRBY": {2, 2}, "DECRBY": {2, 2},
	"EXPIRE": {2, 2}, "PEXPIRE": {2, 2}, "PERSIST": {1, 1}, "RENAME": {2, 2},
	"HSET": {3, MaxKeys * 2}, "HDEL": {2, MaxKeys}, "HINCRBY": {3, 3}, "HSETNX": {3, 3},
	"LPUSH": {2, MaxKeys}, "RPUSH": {2, MaxKeys}, "LPOP": {1, 2}, "RPOP": {1, 2}, "LTRIM": {3, 3}, "LREM": {3, 3},
	"SADD": {2, MaxKeys}, "SREM": {2, MaxKeys}, "SPOP": {1, 2},
	"ZADD": {3, MaxKeys * 2}, "ZREM": {2, MaxKeys}, "ZINCRBY": {3, 3},
}

// refusedAlways is what no mode allows, kept as a list so that a test can say it out loud. It is not what protects: only the two
// lists above allow anything, so a command that is in neither is refused too. This list exists to give a clearer reason.
var refusedAlways = map[string]bool{
	"FLUSHALL": true, "FLUSHDB": true, "CONFIG": true, "EVAL": true, "EVALSHA": true, "EVAL_RO": true, "EVALSHA_RO": true, "FCALL": true,
	"FUNCTION": true, "SCRIPT": true, "KEYS": true, "DEBUG": true, "SHUTDOWN": true, "REPLICAOF": true, "SLAVEOF": true, "MODULE": true,
	"CLIENT": true, "MONITOR": true, "SUBSCRIBE": true, "PSUBSCRIBE": true, "SSUBSCRIBE": true, "PUBLISH": true, "BLPOP": true, "BRPOP": true,
	"BLMOVE": true, "BRPOPLPUSH": true, "BZPOPMIN": true, "BZPOPMAX": true, "WAIT": true, "SAVE": true, "BGSAVE": true, "BGREWRITEAOF": true,
	"ACL": true, "AUTH": true, "HELLO": true, "SELECT": true, "MULTI": true, "EXEC": true, "DISCARD": true, "WATCH": true, "UNWATCH": true,
	"MIGRATE": true, "RESTORE": true, "DUMP": true, "OBJECT": true, "MEMORY": true, "SLOWLOG": true, "LATENCY": true, "INFO": true,
	"COMMAND": true, "RANDOMKEY": true, "SORT": true, "MOVE": true, "COPY": true, "SWAPDB": true, "PSYNC": true, "SYNC": true, "FAILOVER": true,
	"CLUSTER": true, "READONLY": true, "READWRITE": true, "QUIT": true, "RESET": true, "XREAD": true, "XREADGROUP": true, "XADD": true,
	"LOLWUT": true, "ZRANGESTORE": true, "ZUNIONSTORE": true, "ZINTERSTORE": true, "SUNIONSTORE": true, "SINTERSTORE": true, "SDIFFSTORE": true,
	"SORT_RO": true, "OBJECT_": true, "PFADD": true, "PFCOUNT": true, "PFMERGE": true, "GEOADD": true, "LCS": true, "WAITAOF": true,
}

// Check says whether the agent may run this command (its name first, then its arguments) on a target in this mode. It does not run
// anything. The error never repeats an argument: they are the agent's, and a key can hold anything.
func Check(cmd []string, mode Mode) error {
	if len(cmd) == 0 || cmd[0] == "" {
		return ErrEmptyCommand
	}
	if len(cmd)-1 > MaxArgs {
		return ErrTooManyArgs
	}
	for _, a := range cmd[1:] {
		if len(a) > MaxArgBytes {
			return ErrTooManyArgs
		}
	}
	name := strings.ToUpper(cmd[0])
	if name != cmd[0] && strings.ToUpper(strings.TrimSpace(cmd[0])) != name {
		return ErrRefusedCommand
	}
	args := cmd[1:]
	if ar, ok := readCommands[name]; ok {
		return checkShape(name, args, ar)
	}
	if ar, ok := writeCommands[name]; ok {
		if mode != ModeWrite {
			return fmt.Errorf("%w (%s)", ErrWriteCommand, name)
		}
		return checkShape(name, args, ar)
	}
	if refusedAlways[name] {
		return fmt.Errorf("%w (%s)", ErrRefusedCommand, name)
	}
	return fmt.Errorf("%w: it is not on the list of commands that are allowed", ErrRefusedCommand)
}

func checkShape(name string, args []string, ar arity) error {
	if ar.max >= 0 && len(args) > ar.max {
		return fmt.Errorf("%w (%s takes %s)", ErrTooManyArgs, name, arityText(ar))
	}
	if len(args) < ar.min {
		return fmt.Errorf("%w (%s takes %s)", ErrBadArgs, name, arityText(ar))
	}
	switch name {
	case "SCAN":
		return checkScan(name, args[1:], args[0], true)
	case "SSCAN", "HSCAN", "ZSCAN":
		return checkScan(name, args[2:], args[1], false)
	case "ZRANGE":
		return checkOptions(name, args[3:], map[string]bool{"WITHSCORES": true, "BYSCORE": true, "BYLEX": true, "REV": true}, map[string]int{"LIMIT": 2})
	case "ZREVRANGE":
		return checkOptions(name, args[3:], map[string]bool{"WITHSCORES": true}, nil)
	case "SET":
		return checkSet(name, args[2:])
	case "EXPIRE", "PEXPIRE", "INCRBY", "DECRBY", "SETEX":
		return checkNumbers(name, args, map[string][]int{"EXPIRE": {1}, "PEXPIRE": {1}, "INCRBY": {1}, "DECRBY": {1}, "SETEX": {1}}[name])
	case "LRANGE", "LTRIM":
		return checkNumbers(name, args, []int{1, 2})
	case "GETRANGE":
		return checkNumbers(name, args, []int{1, 2})
	case "LINDEX":
		return checkNumbers(name, args, []int{1})
	case "ZCOUNT":
		return nil
	}
	return nil
}

func arityText(a arity) string {
	switch {
	case a.max == a.min:
		return strconv.Itoa(a.min) + " argument(s)"
	case a.max < 0:
		return "at least " + strconv.Itoa(a.min)
	}
	return strconv.Itoa(a.min) + " to " + strconv.Itoa(a.max)
}

func isInt(s string) bool { _, err := strconv.ParseInt(s, 10, 64); return err == nil }

func checkNumbers(name string, args []string, at []int) error {
	for _, i := range at {
		if i < len(args) && !isInt(args[i]) {
			return fmt.Errorf("%w (%s wants a number there)", ErrBadArgs, name)
		}
	}
	return nil
}

// checkScan holds a SCAN-family call to a cursor that is a number, and to options that are safe: MATCH, COUNT (capped), TYPE.
func checkScan(name string, opts []string, cursor string, allowType bool) error {
	if c, err := strconv.ParseUint(cursor, 10, 64); err != nil || c > 1<<63 {
		return fmt.Errorf("%w (%s wants a numeric cursor)", ErrBadArgs, name)
	}
	for i := 0; i < len(opts); i += 2 {
		if i+1 >= len(opts) {
			return fmt.Errorf("%w (%s: an option without its value)", ErrBadArgs, name)
		}
		switch strings.ToUpper(opts[i]) {
		case "MATCH":
		case "COUNT":
			n, err := strconv.Atoi(opts[i+1])
			if err != nil || n < 1 || n > MaxScanSize {
				return fmt.Errorf("%w (%s: COUNT is 1 to %d)", ErrBadArgs, name, MaxScanSize)
			}
		case "TYPE":
			if !allowType {
				return fmt.Errorf("%w (%s has no TYPE)", ErrBadArgs, name)
			}
		default:
			return fmt.Errorf("%w (%s: that option is not allowed)", ErrBadArgs, name)
		}
	}
	return nil
}

// checkOptions allows flags (no value) and options with n values, and nothing else: in particular not STORE.
func checkOptions(name string, opts []string, flags map[string]bool, valued map[string]int) error {
	for i := 0; i < len(opts); i++ {
		o := strings.ToUpper(opts[i])
		if flags[o] {
			continue
		}
		if n, ok := valued[o]; ok {
			if i+n > len(opts)-1 {
				return fmt.Errorf("%w (%s: %s needs %d values)", ErrBadArgs, name, o, n)
			}
			i += n
			continue
		}
		return fmt.Errorf("%w (%s: that option is not allowed)", ErrBadArgs, name)
	}
	return nil
}

// checkSet allows SET's own options: expiry, NX/XX, GET, KEEPTTL. Nothing else follows a value.
func checkSet(name string, opts []string) error {
	for i := 0; i < len(opts); i++ {
		switch strings.ToUpper(opts[i]) {
		case "NX", "XX", "GET", "KEEPTTL":
		case "EX", "PX", "EXAT", "PXAT":
			if i+1 >= len(opts) || !isInt(opts[i+1]) {
				return fmt.Errorf("%w (%s: an expiry needs a number)", ErrBadArgs, name)
			}
			i++
		default:
			return fmt.Errorf("%w (%s: that option is not allowed)", ErrBadArgs, name)
		}
	}
	return nil
}

// IsWrite reports whether a command that Check allows only in write mode is one that changes data. It is the policy's own answer, so
// the tools do not keep a second list.
func IsWrite(cmd []string) bool {
	if len(cmd) == 0 {
		return false
	}
	_, ok := writeCommands[strings.ToUpper(cmd[0])]
	return ok
}

// IsRead reports whether the command is on the list of reads.
func IsRead(cmd []string) bool {
	if len(cmd) == 0 {
		return false
	}
	_, ok := readCommands[strings.ToUpper(cmd[0])]
	return ok
}
