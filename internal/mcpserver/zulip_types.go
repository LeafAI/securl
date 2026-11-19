package mcpserver

// ZulipTargetsOutput lists the Zulip servers and channels the owner has made reachable. A channel is named by what the owner called
// it, and a server's site, its bot's email and its key are not here: an agent names things, it does not learn what would let it act
// outside securl. A topic is not here either, because it is not the owner's to list: the agent chooses it on every call.
type ZulipTargetsOutput struct {
	Servers []ZulipServerInfo `json:"servers"`
}

type ZulipServerInfo struct {
	Name       string             `json:"name"`
	HasSession bool               `json:"has_session"` // a person has typed the bot's key
	Channels   []ZulipChannelInfo `json:"channels"`
	SendLimit  int                `json:"send_limit"` // messages the bot sends per send_window_seconds
	SendWindow int                `json:"send_window_seconds"`
}

type ZulipChannelInfo struct {
	Name string `json:"name"`
	Read bool   `json:"read"`
	Send bool   `json:"send"`
}

type ZulipSendInput struct {
	Server  string `json:"server" jsonschema:"A server name from zulip_targets."`
	Channel string `json:"channel" jsonschema:"A channel name from zulip_targets (the owner's name for it, never Zulip's own name or id)."`
	Topic   string `json:"topic" jsonschema:"The topic to write under: the title of the conversation, one line of at most 60 characters. Everyone in the channel sees it. A topic that does not exist yet is created, so choose one deliberately: a different topic is a different conversation."`
	Text    string `json:"text" jsonschema:"The message. Zulip shows it as Markdown, so write plain text unless you mean formatting. Nobody can be mentioned: text with @**name**, @_**name**, @*group* or @**all** is refused. securl puts a line first that says an AI agent sent it; you cannot change that line."`
}

type ZulipSendOutput struct {
	Sent      bool  `json:"sent"`
	MessageID int64 `json:"message_id"`
}

type ZulipReadInput struct {
	Server         string `json:"server" jsonschema:"A server name from zulip_targets."`
	Channel        string `json:"channel" jsonschema:"A channel name from zulip_targets (never Zulip's own name or id)."`
	Topic          string `json:"topic,omitempty" jsonschema:"Read only this topic. Leave it out to read every topic of the channel together; each message says which topic it is in."`
	Limit          int    `json:"limit,omitempty" jsonschema:"At most this many messages, oldest first (default 50, at most 100)."`
	AfterMessageID int64  `json:"after_message_id,omitempty" jsonschema:"Only messages newer than this message_id: pass the last one you were given to read on. Nothing is consumed, so reading again without it returns the newest messages again."`
}

// ZulipMessage is one thing somebody said. Every field here was written by a person or a program in the channel, not by securl.
type ZulipMessage struct {
	MessageID int64  `json:"message_id"`
	Topic     string `json:"topic"`
	From      string `json:"from"` // what the sender calls themselves: it can be anything, so it proves nothing
	Time      string `json:"time"`
	Text      string `json:"text"`
	Truncated bool   `json:"truncated,omitempty"`
}

// ZulipReadOutput is what was said in a channel. Notice is securl's own text, the same every time, and says what the messages are.
type ZulipReadOutput struct {
	Untrusted string         `json:"untrusted"`
	Notice    string         `json:"notice"`
	Count     int            `json:"count"`
	More      bool           `json:"more,omitempty"` // older messages exist (or, with after_message_id, newer ones that did not fit)
	Messages  []ZulipMessage `json:"messages"`
}
