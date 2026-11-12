package mcpserver

// TelegramTargetsOutput lists the bots and chats the owner has made reachable. A chat is named, never numbered, and a bot's token
// and username are not here: an agent names things, it does not learn what would let it act outside securl.
type TelegramTargetsOutput struct {
	Bots []TelegramBotInfo `json:"bots"`
}

type TelegramBotInfo struct {
	Name       string             `json:"name"`
	HasSession bool               `json:"has_session"` // a person has typed the bot's token
	Chats      []TelegramChatInfo `json:"chats"`
	SendLimit  int                `json:"send_limit"` // messages the bot sends per send_window_seconds
	SendWindow int                `json:"send_window_seconds"`
}

type TelegramChatInfo struct {
	Name string `json:"name"`
	Read bool   `json:"read"`
	Send bool   `json:"send"`
}

type TelegramSendInput struct {
	Bot     string `json:"bot" jsonschema:"A bot name from telegram_targets."`
	Chat    string `json:"chat" jsonschema:"A chat name from telegram_targets (never a chat id)."`
	Text    string `json:"text" jsonschema:"The message, as plain text (nothing is read as formatting or as a link). securl puts a line first that says an AI agent sent it; you cannot change that line."`
	ReplyTo int64  `json:"reply_to,omitempty" jsonschema:"The message_id of a message in this chat to answer."`
}

type TelegramSendOutput struct {
	Sent      bool  `json:"sent"`
	MessageID int64 `json:"message_id"`
}

type TelegramReadInput struct {
	Bot         string `json:"bot" jsonschema:"A bot name from telegram_targets."`
	Chat        string `json:"chat" jsonschema:"A chat name from telegram_targets (never a chat id)."`
	Limit       int    `json:"limit,omitempty" jsonschema:"At most this many messages, oldest first (default 50, at most 100)."`
	WaitSeconds int    `json:"wait_seconds,omitempty" jsonschema:"When nothing new has been said, wait up to this long for something (at most 25)."`
}

// TelegramMessage is one thing somebody said. Every field here was written by a person or a program in the chat, not by securl.
type TelegramMessage struct {
	MessageID int64  `json:"message_id"`
	From      string `json:"from"` // what the sender calls themselves: it can be anything, so it proves nothing
	FromBot   bool   `json:"from_bot"`
	Time      string `json:"time"`
	Text      string `json:"text"`
	Truncated bool   `json:"truncated,omitempty"`
	ReplyTo   int64  `json:"reply_to,omitempty"`
}

// TelegramReadOutput is what was said in a chat. Notice is securl's own text, the same every time, and says what the messages are.
type TelegramReadOutput struct {
	Untrusted string            `json:"untrusted"`
	Notice    string            `json:"notice"`
	Count     int               `json:"count"`
	More      bool              `json:"more,omitempty"`
	Messages  []TelegramMessage `json:"messages"`
}
