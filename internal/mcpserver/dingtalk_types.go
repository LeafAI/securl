package mcpserver

// DingTalkTargetsOutput lists the groups the owner has made reachable. A group is named, and its webhook is not here: an agent names
// things, it does not learn what would let it act outside securl.
type DingTalkTargetsOutput struct {
	Groups []DingTalkGroupInfo `json:"groups"`
}

type DingTalkGroupInfo struct {
	Name       string `json:"name"`
	HasSession bool   `json:"has_session"` // a person has typed the group's webhook
	SendLimit  int    `json:"send_limit"`  // messages the group's robot sends per send_window_seconds
	SendWindow int    `json:"send_window_seconds"`
}

type DingTalkSendInput struct {
	Group string `json:"group" jsonschema:"A group name from dingtalk_targets."`
	Text  string `json:"text" jsonschema:"The message, as plain text (nothing is read as formatting or as a link, and nobody is mentioned). securl puts a line first that says an AI agent sent it; you cannot change that line."`
}

type DingTalkSendOutput struct {
	Sent bool `json:"sent"`
}
