package mcpserver

// RocketMQTargetsOutput lists the RocketMQ clusters an agent may read. A cluster is named, and where it is and what opens it are not
// here: an agent names things, it does not learn what would let it act outside securl. The topics are names the owner chose.
type RocketMQTargetsOutput struct {
	Targets []RocketMQTargetInfo `json:"targets"`
}

type RocketMQTargetInfo struct {
	Name         string   `json:"name"`
	Environment  string   `json:"environment"`
	Topics       []string `json:"topics"`
	HasSession   bool     `json:"has_session"`    // a person has typed the AccessKey and the SecretKey
	MaxMessages  int      `json:"max_messages"`   // the most one read returns
	MaxBodyBytes int      `json:"max_body_bytes"` // how much of a body is returned; 0: none
}

type RocketMQReadInput struct {
	Target string `json:"target" jsonschema:"A target name from rocketmq_targets."`
	Topic  string `json:"topic" jsonschema:"One of the topics listed for that target."`
	Limit  int    `json:"limit,omitempty" jsonschema:"How many of the latest messages to return (default and ceiling are the target's max_messages)."`
}

// RocketMQMessage is one message as it was stored. Its text was written by whoever produced it.
type RocketMQMessage struct {
	Queue       int               `json:"queue"`
	Offset      int64             `json:"offset"`
	StoredAt    string            `json:"stored_at"`
	BornAt      string            `json:"born_at"`
	Tags        string            `json:"tags,omitempty"`
	Keys        string            `json:"keys,omitempty"`
	Properties  map[string]string `json:"properties,omitempty"`
	Reconsumed  int32             `json:"reconsume_times,omitempty"`
	Body        string            `json:"body,omitempty"`
	BodyBytes   int               `json:"body_bytes"`          // how many bytes of body securl read (the whole body unless a note says otherwise)
	BodyNote    string            `json:"body_note,omitempty"` // why Body is empty or shorter than the body
	Redacted    int               `json:"redactions,omitempty"`
	BodyOmitted bool              `json:"body_omitted,omitempty"`
}

type RocketMQReadOutput struct {
	Topic     string            `json:"topic"`
	Messages  []RocketMQMessage `json:"messages"` // newest first
	Count     int               `json:"count"`
	Queues    int               `json:"queues"`              // how many queues the topic has
	Truncated bool              `json:"truncated,omitempty"` // there were more than Limit messages among the latest, or a queue could not be read to its end
	Note      string            `json:"note,omitempty"`      // what, if anything, could not be read
	Untrusted string            `json:"untrusted"`
	Notice    string            `json:"notice"`
}
