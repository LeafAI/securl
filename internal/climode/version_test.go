package climode

import "github.com/LeafAI/securl/internal/mcpserver"

func mcpserverVersion() string { return mcpserver.Version }
func setMCPVersion(v string)   { mcpserver.Version = v }
