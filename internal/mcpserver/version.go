package mcpserver

// Version is the server's version as reported to MCP clients. The binary overrides it at build time:
//
//	go build -ldflags "-X github.com/LeafAI/securl/internal/mcpserver.Version=1.2.3"
var Version = "0.1.0"

// ExternalDrivers lists the login drivers that were built into this binary from other repositories (see docs/DRIVERS.md), each as
// module@commit. The build writes it; it is empty in a build with only the drivers that are part of securl. `securl version` says
// it, so that a binary with a private driver in it cannot be taken for an ordinary one.
var ExternalDrivers []string
