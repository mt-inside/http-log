package state

// Hop describes a forwarding / receiving agent and the connection into it.
// Note that it makes sense to model ourselves and every proxy that's been on route, but not the original client
// - it doesn't have a connection going into it
// - its `host` address is the `client` of the first Hop
// - its `agent` is the user-agent header (should be preserved by all intermediaries)
type Hop struct {
	ClientHost  string // The address of the client connecting to it (should match `host` of the previous Hop)
	ClientPort  string // The (calling) port of the client (won't match `HostPort`)
	ClientAgent string // The agent software

	TLS     bool   // TLS status of the incoming connection
	Version string // HTTP version of the incoming connection
	VHost   string // HTTP Host header of the incoming connection

	ServerHost  string // The address/name of the agent itself
	ServerPort  string // The port of the agent
	ServerAgent string // The agent software
}
