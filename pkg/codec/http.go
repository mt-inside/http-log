package codec

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/mt-inside/http-log/pkg/state"
	"github.com/mt-inside/http-log/pkg/utils"
)

func FirstHeaderFromRequest(headers http.Header, key string) (value string) {
	value = ""

	hs := headers[http.CanonicalHeaderKey(key)]
	if len(hs) >= 1 { // len(nil) == 0
		value = hs[0]
	}

	return
}
func HeaderRepeatedOrCommaSeparated(headers http.Header, key string) []string {
	hs := headers[http.CanonicalHeaderKey(key)]
	if len(hs) == 1 {
		hs = strings.Split(hs[0], ",") // works fine if string doesn't contain ','
	}
	for i := range hs {
		hs[i] = strings.TrimSpace(hs[i])
	}
	return hs
}

func HeaderFromMap(headers map[string]interface{}, key string) (value string) {
	value = ""
	if h, ok := headers[http.CanonicalHeaderKey(key)]; ok { // TODO we canonicalise the header key, but I don't think they're canonicalised in this map
		value = h.(string)
	}
	return
}

func ExtractProxies(r *state.RequestData, s *state.DaemonData) []*state.Hop {

	lastHop := &state.Hop{
		TLS:         s.TlsOn,
		Version:     r.HttpProtocolVersion,
		VHost:       r.HttpHost,
		ServerAgent: "http-log v0.5", // TODO from build pkg when we do that
	}
	lastHop.ClientHost, lastHop.ClientPort = utils.SplitNetAddr(r.TransportRemoteAddress)
	lastHop.ServerHost, lastHop.ServerPort = utils.SplitNetAddr(r.TransportLocalAddress)

	// Empirically:
	// - Apache2: appends x-forwaded-[for,host,server]; overwrites x-forwaded-proto
	// - Nginx: appends x-forwaded-for; ? others
	// - Envoy: appends x-forwaded-for; ? others

	forwadeds := HeaderRepeatedOrCommaSeparated(r.HttpHeaders, "Forwarded")
	forwadedHops := []*state.Hop{}
	for _, f := range forwadeds {
		forwadedHops = append(forwadedHops, parseForwaded(f))
	}
	forwadedHops = append(forwadedHops, lastHop)
	smudgeHops(forwadedHops)

	forwadedFors := HeaderRepeatedOrCommaSeparated(r.HttpHeaders, "X-Forwarded-For")
	forwadedHosts := HeaderRepeatedOrCommaSeparated(r.HttpHeaders, "X-Forwarded-Host")
	forwadedProtos := HeaderRepeatedOrCommaSeparated(r.HttpHeaders, "X-Forwarded-Proto")
	forwadedServers := HeaderRepeatedOrCommaSeparated(r.HttpHeaders, "X-Forwarded-Server")
	forwadedForHops := []*state.Hop{}
	for _, f := range forwadedFors {
		forwadedForHops = append(forwadedForHops, parseXForwadedFor(f))
	}
	forwadedForHops = append(forwadedForHops, lastHop)
	smudgeHops(forwadedForHops)

	// Build this separately from x-forwaded-for, cause not everything that sets that sets these, but these seem to always be set together, giving us a way to find the proxy identity for the hosts and protos
	// - X-Forwaded-Host: name[:port] (original Host header)
	// - X-Forwaded-Proto: http|https (proto used between client and LB; origin will see LB to origin)
	forwadedForOtherHops := []*state.Hop{}
	for _, server := range forwadedServers {
		hop := &state.Hop{
			ServerHost: utils.HostFromHostMaybePort(server),
			ServerPort: utils.PortFromHostMaybePort(server),
		}
		forwadedForOtherHops = append(forwadedForOtherHops, hop)
	}
	if len(forwadedProtos) == len(forwadedForOtherHops) {
		for i, hop := range forwadedForOtherHops {
			hop.TLS = protocolIsTLS(forwadedProtos[i])
		}
	}
	if len(forwadedHosts) == len(forwadedForOtherHops) {
		for i, hop := range forwadedForOtherHops {
			hop.VHost = forwadedHosts[i]
		}
	}
	forwadedForOtherHops = append(forwadedForOtherHops, lastHop)
	smudgeHops(forwadedForOtherHops)

	vias := HeaderRepeatedOrCommaSeparated(r.HttpHeaders, "Via")
	viaHops := []*state.Hop{}
	for _, v := range vias {
		viaHops = append(viaHops, parseVia(v))
	}
	viaHops = append(viaHops, lastHop)
	smudgeHops(viaHops)

	hopses := [][]*state.Hop{
		forwadedForHops,
		forwadedHops,
		forwadedForOtherHops,
		viaHops,
	}
	// Stable sort allows us to express a preference for the ordering above
	sort.SliceStable(hopses,
		func(i, j int) bool {
			return len(hopses[i]) > len(hopses[j])
		})
	hops := mergeHops(hopses)

	// TODO: leave TODO to use the new state-holding OP to print the proxy chain with TCP connection info

	// TODO: x-real-ip
	//
	// TODO: x-envoy-* (external-address etc)

	// TODO: validate internal consistency, like each Hop's host should be the previous one's client. If that's not true, assume there's a transparent agent in the middle and insert a placeholder?

	return hops
}

func protocolIsTLS(protocol string) bool {
	if strings.EqualFold(protocol, "http") {
		return false
	} else if strings.EqualFold(protocol, "https") {
		return true
	} else {
		panic(fmt.Errorf("unknown protocol: %s", protocol))
	}
}

func parseForwaded(forwaded string) *state.Hop {
	h := &state.Hop{}

	// Forwaded: by=<incoming interface>;for=<caller>;host=<host it was looking for>;proto=<http|https>,...
	fields := strings.Split(forwaded, ";")
	for _, field := range fields {
		pivot := strings.IndexRune(field, '=')
		key := field[:pivot]
		value := field[pivot+1:]
		switch key {
		case "by":
			h.ServerHost, h.ServerPort = utils.SplitHostMaybePort(value)
		case "for":
			h.ClientHost, h.ClientPort = utils.SplitHostMaybePort(value)
		case "host":
			h.VHost = value
		case "proto":
			h.TLS = protocolIsTLS(value)
		default:
			panic(errors.New("unknown field in Forwarded header"))
		}
	}

	return h
}

func parseVia(via string) *state.Hop {
	h := &state.Hop{}

	// Via: HTTP/1.1 proxy.foo.com:8080, <repeat>
	// Via: 1.1 proxy.foo.com, <repeat> (proxy's name)
	fields := strings.Fields(via) // split on any whitespace
	if len(fields) != 2 && len(fields) != 3 {
		panic(fmt.Errorf("malformed Via header: '%s'", via))
	}
	proto := fields[0]                                               // can be split into host and optional port
	h.ServerHost, h.ServerPort = utils.SplitHostMaybePort(fields[1]) // might be proxy host[:port] or might be a "pseudonym" for the proxy. Unable to tell pseudonym from host-without-port I think
	if len(fields) == 3 {
		h.ServerAgent = fields[2]
	}

	protoParts := strings.Split(proto, "/")
	switch len(protoParts) {
	case 1:
		h.Version = protoParts[0]
	case 2:
		h.TLS = protocolIsTLS(protoParts[0])
		h.Version = protoParts[1]
	default:
		panic(fmt.Errorf("malformed Via header: '%s'", via))
	}

	return h
}

func parseXForwadedFor(xff string) *state.Hop {
	h := &state.Hop{}

	// X-Forwaded-For: ip, <repeat>
	h.ClientHost = utils.HostFromHostMaybePort(xff) // Spec says no port but just in case

	return h
}

func smudgeHops(hops []*state.Hop) {
	for i := range hops {
		if hops[i].ClientHost == "" && i >= 1 {
			hops[i].ClientHost = hops[i-1].ServerHost
		}
		if hops[i].ServerHost == "" && i <= len(hops)-1-1 {
			hops[i].ServerHost = hops[i+1].ClientHost
		}
	}
}
func mergeHops(hopses [][]*state.Hop) []*state.Hop {
	for _, seconadry := range hopses[1:] {
		if len(seconadry) == 0 {
			break // if this is empty we know all the others after it will be because of the sort so we're done
		}
		var i int
		for _, hop := range hopses[0] {
			if seconadry[i].ServerHost == hop.ServerHost {
				if hop.ServerAgent == "" {
					hop.ServerAgent = seconadry[i].ServerAgent
				}
				if hop.ClientHost == "" {
					hop.ClientHost = seconadry[i].ClientHost
				}
				if hop.ClientPort == "" {
					hop.ClientPort = seconadry[i].ClientPort
				}
				// TODO: need to distibguish been false and not set
				if hop.Version == "" {
					hop.Version = seconadry[i].Version
				}
				if hop.VHost == "" {
					hop.VHost = seconadry[i].VHost
				}

				if i == len(seconadry)-1 {
					break
				}
				i = i + 1
			}
		}
	}

	return hopses[0]
}
