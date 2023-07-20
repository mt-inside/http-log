package utils

import (
	"fmt"
	"net"
	"strconv"
)

func HostFromHostMaybePort(hostMaybePort string) (host string) {
	var err error
	host, _, err = net.SplitHostPort(hostMaybePort)
	if err != nil {
		host = hostMaybePort
	}
	return
}
func PortFromHostMaybePort(hostMaybePort string) (port string) {
	var err error
	_, port, err = net.SplitHostPort(hostMaybePort)
	if err != nil {
		port = ""
	}
	return
}
func SplitHostMaybePort(hostMaybePort string) (host, port string) {
	var err error
	host, port, err = net.SplitHostPort(hostMaybePort)
	if err != nil {
		host = hostMaybePort
		port = ""
	}
	return
}
func SplitHostMaybePortDefault(hostMaybePort string, defaultPort uint64) (string, uint64) {
	var err error
	host, port, err := net.SplitHostPort(hostMaybePort)
	if err == nil {
		p, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			panic(err)
		}
		return host, p
	} else {
		return hostMaybePort, defaultPort
	}
}

func SplitNetAddr(addr net.Addr) (host, port string) {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP.String(), strconv.Itoa(a.Port)
	case *net.UDPAddr:
		return a.IP.String(), strconv.Itoa(a.Port)
	default:
		panic(fmt.Errorf("unknown net.Addr type %v", addr))
	}
}
