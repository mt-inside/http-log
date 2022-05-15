package utils

import (
	"errors"
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

func SplitNetAddr(addr net.Addr) (host, port string) {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP.String(), strconv.Itoa(a.Port)
	default:
		panic(errors.New("unknown net.Addr type"))
	}
}
