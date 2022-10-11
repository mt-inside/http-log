package codec

import (
	"net"
	"os"
)

func Hostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	return hostname
}

func DefaultIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return "unknown"
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP.String()
}
