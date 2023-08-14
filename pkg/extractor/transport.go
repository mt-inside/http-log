package extractor

import (
	"net"
	"time"

	"github.com/mt-inside/http-log/pkg/state"
)

func NetListener(l net.Listener, d *state.DaemonData) {
	d.TransportListenTime = time.Now()

	switch lis := l.(type) {
	case *net.TCPListener:
		d.TransportListenAddress = lis.Addr()
	default: // assume it's an (unexported) *tls.listener
		d.TransportListenAddress = l.Addr()
	}
}

func NetConn(c net.Conn, requestNo uint64, d *state.RequestData) {
	d.TransportConnTime = time.Now()
	d.TransportConnNo = requestNo
	d.TransportRemoteAddress = c.RemoteAddr()
	d.TransportLocalAddress = c.LocalAddr()
}
