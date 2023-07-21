package main

import (
	"net"
	"time"

	"github.com/quic-go/quic-go/logging"

	"github.com/mt-inside/http-log/pkg/output"
	"github.com/mt-inside/http-log/pkg/state"
)

type myTracer struct {
	s     output.TtyStyler
	b     output.Bios
	d     *state.RequestData
	reqNo *uint64
}

func (t *myTracer) StartedConnection(local, remote net.Addr, srcConnID, destConnID logging.ConnectionID) {
	now := time.Now()
	t.d.TransportConnTime = &now // start and connection times are an even worse concept with lazy connections like this
	t.d.TransportConnNo = *t.reqNo + 1
	*t.reqNo = t.d.TransportConnNo

	t.d.TransportLocalAddress = local
	t.d.TransportRemoteAddress = remote

	t.b.TraceWithName("transport", "Accepting connection", "number", t.reqNo)
}

func (t *myTracer) NegotiatedVersion(chosen logging.VersionNumber, clientVersions, serverVersions []logging.VersionNumber) {
	t.d.TransportVersion = chosen // TODO print me
}
func (t *myTracer) ClosedConnection(err error) {
	t.b.TraceWithName("transport", "Connection closed", "reason", err)
}
func (t *myTracer) SentTransportParameters(*logging.TransportParameters) {
}
func (t *myTracer) ReceivedTransportParameters(*logging.TransportParameters) {
}
func (t *myTracer) RestoredTransportParameters(parameters *logging.TransportParameters) {
}
func (t *myTracer) SentLongHeaderPacket(hdr *logging.ExtendedHeader, size logging.ByteCount, ack *logging.AckFrame, frames []logging.Frame) {
}
func (t *myTracer) SentShortHeaderPacket(hdr *logging.ShortHeader, size logging.ByteCount, ack *logging.AckFrame, frames []logging.Frame) {
}
func (t *myTracer) ReceivedVersionNegotiationPacket(dest, src logging.ArbitraryLenConnectionID, _ []logging.VersionNumber) {
}
func (t *myTracer) ReceivedRetry(*logging.Header) {
}
func (t *myTracer) ReceivedLongHeaderPacket(hdr *logging.ExtendedHeader, size logging.ByteCount, frames []logging.Frame) {
}
func (t *myTracer) ReceivedShortHeaderPacket(hdr *logging.ShortHeader, size logging.ByteCount, frames []logging.Frame) {
}
func (t *myTracer) BufferedPacket(logging.PacketType, logging.ByteCount) {
}
func (t *myTracer) DroppedPacket(logging.PacketType, logging.ByteCount, logging.PacketDropReason) {
}
func (t *myTracer) UpdatedMetrics(rttStats *logging.RTTStats, cwnd, bytesInFlight logging.ByteCount, packetsInFlight int) {
}
func (t *myTracer) AcknowledgedPacket(logging.EncryptionLevel, logging.PacketNumber) {
}
func (t *myTracer) LostPacket(logging.EncryptionLevel, logging.PacketNumber, logging.PacketLossReason) {
}
func (t *myTracer) UpdatedCongestionState(logging.CongestionState) {
}
func (t *myTracer) UpdatedPTOCount(value uint32) {
}
func (t *myTracer) UpdatedKeyFromTLS(logging.EncryptionLevel, logging.Perspective) {
}
func (t *myTracer) UpdatedKey(generation logging.KeyPhase, remote bool) {
}
func (t *myTracer) DroppedEncryptionLevel(logging.EncryptionLevel) {
}
func (t *myTracer) DroppedKey(generation logging.KeyPhase) {
}
func (t *myTracer) SetLossTimer(logging.TimerType, logging.EncryptionLevel, time.Time) {
}
func (t *myTracer) LossTimerExpired(logging.TimerType, logging.EncryptionLevel) {
}
func (t *myTracer) LossTimerCanceled() {
}
func (t *myTracer) Close() {
	t.b.TraceWithName("transport", "Connection state change", "state", "closed")
}
func (t *myTracer) Debug(name, msg string) {
}
