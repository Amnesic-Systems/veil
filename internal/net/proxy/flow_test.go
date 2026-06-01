package proxy

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStreamIndexSingleStream(t *testing.T) {
	require.Equal(t, ControlStreamIndex, streamIndex([]byte{1, 2, 3}, 1))
}

func TestStreamIndexICMPUsesControlStream(t *testing.T) {
	pkt := icmpPacket(t, net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.1"))
	require.Equal(t, ControlStreamIndex, streamIndex(pkt, 8))
}

func TestStreamIndexNonTCPUDPUsesControlStream(t *testing.T) {
	pkt := ipPacket(t, net.ParseIP("10.0.0.2"), net.ParseIP("1.1.1.1"), 47)
	require.Equal(t, ControlStreamIndex, streamIndex(pkt, 8))
}

func TestStreamIndexTCPUsesDataStream(t *testing.T) {
	pkt := tcpPacket(t, net.ParseIP("10.0.0.2"), net.ParseIP("1.1.1.1"), 1234, 443)
	require.GreaterOrEqual(t, streamIndex(pkt, 8), 1)
}

func TestStreamIndexStableForSameFlow(t *testing.T) {
	pkt := tcpPacket(t, net.ParseIP("10.0.0.2"), net.ParseIP("1.1.1.1"), 1234, 443)

	first := streamIndex(pkt, 8)
	for range 10 {
		require.Equal(t, first, streamIndex(pkt, 8))
	}
}

func TestStreamIndexSpreadsDifferentFlows(t *testing.T) {
	streams := 16
	seen := make(map[int]struct{}, streams)

	for sport := 1024; sport < 1024+streams*4; sport++ {
		pkt := tcpPacket(
			t,
			net.ParseIP("10.0.0.2"),
			net.ParseIP("93.184.216.34"),
			uint16(sport),
			443,
		)
		idx := streamIndex(pkt, streams)
		require.GreaterOrEqual(t, idx, 1)
		seen[idx] = struct{}{}
	}

	require.Greater(t, len(seen), 1)
}

func ipPacket(t *testing.T, src, dst net.IP, proto byte) []byte {
	t.Helper()

	src4 := src.To4()
	dst4 := dst.To4()
	require.NotNil(t, src4)
	require.NotNil(t, dst4)

	pkt := make([]byte, 20)
	pkt[0] = 0x45
	pkt[9] = proto
	copy(pkt[12:16], src4)
	copy(pkt[16:20], dst4)
	return pkt
}

func icmpPacket(t *testing.T, src, dst net.IP) []byte {
	t.Helper()
	return ipPacket(t, src, dst, protocolICMP)
}

func tcpPacket(
	t *testing.T,
	src, dst net.IP,
	srcPort, dstPort uint16,
) []byte {
	t.Helper()

	pkt := make([]byte, 40)
	pkt[0] = 0x45
	pkt[9] = protocolTCP
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	return pkt
}
