package proxy

import (
	"errors"
	"hash/fnv"

	"golang.org/x/net/ipv4"
)

const (
	// ControlStreamIndex is the VSOCK stream used for ICMP and other
	// non-flow traffic, plus future control messages.
	ControlStreamIndex = 0

	transportPortsLen = 4 // source port (2) + destination port (2)

	// IANA IP protocol numbers.
	protocolICMP = 1
	protocolTCP  = 6
	protocolUDP  = 17

	// flowKeyCap is the largest key we build: addrs + protocol + ports.
	flowKeyCap = 8 + 1 + transportPortsLen

	// nonIPv4FlowKeyLen is the fallback key size for non-IPv4 packets so they
	// still hash deterministically without reading past byte 0.
	nonIPv4FlowKeyLen = 1
)

var errNotIPv4 = errors.New("not an IPv4 packet")

// streamIndex selects a VSOCK stream for an IPv4 packet. streams is the total
// number of VSOCK connections: index 0 is the control stream; TCP and UDP
// flows hash across indices 1 through streams-1.
func streamIndex(packet []byte, streams int) int {
	if streams <= 1 {
		return ControlStreamIndex
	}
	if isControlPacket(packet) {
		return ControlStreamIndex
	}

	dataStreams := streams - 1
	h := fnv.New32a()
	_, _ = h.Write(flowKey(packet))
	return 1 + int(h.Sum32()%uint32(dataStreams))
}

// parseIPv4Header parses the IP layer of a TUN frame using ipv4.ParseHeader.
// Non-IPv4 versions (e.g. IPv6) are rejected even when the buffer is long enough
// to parse.
func parseIPv4Header(packet []byte) (*ipv4.Header, error) {
	hdr, err := ipv4.ParseHeader(packet)
	if err != nil {
		return nil, err
	}
	if hdr.Version != ipv4.Version {
		return nil, errNotIPv4
	}
	return hdr, nil
}

// isControlPacket reports whether a TUN frame should use the control stream
// rather than a hashed data stream. Only IPv4 TCP and UDP packets are routed
// to data streams; everything else (ICMP, truncated frames, IPv6, etc.) stays
// on the control stream.
func isControlPacket(packet []byte) bool {
	hdr, err := parseIPv4Header(packet)
	if err != nil {
		return true
	}

	switch hdr.Protocol {
	case protocolTCP, protocolUDP:
		return false
	default:
		return true
	}
}

// flowKey returns bytes that identify a connection for consistent hashing.
// For TCP/UDP the key is the IPv4 5-tuple: src/dst addresses, protocol, and
// src/dst ports. Other packets use a shorter key so they still hash stably but
// are unlikely to collide with real flows.
func flowKey(packet []byte) []byte {
	hdr, err := parseIPv4Header(packet)
	if err != nil {
		if errors.Is(err, errNotIPv4) {
			return packet[:nonIPv4FlowKeyLen]
		}
		return packet
	}

	src := hdr.Src.To4()
	dst := hdr.Dst.To4()
	if src == nil || dst == nil {
		return packet
	}

	proto := byte(hdr.Protocol)
	key := make([]byte, 0, flowKeyCap)
	key = append(key, src...)
	key = append(key, dst...)
	key = append(key, proto)

	switch hdr.Protocol {
	case protocolTCP, protocolUDP:
		// Transport header starts immediately after the IP header; first four
		// bytes are source and destination ports (big-endian).
		end := hdr.Len + transportPortsLen
		if len(packet) >= end {
			key = append(key, packet[hdr.Len:end]...)
		}
	}

	return key
}
