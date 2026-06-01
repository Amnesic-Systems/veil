package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"github.com/Amnesic-Systems/veil/internal/net/tun"
)

const lenBufSize = 2

// TunToVSOCK forwards network packets from the tun device to our
// TCP-over-VSOCK connection. The function keeps on forwarding packets until we
// encounter an error or EOF. Errors (including EOF) are written to the given
// channel.
func TunToVSOCK(
	from io.ReadCloser,
	to io.WriteCloser,
	ch chan error,
	wg *sync.WaitGroup,
) {
	TunToVSOCKStreams(from, []io.WriteCloser{to}, ch, wg)
}

// TunToVSOCKStreams forwards packets from tun to parallel VSOCK streams.
// Flows are hashed to a stream so unrelated traffic avoids head-of-line
// blocking on a single byte pipe.
func TunToVSOCKStreams(
	from io.ReadCloser,
	to []io.WriteCloser,
	ch chan error,
	wg *sync.WaitGroup,
) {
	defer func() {
		for _, w := range to {
			_ = w.Close()
		}
	}()
	defer wg.Done()
	var (
		err     error
		streams = len(to)
		sendBuf = make([]byte, lenBufSize+tun.MTU)
		pktBuf  = sendBuf[lenBufSize:]
	)

	for {
		// Read a network packet from the tun interface.
		nr, rerr := from.Read(pktBuf)
		if nr > 0 {
			// Forward the network packet to our TCP-over-VSOCK connection.
			binary.BigEndian.PutUint16(sendBuf, uint16(nr))
			idx := streamIndex(pktBuf[:nr], streams)
			if _, werr := to[idx].Write(sendBuf[:lenBufSize+nr]); werr != nil {
				err = werr
				break
			}
		}
		if rerr != nil {
			err = rerr
			break
		}
	}
	ch <- fmt.Errorf("stopped tun-to-vsock forwarding: %w", err)
}

// VSOCKToTun forwards network packets from our TCP-over-VSOCK connection to
// the tun interface. The function keeps on forwarding packets until we
// encounter an error or EOF. Errors (including EOF) are written to the given
// channel.
func VSOCKToTun(
	from io.ReadCloser,
	to io.WriteCloser,
	ch chan error,
	wg *sync.WaitGroup,
) {
	defer func() { _ = to.Close() }()
	defer wg.Done()
	var (
		err       error
		pktLen    uint16
		pktLenBuf = make([]byte, lenBufSize)
		pktBuf    = make([]byte, tun.MTU)
	)

	for {
		// Read the length prefix that tells us the size of the subsequent
		// packet.
		if _, err = io.ReadFull(from, pktLenBuf); err != nil {
			break
		}
		pktLen = binary.BigEndian.Uint16(pktLenBuf)

		// Read the packet.
		if _, err = io.ReadFull(from, pktBuf[:pktLen]); err != nil {
			break
		}

		// Forward the packet to the tun interface.
		if _, err = to.Write(pktBuf[:pktLen]); err != nil {
			break
		}
	}
	ch <- fmt.Errorf("stopped vsock-to-tun forwarding: %w", err)
}
