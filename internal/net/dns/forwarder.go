package dns

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	defaultDNSPort = "53"
	maxDNSPacket   = 65535
	maxUDPQueries  = 128
	queryTimeout   = 2 * time.Second
)

// Config contains DNS forwarding configuration.
type Config struct {
	// ListenAddr is the enclave-facing address, e.g., 10.0.0.1:53.
	ListenAddr string

	// Upstreams contains host-facing DNS resolvers, e.g., 127.0.0.53:53.
	Upstreams []string
}

// Forwarder forwards DNS queries from an enclave-facing listener to one or
// more host-facing upstream resolvers.
type Forwarder struct {
	udp       net.PacketConn
	tcp       net.Listener
	upstreams []string
	sem       chan struct{}
	once      sync.Once
}

// Start starts a DNS forwarder and returns after the UDP and TCP listeners are
// ready.
func Start(ctx context.Context, cfg Config) (_ *Forwarder, err error) {
	if cfg.ListenAddr == "" {
		return nil, errors.New("listen address is empty")
	}
	upstreams := normalizeUpstreams(cfg.Upstreams)
	if len(upstreams) == 0 {
		return nil, errors.New("no upstream DNS resolvers configured")
	}

	udp, err := net.ListenPacket("udp", cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen for UDP DNS: %w", err)
	}
	defer func() {
		if err != nil {
			_ = udp.Close()
		}
	}()

	tcp, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen for TCP DNS: %w", err)
	}

	f := &Forwarder{
		udp:       udp,
		tcp:       tcp,
		upstreams: upstreams,
		sem:       make(chan struct{}, maxUDPQueries),
	}
	go func() {
		<-ctx.Done()
		_ = f.Close()
	}()
	go f.serveUDP(ctx)
	go f.serveTCP(ctx)

	return f, nil
}

// UDPAddr returns the forwarder's UDP listener address.
func (f *Forwarder) UDPAddr() net.Addr {
	return f.udp.LocalAddr()
}

// TCPAddr returns the forwarder's TCP listener address.
func (f *Forwarder) TCPAddr() net.Addr {
	return f.tcp.Addr()
}

// Close stops the forwarder.
func (f *Forwarder) Close() error {
	var err error
	f.once.Do(func() {
		err = errors.Join(f.udp.Close(), f.tcp.Close())
	})
	return err
}

// UpstreamsFromFile extracts nameserver entries from a resolv.conf file.
func UpstreamsFromFile(path string) ([]string, error) {
	fd, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = fd.Close() }()
	return UpstreamsFromReader(fd)
}

// UpstreamsFromReader extracts nameserver entries from resolv.conf content.
func UpstreamsFromReader(r io.Reader) ([]string, error) {
	var (
		s        = bufio.NewScanner(r)
		seen     = make(map[string]bool)
		upstream []string
	)
	for s.Scan() {
		line := stripComment(s.Text())
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		addr := withDefaultPort(fields[1])
		if !seen[addr] {
			upstream = append(upstream, addr)
			seen[addr] = true
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(upstream) == 0 {
		return nil, errors.New("resolv.conf contains no nameserver entries")
	}
	return upstream, nil
}

func stripComment(line string) string {
	// 'man 5 resolv.conf' says:
	// Lines that contain a semicolon (;) or hash character (#) in the first
	// column are treated as comments.
	for _, marker := range []string{"#", ";"} {
		if before, _, ok := strings.Cut(line, marker); ok {
			line = before
		}
	}
	return line
}

func withDefaultPort(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, defaultDNSPort)
}

func normalizeUpstreams(upstreams []string) []string {
	var normalized []string
	for _, upstream := range upstreams {
		upstream = strings.TrimSpace(upstream)
		if upstream != "" {
			normalized = append(normalized, withDefaultPort(upstream))
		}
	}
	return normalized
}

func (f *Forwarder) serveUDP(ctx context.Context) {
	for {
		buf := make([]byte, maxDNSPacket)
		n, client, err := f.udp.ReadFrom(buf)
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				log.Printf("Error reading UDP DNS query: %v", err)
			}
			return
		}

		select {
		case f.sem <- struct{}{}:
		default:
			log.Print("Dropping UDP DNS query because the forwarder is saturated.")
			continue
		}

		query := append([]byte(nil), buf[:n]...)
		go func() {
			defer func() { <-f.sem }()
			f.forwardUDP(ctx, client, query)
		}()
	}
}

func (f *Forwarder) forwardUDP(ctx context.Context, client net.Addr, query []byte) {
	for _, upstream := range f.upstreams {
		dialer := net.Dialer{Timeout: queryTimeout}
		conn, err := dialer.DialContext(ctx, "udp", upstream)
		if err != nil {
			log.Printf("Error dialing UDP DNS upstream %s: %v", upstream, err)
			continue
		}

		if err := conn.SetDeadline(time.Now().Add(queryTimeout)); err != nil {
			_ = conn.Close()
			log.Printf("Error setting UDP DNS deadline: %v", err)
			continue
		}
		if _, err = conn.Write(query); err != nil {
			_ = conn.Close()
			log.Printf("Error writing UDP DNS query to %s: %v", upstream, err)
			continue
		}

		resp := make([]byte, maxDNSPacket)
		n, err := conn.Read(resp)
		_ = conn.Close()
		if err != nil {
			log.Printf("Error reading UDP DNS response from %s: %v", upstream, err)
			continue
		}
		if _, err = f.udp.WriteTo(resp[:n], client); err != nil {
			log.Printf("Error writing UDP DNS response to enclave: %v", err)
		}
		return
	}
}

func (f *Forwarder) serveTCP(ctx context.Context) {
	for {
		client, err := f.tcp.Accept()
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				log.Printf("Error accepting TCP DNS connection: %v", err)
			}
			return
		}
		go f.forwardTCP(ctx, client)
	}
}

func (f *Forwarder) forwardTCP(ctx context.Context, client net.Conn) {
	defer func() { _ = client.Close() }()

	for {
		query, err := readTCPDNSMessage(client)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				log.Printf("Error reading TCP DNS query: %v", err)
			}
			return
		}

		resp, err := f.exchangeTCP(ctx, query)
		if err != nil {
			log.Printf("Error forwarding TCP DNS query: %v", err)
			return
		}
		if _, err = client.Write(resp); err != nil {
			log.Printf("Error writing TCP DNS response to enclave: %v", err)
			return
		}
	}
}

func (f *Forwarder) exchangeTCP(ctx context.Context, query []byte) ([]byte, error) {
	var lastErr error
	for _, upstream := range f.upstreams {
		dialer := net.Dialer{Timeout: queryTimeout}
		server, err := dialer.DialContext(ctx, "tcp", upstream)
		if err != nil {
			lastErr = fmt.Errorf("failed to dial %s: %w", upstream, err)
			continue
		}

		if err := server.SetDeadline(time.Now().Add(queryTimeout)); err != nil {
			_ = server.Close()
			lastErr = fmt.Errorf("failed to set deadline for %s: %w", upstream, err)
			continue
		}
		if _, err = server.Write(query); err != nil {
			_ = server.Close()
			lastErr = fmt.Errorf("failed to write query to %s: %w", upstream, err)
			continue
		}
		resp, err := readTCPDNSMessage(server)
		_ = server.Close()
		if err != nil {
			lastErr = fmt.Errorf("failed to read response from %s: %w", upstream, err)
			continue
		}
		return resp, nil
	}
	return nil, lastErr
}

func readTCPDNSMessage(r io.Reader) ([]byte, error) {
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}

	msgLen := binary.BigEndian.Uint16(lenBuf)
	msg := make([]byte, int(msgLen)+len(lenBuf))
	copy(msg, lenBuf)
	_, err := io.ReadFull(r, msg[len(lenBuf):])
	return msg, err
}
