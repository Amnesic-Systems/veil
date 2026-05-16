package tunnel

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/Amnesic-Systems/veil/internal/backoff"
	"github.com/Amnesic-Systems/veil/internal/errs"
	"github.com/Amnesic-Systems/veil/internal/net/proxy"
	"github.com/Amnesic-Systems/veil/internal/net/tun"
	"github.com/mdlayher/vsock"
)

const (
	// proxyCID determines the CID (analogous to an IP address) of the parent
	// EC2 instance. According to AWS docs, it is always 3:
	// https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html
	proxyCID         = 3
	DefaultVSOCKPort = 1024
)

type VsockTunneler struct {
	timer *backoff.Timer
}

func NewVSOCK() *VsockTunneler {
	return &VsockTunneler{
		timer: backoff.NewTimer(),
	}
}

func (v *VsockTunneler) Start(
	ctx context.Context,
	port uint32,
) error {
	readyCh := make(chan struct{})
	var ready sync.Once

	go func() {
		defer ready.Do(func() { close(readyCh) })

		var err error
		for {
			if ctx.Err() != nil {
				return
			}

			if err = setupTunnel(ctx, v.timer, port, func() {
				ready.Do(func() { close(readyCh) })
			}); err != nil {
				log.Printf("Error: %v", err)
			}
			v.timer.Sleep(ctx)
		}
	}()

	select {
	case <-readyCh:
		return ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}

// setupTunnel establishes a tunnel between the enclave and the parent EC2 and
// forward traffic between the two.  The function blocks until the tunnel is
// torn down.
func setupTunnel(
	ctx context.Context,
	timer *backoff.Timer,
	port uint32,
	ready func(),
) (err error) {
	defer errs.Wrap(&err, "tunnel failed")
	var (
		wg    sync.WaitGroup
		errCh = make(chan error, 2)
	)

	// Establish TCP-over-VSOCK connection with veil-proxy.
	conn, err := vsock.Dial(proxyCID, port, nil)
	if err != nil {
		return fmt.Errorf("failed to connect to veil-proxy: %w", err)
	}
	defer func() { _ = conn.Close() }()
	log.Println("Established TCP connection with veil-proxy.")

	// Create and configure the tun device.
	tun, err := tun.SetupTunAsEnclave()
	if err != nil {
		return fmt.Errorf("failed to set up tun device: %w", err)
	}
	defer func() { _ = tun.Close() }()
	log.Println("Set up tun device.")

	// Spawn goroutines that forward traffic and wait for them to finish.
	wg.Add(2)
	defer wg.Wait()
	go proxy.VSOCKToTun(conn, tun, errCh, &wg)
	go proxy.TunToVSOCK(tun, conn, errCh, &wg)
	log.Println("Started goroutines to forward traffic.")
	ready()

	// Reset the backoff interval.
	timer.Reset()

	select {
	// Return the first error that occurs.
	case err := <-errCh:
		return err
	case <-ctx.Done():
		_, _ = conn.Close(), tun.Close()
		return nil
	}
}
