package tunnel

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

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
	minBackoff       = time.Second
	maxBackoff       = time.Second * 10
	DefaultVSOCKPort = 1024
)

type VsockTunneler struct {
	backoff time.Duration
}

func NewVSOCK() *VsockTunneler {
	return &VsockTunneler{
		backoff: minBackoff,
	}
}

func (v *VsockTunneler) Start(
	ctx context.Context,
	wg *sync.WaitGroup,
	port uint32,
) {
	defer wg.Done()

	go func() {
		var err error
		for {
			if err = setupTunnel(ctx, &v.backoff, port); err != nil {
				log.Printf("Error: %v", err)
			}
			time.Sleep(v.backoff)
			v.backoff = v.backoff * 2
			if v.backoff > maxBackoff {
				v.backoff = maxBackoff
			}
		}
	}()
}

// setupTunnel establishes a tunnel between the enclave and the parent EC2 and
// forward traffic between the two.  The function blocks until the tunnel is
// torn down.
func setupTunnel(
	ctx context.Context,
	backoff *time.Duration,
	port uint32,
) (err error) {
	defer errs.Wrap(&err, "tunnel failed")
	var (
		wg    sync.WaitGroup
		errCh = make(chan error, 1)
	)

	// Establish TCP-over-VSOCK connection with veil-proxy.
	conn, err := vsock.Dial(proxyCID, port, nil)
	if err != nil {
		return fmt.Errorf("failed to connect to veil-proxy: %w", err)
	}
	defer conn.Close()
	log.Println("Established TCP connection with veil-proxy.")

	// Create and configure the tun device.
	tun, err := tun.SetupTunAsEnclave()
	if err != nil {
		return fmt.Errorf("failed to set up tun device: %w", err)
	}
	defer tun.Close()
	log.Println("Set up tun device.")

	// Spawn goroutines that forward traffic and wait for them to finish.
	wg.Add(2)
	defer wg.Wait()
	go proxy.VSOCKToTun(conn, tun, errCh, &wg)
	go proxy.TunToVSOCK(tun, conn, errCh, &wg)
	log.Println("Started goroutines to forward traffic.")

	// Reset the backoff interval.
	*backoff = minBackoff

	select {
	// Return the first error that occurs.
	case err := <-errCh:
		return err
	case <-ctx.Done():
		_, _ = conn.Close(), tun.Close()
		return nil
	}
}
