package proxy

import (
	"fmt"
	"net"
	"os"
	"unsafe"

	"github.com/milosgajdos/tenus"
	"golang.org/x/sys/unix"
)

const (
	asEnclave = iota
	asProxy
)

type ifReq struct {
	Name  [0x10]byte
	Flags uint16
	pad   [0x28 - 0x10 - 2]byte
}

// SetupTunAsProxy sets up a tun interface and returns a ready-to-use file
// descriptor.
func SetupTunAsProxy() (*os.File, error) {
	return setupTun(asProxy)
}

// SetupTunAsEnclave sets up a tun interface and returns a ready-to-use file
// descriptor.
func SetupTunAsEnclave() (*os.File, error) {
	return setupTun(asEnclave)
}

// setupTun creates and configures a tun interface. The given typ must be
// asEnclave or asProxy.
func setupTun(typ int) (*os.File, error) {
	fd, err := createTun()
	if err != nil {
		return nil, err
	}
	if err := configureTun(typ); err != nil {
		return nil, err
	}

	return fd, nil
}

// createTun returns a ready-to-use file descriptor for our tun interface.
func createTun() (*os.File, error) {
	const tunPath = "/dev/net/tun"
	tunfd, err := unix.Open(tunPath, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	ifr := ifReq{
		Flags: unix.IFF_TUN | unix.IFF_NO_PI,
	}
	copy(ifr.Name[:], tunName)

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(tunfd),
		uintptr(unix.TUNSETIFF),
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		return nil, errno
	}
	unix.SetNonblock(tunfd, true)

	return os.NewFile(uintptr(tunfd), tunPath), nil
}

// configureTun configures our tun device. The function assigns an IP address,
// sets the link MTU, and may set the default gateway, after which the device
// is ready for use.
func configureTun(typ int) error {
	cidrStr := "10.0.0.1/24"
	if typ == asEnclave {
		cidrStr = "10.0.0.2/24"
	}

	link, err := tenus.NewLinkFrom(tunName)
	if err != nil {
		return fmt.Errorf("failed to retrieve link: %w", err)
	}
	cidr, network, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return fmt.Errorf("failed to parse CIDR: %w", err)
	}
	if err = link.SetLinkIp(cidr, network); err != nil {
		return fmt.Errorf("failed to set link address: %w", err)
	}
	if err := link.SetLinkMTU(tunMTU); err != nil {
		return fmt.Errorf("failed to set link MTU: %w", err)
	}
	// Set the enclave's default gateway to the proxy's IP address.
	if typ == asEnclave {
		gw := net.ParseIP("10.0.0.1")
		if err := link.SetLinkDefaultGw(&gw); err != nil {
			return fmt.Errorf("failed to set default gateway: %w", err)
		}
	}
	if err := link.SetLinkUp(); err != nil {
		return fmt.Errorf("failed to bring up link: %w", err)
	}

	return nil
}
