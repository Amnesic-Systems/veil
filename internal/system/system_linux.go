package system

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"strings"
	"syscall"
	"unsafe"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/milosgajdos/tenus"
	"golang.org/x/sys/unix"

	"github.com/Amnesic-Systems/veil/internal/errs"
)

const (
	pathToRNG = "/sys/devices/virtual/misc/hw_random/rng_current"
	wantRNG   = "nsm-hwrng"
)

func SetResolver(resolver string) (err error) {
	defer errs.Wrap(&err, "failed to set DNS resolver")
	log.Printf("Setting DNS resolver to %s.", resolver)

	// A Nitro Enclave's /etc/resolv.conf is a symlink to
	// /run/resolvconf/resolv.conf.  As of 2022-11-21, the /run/ directory
	// exists but not its resolvconf/ subdirectory.
	dir := "/run/resolvconf/"
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	c := fmt.Sprintf("nameserver %s\n", resolver)
	return os.WriteFile(path.Join(dir, "resolv.conf"), []byte(c), 0644)
}

func SeedRandomness() (err error) {
	defer errs.Wrap(&err, "failed to seed entropy pool")
	log.Println("Seeding system entropy pool.")

	s, err := nsm.OpenDefaultSession()
	if err != nil {
		return err
	}
	defer func() { err = s.Close() }()

	fd, err := os.OpenFile("/dev/random", os.O_WRONLY, os.ModePerm)
	if err != nil {
		return err
	}
	defer func() { err = fd.Close() }()

	const seedLen = 2048
	var w int
	for total := 0; total < seedLen; {
		res, err := s.Send(&request.GetRandom{})
		if err != nil {
			return err
		}
		if res.GetRandom == nil {
			return errors.New("attribute GetRandom in NSM response is nil")
		}
		if len(res.GetRandom.Random) == 0 {
			return errors.New("got no random bytes from NSM")
		}

		// Write NSM-provided random bytes to the system's entropy pool to seed
		// it.
		if w, err = fd.Write(res.GetRandom.Random); err != nil {
			return err
		}
		total += w

		// Tell the system to update its entropy count.
		if _, _, errno := unix.Syscall(
			unix.SYS_IOCTL,
			uintptr(fd.Fd()),
			uintptr(unix.RNDADDTOENTCNT),
			uintptr(unsafe.Pointer(&w)),
		); errno != 0 {
			return errno
		}
	}
	return nil
}

// SetupLo sets up the loopback interface.
func SetupLo() (err error) {
	defer errs.Wrap(&err, "failed to configure loopback interface")
	log.Println("Setting up loopback interface.")

	link, err := tenus.NewLinkFrom("lo")
	if err != nil {
		return err
	}
	addr, network, err := net.ParseCIDR("127.0.0.1/8")
	if err != nil {
		return err
	}
	if err = link.SetLinkIp(addr, network); err != nil {
		return err
	}
	return link.SetLinkUp()
}

// HasSecureRNG checks if the enclave is configured to use the Nitro hardware
// RNG. This was suggested in:
// https://blog.trailofbits.com/2024/09/24/notes-on-aws-nitro-enclaves-attack-surface/
func HasSecureRNG() bool {
	log.Println("Checking if system uses desired RNG.")
	haveRNG, err := os.ReadFile(pathToRNG)
	if err != nil {
		log.Printf("Error reading %s: %v", pathToRNG, err)
		return false
	}
	log.Printf("Have RNG: %s", haveRNG)
	return strings.TrimSpace(string(haveRNG)) == wantRNG
}

// HasSecureKernelVersion checks if the system is running a kernel version that
// includes important security updates. This was suggested in:
// https://blog.trailofbits.com/2024/09/24/notes-on-aws-nitro-enclaves-attack-surface/
func HasSecureKernelVersion() bool {
	log.Println("Checking if system has desired kernel version.")
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		log.Printf("Error calling uname system call: %v", err)
		return false
	}
	return hasSecureKernelVersion(uname)
}

func hasSecureKernelVersion(uname syscall.Utsname) bool {
	// Store major, minor, and patch version in an array.
	var version [3]int
	var digit, offset int
	// Parse the kernel version, which is a character array of the form
	// "5.17.12".
	for _, char := range uname.Release {
		if '0' <= char && char <= '9' {
			digit = digit*10 + int(char-'0')
		} else {
			version[offset] = digit
			digit = 0
			offset++
			if offset >= len(version) {
				break
			}
		}
	}
	log.Printf("Have kernel version: %d.%d.%d", version[0], version[1], version[2])

	// We are looking for kernel version 5.17.12 or later.
	minVersion := [3]int{5, 17, 12}
	for i := range version {
		if version[i] < minVersion[i] {
			return false
		}
		if version[i] > minVersion[i] {
			return true
		}
	}
	return true
}
