// Package nat provides functions to enable and disable host forwarding for
// veil-proxy.
package nat

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/coreos/go-iptables/iptables"

	"github.com/Amnesic-Systems/veil/internal/net/tun"
)

var (
	ipForwardPath    = "/proc/sys/net/ipv4/ip_forward"
	ipForwardMu      sync.Mutex
	restoreIPForward *string
)

// Enable enables IP forwarding and our iptables NAT rules, which connect the
// enclave to the Internet.
func Enable() error {
	if err := applyRules(true); err != nil {
		return err
	}
	if err := enableIPForwarding(); err != nil {
		return errors.Join(err, applyRules(false))
	}
	return nil
}

// Disable disables our iptables NAT rules and restores the prior IP forwarding
// state if Enable changed it.
func Disable() error {
	return errors.Join(applyRules(false), restorePriorIPForwarding())
}

func applyRules(toggle bool) error {
	t, err := iptables.New()
	if err != nil {
		return err
	}

	f := t.AppendUnique
	if !toggle {
		f = t.DeleteIfExists
	}

	var iptablesRules = [][]string{
		{"nat", "POSTROUTING", "-s", "10.0.0.0/24", "-j", "MASQUERADE"},
		{"filter", "FORWARD", "-i", tun.Name, "-s", "10.0.0.0/24", "-j", "ACCEPT"},
		{"filter", "FORWARD", "-o", tun.Name, "-d", "10.0.0.0/24", "-j", "ACCEPT"},
	}

	const table, chain, rulespec = 0, 1, 2
	for _, r := range iptablesRules {
		if err := f(r[table], r[chain], r[rulespec:]...); err != nil {
			return err
		}
	}

	return nil
}

func enableIPForwarding() error {
	ipForwardMu.Lock()
	defer ipForwardMu.Unlock()

	content, err := os.ReadFile(ipForwardPath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", ipForwardPath, err)
	}

	current := strings.TrimSpace(string(content))
	if current == "1" {
		return nil
	}

	if err := os.WriteFile(ipForwardPath, []byte("1\n"), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", ipForwardPath, err)
	}
	if restoreIPForward == nil {
		restoreIPForward = &current
	}
	return nil
}

func restorePriorIPForwarding() error {
	ipForwardMu.Lock()
	defer ipForwardMu.Unlock()

	if restoreIPForward == nil {
		return nil
	}

	if err := os.WriteFile(ipForwardPath, []byte(*restoreIPForward+"\n"), 0644); err != nil {
		return fmt.Errorf("failed to restore %s: %w", ipForwardPath, err)
	}
	restoreIPForward = nil
	return nil
}
