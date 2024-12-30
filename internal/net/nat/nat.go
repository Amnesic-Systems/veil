// Package nat provides functions to enable and disable iptables forwarding
// rules for veil-proxy.
package nat

import (
	"github.com/coreos/go-iptables/iptables"

	"github.com/Amnesic-Systems/veil/internal/net/tun"
)

// Enable enables our iptables NAT rules, which connect the enclave to the
// Internet.
func Enable() error {
	return applyRules(true)
}

// Disable disables our iptables NAT rules.
func Disable() error {
	return applyRules(false)
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
