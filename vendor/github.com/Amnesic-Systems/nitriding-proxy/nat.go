package proxy

import "github.com/coreos/go-iptables/iptables"

const (
	On  = true
	Off = false
)

// ToggleNAT toggles our iptables NAT rules, which ensure that the enclave can
// talk to the Internet.
func ToggleNAT(toggle bool) error {
	var iptablesRules = [][]string{
		{"nat", "POSTROUTING", "-s", "10.0.0.0/24", "-j", "MASQUERADE"},
		{"filter", "FORWARD", "-i", tunName, "-s", "10.0.0.0/24", "-j", "ACCEPT"},
		{"filter", "FORWARD", "-o", tunName, "-d", "10.0.0.0/24", "-j", "ACCEPT"},
	}

	t, err := iptables.New()
	if err != nil {
		return err
	}

	f := t.AppendUnique
	if toggle == Off {
		f = t.DeleteIfExists
	}

	const table, chain, rulespec = 0, 1, 2
	for _, r := range iptablesRules {
		if err := f(r[table], r[chain], r[rulespec:]...); err != nil {
			return err
		}
	}

	return nil
}
