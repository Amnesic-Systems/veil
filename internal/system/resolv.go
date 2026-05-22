package system

import (
	"fmt"
	"strings"
)

func renderResolvConf(resolver string, searchDomains []string, ndots *int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "nameserver %s\n", resolver)
	if len(searchDomains) > 0 {
		fmt.Fprintf(&b, "search %s\n", strings.Join(searchDomains, " "))
	}
	if ndots != nil {
		fmt.Fprintf(&b, "options ndots:%d\n", *ndots)
	}
	return b.String()
}
