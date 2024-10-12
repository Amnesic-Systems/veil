package system

import (
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHasSecureKernelVersion(t *testing.T) {
	cases := []struct {
		name  string
		uname syscall.Utsname
		want  bool
	}{
		{
			name: "kernel version is too low",
			uname: syscall.Utsname{
				Release: [65]int8{'5', '.', '1', '7', '.', '1', '1'},
			},
			want: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := hasSecureKernelVersion(c.uname)
			require.Equal(t, c.want, got)
		})
	}
}
