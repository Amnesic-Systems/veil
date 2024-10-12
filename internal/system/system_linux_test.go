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
			name: "patch version too low",
			uname: syscall.Utsname{
				Release: [65]int8{'5', '.', '1', '7', '.', '1', '1'},
			},
			want: false,
		},
		{
			name: "minor version too low",
			uname: syscall.Utsname{
				Release: [65]int8{'5', '.', '1', '6', '.', '1', '2'},
			},
			want: false,
		},
		{
			name: "major version too low",
			uname: syscall.Utsname{
				Release: [65]int8{'4', '.', '1', '7', '.', '1', '2'},
			},
			want: false,
		},
		{
			name: "version matches minimum",
			uname: syscall.Utsname{
				Release: [65]int8{'5', '.', '1', '7', '.', '1', '2'},
			},
			want: true,
		},
		{
			name: "major version high",
			uname: syscall.Utsname{
				Release: [65]int8{'6', '.', '1', '7', '.', '1', '2'},
			},
			want: true,
		},
		{
			name: "minor version high",
			uname: syscall.Utsname{
				Release: [65]int8{'5', '.', '1', '8', '.', '1', '2'},
			},
			want: true,
		},
		{
			name: "patch version high",
			uname: syscall.Utsname{
				Release: [65]int8{'5', '.', '1', '7', '.', '1', '3'},
			},
			want: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := hasSecureKernelVersion(c.uname)
			require.Equal(t, c.want, got)
		})
	}
}
