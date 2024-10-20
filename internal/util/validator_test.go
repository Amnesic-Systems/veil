package util

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSpringErrs(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		errs map[string]string
		want string
	}{
		{
			name: "nil",
			errs: nil,
		},
		{
			name: "empty",
			errs: map[string]string{},
		},
		{
			name: "one error",
			errs: map[string]string{
				"foo": "bar",
			},
			want: "foo: bar\n",
		},
		{
			name: "sorted errors",
			errs: map[string]string{
				"a": "foo",
				"b": "bar",
				"c": "baz",
				"d": "qux",
			},
			want: "a: foo\nb: bar\nc: baz\nd: qux\n",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, SprintErrs(c.errs))
		})
	}
}
