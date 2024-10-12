package httperr

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	const msg = "foo"

	e := New(msg)
	require.Equal(t, e.Msg, msg)
}

func TestFromBody(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantBody string
	}{
		{
			name:     "empty body",
			body:     "",
			wantBody: "",
		},
		{
			name:     "invalid JSON",
			body:     "foo",
			wantBody: "",
		},
		{
			name:     "valid JSON",
			body:     `{"error":"foo"}`,
			wantBody: "foo",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := &http.Response{
				Body: io.NopCloser(strings.NewReader(c.body)),
			}
			require.Equal(t, c.wantBody, FromBody(resp))
			// Read the body again, to ensure it wasn't consumed.
			require.Equal(t, c.wantBody, FromBody(resp))
		})
	}
}
