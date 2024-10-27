package nonce

import (
	"io"
	"testing"

	"github.com/Amnesic-Systems/veil/internal/errs"
	"github.com/Amnesic-Systems/veil/internal/testutil"
	"github.com/stretchr/testify/assert"
)

func TestFromSlice(t *testing.T) {
	validSlice := make([]byte, Len)
	validSlice[0] = 1

	cases := []struct {
		name    string
		in      []byte
		want    Nonce
		wantErr error
	}{
		{
			name:    "too short",
			in:      []byte{},
			wantErr: errs.InvalidLength,
		},
		{
			name: "too long",
			in:   append(validSlice, 0),
			want: Nonce{1},
		},
		{
			name:    "valid",
			in:      validSlice,
			want:    Nonce{1},
			wantErr: nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := FromSlice(c.in)
			if c.wantErr != nil {
				assert.ErrorIs(t, err, c.wantErr)
				return
			}
			assert.Equal(t, c.want, *got)
		})
	}
}

func TestNewNonce(t *testing.T) {
	origReader := cryptoRead
	defer func() { cryptoRead = origReader }()

	cases := []struct {
		name    string
		reader  io.Reader
		wantErr error
	}{
		{
			name:    "valid",
			reader:  cryptoRead,
			wantErr: nil,
		},
		{
			name:    "read error",
			reader:  testutil.NewMockReader(testutil.WithFailOnRead()),
			wantErr: errNotEnoughRead,
		},
		{
			name:    "short read",
			reader:  testutil.NewMockReader(testutil.WithShortRead(5)),
			wantErr: errNotEnoughRead,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cryptoRead = c.reader
			_, err := New()
			assert.Equal(t, c.wantErr, err)
		})
	}
}

func TestURLEncode(t *testing.T) {
	cases := []struct {
		name string
		in   Nonce
		want string
	}{
		{
			name: "all zeroes",
			in:   Nonce{},
			want: `AAAAAAAAAAAAAAAAAAAAAAAAAAA%3D`,
		},
		{
			name: "contains slash",
			in:   Nonce{0xff},
			want: `%2FwAAAAAAAAAAAAAAAAAAAAAAAAA%3D`,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, c.in.URLEncode())
		})
	}
}
