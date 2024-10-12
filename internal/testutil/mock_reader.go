package testutil

import "io"

var _ = io.Reader(&MockReader{})

type MockReader struct {
	failRead bool
	retOnly  int
}

type optFunc func(*MockReader)

func WithFailOnRead() optFunc {
	return func(m *MockReader) {
		m.failRead = true
	}
}

func WithShortRead(n int) optFunc {
	return func(m *MockReader) {
		m.retOnly = n
	}
}

func NewMockReader(opts ...optFunc) io.Reader {
	m := new(MockReader)
	for _, opt := range opts {
		opt(m)
	}
	return m
}

func (r *MockReader) Read(p []byte) (n int, err error) {
	if r.failRead {
		return 0, io.ErrUnexpectedEOF
	}
	if r.retOnly > 0 {
		return r.retOnly, nil
	}
	return len(p), nil
}
