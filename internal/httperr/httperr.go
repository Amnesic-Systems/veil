package httperr

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

// Error is an application error message.
type Error struct {
	Msg string `json:"error"`
}

// New creates a new application layer error message.
func New(msg string) *Error {
	return &Error{Msg: msg}
}

// FromBody extracts the error message from an HTTP response body. The response
// body is not consumed and is still available for further reading.
func FromBody(resp *http.Response) string {
	var b bytes.Buffer
	resp.Body = io.NopCloser(io.TeeReader(resp.Body, &b))
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	resp.Body = io.NopCloser(&b)

	var e Error
	if err := json.Unmarshal(body, &e); err != nil {
		return ""
	}
	return e.Msg
}
