// Package errs provides convenience functions for error handling.
package errs

import (
	"errors"
	"fmt"
)

var (
	InvalidFormat = errors.New("invalid format")
	InvalidLength = errors.New("invalid length")
	IsNil         = errors.New("argument must not be nil")
)

// Wrap wraps the given error using the given string and (if provided) string
// arguments. The function replaces the given error with the new error.
func Wrap(err *error, str string, args ...any) {
	if *err != nil {
		*err = fmt.Errorf("%s: %w", fmt.Sprintf(str, args...), *err)
	}
}

// WrapErr works like `Wrap` but takes as input a second error instead of a
// string.
func WrapErr(err *error, new error) {
	if *err != nil {
		*err = fmt.Errorf("%w: %w", new, *err)
	}
}

// Add works like `Wrap` but returns the new error instead.
func Add(err error, str string, args ...any) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", fmt.Sprintf(str, args...), err)
}

// Join joins the two given errors using `errors.Join`. The only difference to
// `errors.Join` is that this function takes as input an error pointer, which
// allows us to omit re-assignment.
func Join(origErr *error, new error) {
	if origErr == nil {
		return
	}
	*origErr = errors.Join(*origErr, new)
}
