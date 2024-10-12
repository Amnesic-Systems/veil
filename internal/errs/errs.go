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

func Wrap(err *error, str string, args ...any) {
	if *err != nil {
		*err = fmt.Errorf("%s: %w", fmt.Sprintf(str, args...), *err)
	}
}
