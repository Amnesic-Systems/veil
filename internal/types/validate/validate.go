// Package validate provides a typo and functions to validate input like command
// line configuration or client-submitted JSON objects.
package validate

import (
	"errors"
	"fmt"
	"slices"
)

func SprintErrs(errs map[string]string) string {
	var s string

	// Sort the error keys.
	errKeys := []string{}
	for key := range errs {
		errKeys = append(errKeys, key)
	}
	slices.Sort(errKeys)

	for _, key := range errKeys {
		s += key + ": " + errs[key] + "\n"
	}

	return s
}

// Objects validates `v` and returns an error if there are validation errors. If
// there is more than one validation error, the function joins the errors using
// `errors.Join`.
func Object(v Validator) error {
	var err error
	if problems := v.Validate(); len(problems) > 0 {
		for field, problem := range problems {
			err = errors.Join(err, fmt.Errorf("field %s: %v", field, problem))
		}
		return err
	}
	return nil
}

type Validator interface {
	Validate() map[string]string
}
