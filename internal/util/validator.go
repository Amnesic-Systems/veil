package util

import (
	"context"
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

type Validator interface {
	Validate(context.Context) map[string]string
}
