package util

import "context"

func SprintErrs(errs map[string]string) string {
	var s string
	for field, problem := range errs {
		s += field + ": " + problem + "\n"
	}
	return s
}

type Validator interface {
	Validate(context.Context) map[string]string
}
