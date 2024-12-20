// Package must provides functions to perform an action or panic.
package must

// Get returns the value of v if err is nil and panics otherwise.
func Get[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
