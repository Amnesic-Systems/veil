// Package addr implements helper functions for dealing with pointers.
package addr

// Of returns a pointer to the given value.
func Of[T any](v T) *T {
	return &v
}
