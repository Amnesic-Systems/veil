package util

func AddrOf[T any](v T) *T {
	return &v
}

func Must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
