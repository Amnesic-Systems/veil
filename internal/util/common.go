package util

func AddrOf[T any](v T) *T {
	return &v
}

func PanicOnErr[T any](err error) {
	if err != nil {
		panic(err)
	}
}

func Must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
