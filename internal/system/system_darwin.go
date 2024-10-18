package system

func HasSecureRNG() bool           { return true }
func HasSecureKernelVersion() bool { return true }
func SetupLo() error               { return nil }
func SeedRandomness() (err error)  { return nil }
