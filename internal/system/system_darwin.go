package system

func SetResolver(_ string) error   { return nil }
func HasSecureRNG() bool           { return true }
func HasSecureKernelVersion() bool { return true }
func SetupLo() error               { return nil }
func SeedRandomness() error        { return nil }
