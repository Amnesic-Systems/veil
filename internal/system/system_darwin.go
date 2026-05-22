package system

func SetResolver(_ string, _ []string, _ *int) error { return nil }
func HasSecureRNG() bool                             { return true }
func HasSecureKernelVersion() bool                   { return true }
func SetupLo() error                                 { return nil }
func SeedRandomness() error                          { return nil }
