package system

import (
	"log"
	"os"
)

const (
	pathToRNG = "/sys/devices/virtual/misc/hw_random/rng_current"
	wantRNG   = "nsm-hwrng"
)

// HasSecureRNG checks if the enclave is configured to use the Nitro hardware
// RNG. This was suggested in:
// https://blog.trailofbits.com/2024/09/24/notes-on-aws-nitro-enclaves-attack-surface/
func HasSecureRNG() bool {
	haveRNG, err := os.ReadFile(pathToRNG)
	if err != nil {
		log.Printf("Error reading %s: %v", pathToRNG, err)
		return false
	}
	log.Printf("Have RNG: %s", haveRNG)
	return string(haveRNG) == wantRNG
}
