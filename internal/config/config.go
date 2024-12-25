// Package config contains the structs representing the configuration of our
// command line tools.
package config

import (
	"github.com/Amnesic-Systems/veil/internal/types/validate"
)

// Check that all configuration types satisfy the `Validator` interface.
var (
	_ = validate.Validator(&Veil{})
	_ = validate.Validator(&VeilProxy{})
	_ = validate.Validator(&VeilVerify{})
)
