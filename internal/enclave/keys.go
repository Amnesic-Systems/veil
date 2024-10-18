package enclave

import (
	"bytes"
	"context"
	"sync"
)

// Keys holds key material for veil itself (the HTTPS certificate) and for the
// enclave application (whatever the application wants to "store" in veil).
// These keys are meant to be managed by a leader enclave and -- if horizontal
// scaling is required -- synced to worker enclaves.  The struct implements
// getters and setters that allow for thread-safe setting and getting of
// members.
type Keys struct {
	sync.Mutex
	VeilKey  []byte `json:"veil_key"`
	VeilCert []byte `json:"veil_cert"`
	AppKeys  []byte `json:"app_keys"`
}

// Validate implements the Validator interface for Keys.
func (k *Keys) Validate(_ context.Context) map[string]string {
	k.Lock()
	defer k.Unlock()

	errs := make(map[string]string)
	if len(k.VeilKey) == 0 {
		errs["veil_key"] = "veil key is uninitialized"
	}
	if len(k.VeilCert) == 0 {
		errs["veil_cert"] = "veil cert is uninitialized"
	}
	if len(k.AppKeys) == 0 {
		errs["app_keys"] = "app keys are uninitialized"
	}
	return errs
}

func (our *Keys) Equal(their *Keys) bool {
	our.Lock()
	their.Lock()
	defer our.Unlock()
	defer their.Unlock()

	return bytes.Equal(our.VeilCert, their.VeilCert) &&
		bytes.Equal(our.VeilKey, their.VeilKey) &&
		bytes.Equal(our.AppKeys, their.AppKeys)
}

func (k *Keys) SetAppKeys(appKeys []byte) {
	k.Lock()
	defer k.Unlock()

	k.AppKeys = appKeys
}

func (k *Keys) SetVeilKeys(key, cert []byte) {
	k.Lock()
	defer k.Unlock()

	k.VeilKey = key
	k.VeilCert = cert
}

func (k *Keys) Set(newKeys *Keys) {
	k.SetAppKeys(newKeys.AppKeys)
	k.SetVeilKeys(newKeys.VeilKey, newKeys.VeilCert)
}
