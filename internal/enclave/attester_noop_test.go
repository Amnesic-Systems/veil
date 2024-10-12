package enclave

import (
	"reflect"
	"testing"

	"github.com/Amnesic-Systems/veil/internal/nonce"
)

// TODO: move
func assertEqual(t *testing.T, is, should interface{}) {
	t.Helper()
	if should != is {
		t.Fatalf("Expected value\n%v\nbut got\n%v", should, is)
	}
}

func TestSuccessfulVerification(t *testing.T) {
	var (
		a = NewNoopAttester()
		// // JSON objects are map[string]interface{} and numbers are float64.
		// origAux = map[string]any{
		// 	"Name": "John Doe",
		// 	"Age":  float64(42),
		// }
		origAux = &AuxInfo{
			PublicKey: [1024]byte{'a', 'b', 'c'},
			UserData:  [1024]byte{'d', 'e', 'f'},
			Nonce:     [1024]byte{'g', 'h', 'i'},
		}
	)

	attestation, err := a.Attest(origAux)
	assertEqual(t, err, nil)

	aux, err := a.Verify(attestation.Doc, &nonce.Nonce{})
	assertEqual(t, err, nil)
	assertEqual(t, reflect.DeepEqual(origAux, aux), true)
}

func TestFailedVerification(t *testing.T) {
	var a = NewNoopAttester()

	_, err := a.Verify([]byte(`"foo": "bar`), &nonce.Nonce{})
	assertEqual(t, err == nil, false)
}
