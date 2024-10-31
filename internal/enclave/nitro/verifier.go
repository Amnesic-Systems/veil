package nitro

// This file was taken from Stojan Dimitrovski's excellent nitrite package:
// https://github.com/hf/nitrite
// Veil contains a copy because we had to make some adjustments to the sanity
// checks to be compliant with the Nitro Enclave specification:
// https://docs.aws.amazon.com/pdfs/enclaves/latest/user/enclaves-user.pdf
//
// The file was originally licensed as follows:
// -----------------------------------------------------------------------------
// Copyright 2020 Stojan Dimitrovski
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is furnished to do
// so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"

	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/Amnesic-Systems/veil/internal/errs"
	"github.com/fxamacker/cbor/v2"
)

// Document represents the AWS Nitro Enclave attestation document as specified
// on page 70 of:
// https://docs.aws.amazon.com/pdfs/enclaves/latest/user/enclaves-user.pdf
type Document struct {
	ModuleID    string   `cbor:"module_id" json:"module_id"`
	Timestamp   uint64   `cbor:"timestamp" json:"timestamp"`
	Digest      string   `cbor:"digest" json:"digest"`
	PCRs        pcr      `cbor:"pcrs" json:"pcrs"`
	Certificate []byte   `cbor:"certificate" json:"certificate"`
	CABundle    [][]byte `cbor:"cabundle" json:"cabundle"`

	PublicKey []byte `cbor:"public_key" json:"public_key,omitempty"`
	UserData  []byte `cbor:"user_data" json:"user_data,omitempty"`
	Nonce     []byte `cbor:"nonce" json:"nonce,omitempty"`
}

// Result is a successful verification result of an attestation payload.
type Result struct {
	// Document contains the attestation document.
	Document *Document `json:"document,omitempty"`

	// Certificates contains all of the certificates except the root.
	Certificates []*x509.Certificate `json:"certificates,omitempty"`

	// Protected section from the COSE Sign1 payload.
	Protected []byte `json:"protected,omitempty"`
	// Unprotected section from the COSE Sign1 payload.
	Unprotected []byte `json:"unprotected,omitempty"`
	// Payload section from the COSE Sign1 payload.
	Payload []byte `json:"payload,omitempty"`
	// Signature section from the COSE Sign1 payload.
	Signature []byte `json:"signature,omitempty"`
	// COSESign1 contains the COSE Signature Structure which was used to
	// calculate the `Signature`.
	COSESign1 []byte `json:"cose_sign1,omitempty"`
}

// verifyOptions specifies the options for verifying the attestation payload.
// If `Roots` is nil, the `DefaultCARoot` is used. If `CurrentTime` is 0,
// `time.Now()` will be used. It is a strong recommendation you explicitly
// supply this value.
type verifyOptions struct {
	Roots       *x509.CertPool
	CurrentTime time.Time
}

type coseHeader struct {
	Alg interface{} `cbor:"1,keyasint,omitempty" json:"alg,omitempty"`
}

func (h *coseHeader) AlgorithmString() (string, bool) {
	switch h.Alg.(type) {
	case string:
		return h.Alg.(string), true
	}
	return "", false
}

func (h *coseHeader) AlgorithmInt() (int64, bool) {
	switch h.Alg.(type) {
	case int64:
		return h.Alg.(int64), true
	}
	return 0, false
}

type cosePayload struct {
	_ struct{} `cbor:",toarray"`

	Protected   []byte
	Unprotected cbor.RawMessage
	Payload     []byte
	Signature   []byte
}

type coseSignature struct {
	_ struct{} `cbor:",toarray"`

	Context     string
	Protected   []byte
	ExternalAAD []byte
	Payload     []byte
}

var defaultRoot *x509.CertPool = createAWSNitroRoot()

func createAWSNitroRoot() *x509.CertPool {
	// defaultCARoots contains the PEM encoded roots for verifying Nitro
	// Enclave attestation signatures. You can download them from
	// https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
	// It's recommended you calculate the SHA256 sum of this string and match
	// it to the one supplied in the AWS documentation
	// https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
	const defaultCARoots = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----`
	pool := x509.NewCertPool()

	ok := pool.AppendCertsFromPEM([]byte(defaultCARoots))
	if !ok {
		return nil
	}
	return pool
}

// verify verifies the attestation payload from `data` with the provided
// verification options. If the options specify `Roots` as `nil`, the
// `DefaultCARoot` will be used. If you do not specify `CurrentTime`,
// `time.Now()` will be used. It is strongly recommended you specifically
// supply the time.  If the returned error is non-nil, it is either one of the
// `Err` codes specified in this package, or is an error from the `crypto/x509`
// package. Revocation checks are NOT performed and you should check for
// revoked certificates by looking at the `Certificates` field in the `Result`.
// Result will be non-null if and only if either of these are true: certificate
// verification has passed, certificate verification has failed (expired, not
// trusted, etc.), signature is OK or signature is not OK. If either signature
// is not OK or certificate can't be verified, both Result and error will be
// set! You can use the SignatureOK field from the result to distinguish
// errors.
func verify(data []byte, options verifyOptions) (_ *Result, err error) {
	defer errs.Wrap(&err, "failed to verify attestation document")

	cose := cosePayload{}
	err = cbor.Unmarshal(data, &cose)
	if nil != err {
		return nil, errors.New("data is not a COSESign1 array")
	}

	if len(cose.Protected) == 0 {
		return nil, errors.New("COSESign1 protected section is nil or empty")
	}
	if len(cose.Payload) == 0 {
		return nil, errors.New("COSESign1 payload section is nil or empty")
	}
	if len(cose.Signature) == 0 {
		return nil, errors.New("COSESign1 signature section is nil or empty")
	}

	header := coseHeader{}
	err = cbor.Unmarshal(cose.Protected, &header)
	if nil != err {
		return nil, errors.New("COSESign1 protected section is not a COSESig1 header")
	}

	intAlg, ok := header.AlgorithmInt()

	// https://datatracker.ietf.org/doc/html/rfc8152#section-8.1
	if ok {
		switch intAlg {
		case -35:
			// do nothing -- OK
		default:
			return nil, errors.New("COSESign1 algorithm not ECDSA384")
		}
	} else {
		strAlg, ok := header.AlgorithmString()

		if ok {
			switch strAlg {
			case "ES384":
				// do nothing -- OK
			default:
				return nil, errors.New("COSESign1 algorithm not ECDSA384")
			}
		} else {
			return nil, errors.New("COSESign1 algorithm not ECDSA384")
		}
	}

	// Decode the attestation document.
	doc := Document{}
	err = cbor.Unmarshal(cose.Payload, &doc)
	if nil != err {
		return nil, err
	}

	// Perform sanity checks on the attestation document.
	if doc.ModuleID == "" ||
		doc.Digest == "" ||
		doc.Timestamp == 0 ||
		doc.PCRs == nil ||
		doc.Certificate == nil ||
		doc.CABundle == nil {
		return nil, errors.New("mandatory fields missing")
	}
	if doc.Digest != "SHA384" {
		return nil, errors.New("payload 'digest' is not SHA384")
	}
	if doc.Timestamp < 1 {
		return nil, errors.New("payload 'timestamp' is 0 or less")
	}
	if len(doc.PCRs) < 1 || len(doc.PCRs) > 32 {
		return nil, errors.New("payload 'pcrs' is less than 1 or more than 32")
	}
	for key, value := range doc.PCRs {
		if key > 31 {
			return nil, errors.New("payload 'pcrs' key index exceeds 31")
		}
		if value == nil || !slices.Contains([]int{32, 48, 64}, len(value)) {
			return nil, errors.New("payload 'pcrs' not of length {32,48,64}")
		}
	}
	if len(doc.CABundle) < 1 {
		return nil, errors.New("payload 'cabundle' has 0 elements")
	}
	for _, item := range doc.CABundle {
		if nil == item || len(item) < 1 || len(item) > 1024 {
			return nil, errors.New("payload 'cabundle' has a nil item or of length not in [1, 1024]")
		}
	}

	// Check that the length of the auxiliary fields doesn't exceed the maximum
	// according to the specification.
	if len(doc.PublicKey) > enclave.AuxFieldLen {
		return nil, errors.New("payload 'public_key' exceeds maximum length")
	}
	if len(doc.UserData) > enclave.AuxFieldLen {
		return nil, errors.New("payload 'user_data' exceeds maximum length")
	}
	if len(doc.Nonce) > enclave.AuxFieldLen {
		return nil, errors.New("payload 'nonce' exceeds maximum length")
	}

	// Parse the certificates that was used to sign the attestation document.
	certificates := make([]*x509.Certificate, 0, len(doc.CABundle)+1)
	cert, err := x509.ParseCertificate(doc.Certificate)
	if nil != err {
		return nil, err
	}

	// Perform sanity checks on public key and signature algorithm.
	if cert.PublicKeyAlgorithm != x509.ECDSA {
		return nil, errors.New("certificate public key algorithm is not ECDSA")
	}
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		return nil, errors.New("certificate signature algorithm is not ECDSAWithSHA384")
	}

	// Construct the issuing CA bundle.
	certificates = append(certificates, cert)
	intermediates := x509.NewCertPool()
	for _, item := range doc.CABundle {
		cert, err := x509.ParseCertificate(item)
		if nil != err {
			return nil, err
		}
		intermediates.AddCert(cert)
		certificates = append(certificates, cert)
	}

	// Set the hard-coded root certificate.
	roots := options.Roots
	if nil == roots {
		roots = defaultRoot
	}

	// Verify the hypervisor's issuing certificate.
	currentTime := options.CurrentTime
	if currentTime.IsZero() {
		currentTime = time.Now()
	}
	if _, err = cert.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
		CurrentTime:   currentTime,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageAny,
		},
	}); err != nil {
		return nil, err
	}

	sigStruct, err := cbor.Marshal(&coseSignature{
		Context:     "Signature1",
		Protected:   cose.Protected,
		ExternalAAD: []byte{},
		Payload:     cose.Payload,
	})
	if err != nil {
		return nil, err
	}

	sigOK, err := isValidECDSASignature(cert.PublicKey.(*ecdsa.PublicKey), sigStruct, cose.Signature)
	if err != nil {
		return nil, err
	}
	if !sigOK {
		return nil, errors.New("payload's signature does not match signature from certificate")
	}

	return &Result{
		Document:     &doc,
		Certificates: certificates,
		Protected:    cose.Protected,
		Unprotected:  cose.Unprotected,
		Payload:      cose.Payload,
		Signature:    cose.Signature,
		COSESign1:    sigStruct,
	}, err
}

func isValidECDSASignature(publicKey *ecdsa.PublicKey, sigStruct, signature []byte) (bool, error) {
	// https://datatracker.ietf.org/doc/html/rfc8152#section-8.1
	var hashSigStruct []byte

	switch publicKey.Curve.Params().Name {
	case "P-224":
		h := sha256.Sum224(sigStruct)
		hashSigStruct = h[:]

	case "P-256":
		h := sha256.Sum256(sigStruct)
		hashSigStruct = h[:]

	case "P-384":
		h := sha512.Sum384(sigStruct)
		hashSigStruct = h[:]

	case "P-512":
		h := sha512.Sum512(sigStruct)
		hashSigStruct = h[:]

	default:
		return false, fmt.Errorf("unknown ECDSA curve name %v", publicKey.Curve.Params().Name)
	}

	if len(signature) != 2*len(hashSigStruct) {
		return false, nil
	}

	r := big.NewInt(0)
	s := big.NewInt(0)

	r = r.SetBytes(signature[:len(hashSigStruct)])
	s = s.SetBytes(signature[len(hashSigStruct):])

	return ecdsa.Verify(publicKey, hashSigStruct, r, s), nil
}
