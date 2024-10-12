package httputil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"time"

	"github.com/Amnesic-Systems/veil/internal/errs"
	"github.com/Amnesic-Systems/veil/internal/nonce"
)

const (
	certOrg      = "Amnesic Systems"
	certValidity = time.Hour * 24 * 365 // One year.
)

var (
	errBadForm        = errors.New("failed to parse POST form data")
	errNoNonce        = errors.New("could not find nonce in URL query parameters")
	errBadNonceFormat = errors.New("unexpected nonce format; must be Base64 string")
)

// ExtractNonce extracts a nonce from the HTTP request's parameters, e.g.:
// https://example.com/endpoint?nonce=jtEcS7icZiwF5GMvmvnjuZ9xjcc%3D
func ExtractNonce(r *http.Request) (n *nonce.Nonce, err error) {
	defer errs.Wrap(&err, "failed to extract nonce from request")

	if err := r.ParseForm(); err != nil {
		return nil, errBadForm
	}

	strNonce := r.URL.Query().Get("nonce")
	if strNonce == "" {
		return nil, errNoNonce
	}

	// Decode Base64-encoded nonce.
	rawNonce, err := base64.StdEncoding.DecodeString(strNonce)
	if err != nil {
		return nil, errBadNonceFormat
	}

	n, err = nonce.FromSlice(rawNonce)
	if err != nil {
		return nil, err
	}
	return n, nil
}

// NewNoAuthHTTPClient returns an HTTP client that skips HTTPS certificate
// validation.  In the context of veil, this is fine because all we need is a
// confidential channel; not an authenticated channel.  Authentication is
// handled by the next layer, using attestation documents.
func NewNoAuthHTTPClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}
}

// CreateCertificate creates a self-signed certificate and returns the
// PEM-encoded certificate and key.  Some of the code below was taken from:
// https://eli.thegreenplace.net/2021/go-https-servers-with-tls/
func CreateCertificate(fqdn string) (cert []byte, key []byte, err error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{certOrg},
		},
		DNSNames:              []string{fqdn},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(certValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		return nil, nil, err
	}

	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if pemCert == nil {
		return nil, nil, errors.New("error encoding cert as PEM")
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if pemKey == nil {
		return nil, nil, errors.New("error encoding key as PEM")
	}

	return pemCert, pemKey, nil
}
