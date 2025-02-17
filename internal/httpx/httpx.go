// Package httpx implements utility functions related to HTTP.
package httpx

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/Amnesic-Systems/veil/internal/errs"
	"github.com/Amnesic-Systems/veil/internal/nonce"
)

const (
	certOrg      = "Amnesic Systems"
	certValidity = time.Hour * 24 * 365 // One year.
	ParamNonce   = "nonce"
)

var (
	errBadForm          = errors.New("failed to parse POST form data")
	errNoNonce          = errors.New("could not find nonce in URL query parameters")
	errBadNonceFormat   = errors.New("unexpected nonce format; must be Base64 string")
	errDeadlineExceeded = errors.New("deadline exceeded")
)

// ExtractNonce extracts a nonce from the HTTP request's parameters, e.g.:
// https://example.com/endpoint?nonce=jtEcS7icZiwF5GMvmvnjuZ9xjcc%3D
func ExtractNonce(r *http.Request) (n *nonce.Nonce, err error) {
	defer errs.Wrap(&err, "failed to extract nonce from request")

	if err := r.ParseForm(); err != nil {
		return nil, errBadForm
	}

	strNonce := r.URL.Query().Get(ParamNonce)
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

// NewUnauthClient returns an HTTP client that skips HTTPS certificate
// validation.  In the context of veil, this is fine because all we need is a
// confidential channel; not an authenticated channel.  Authentication is
// handled by the next layer, using attestation documents.
func NewUnauthClient() *http.Client {
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

// WaitForSvc waits for the service (specified by the URL) to become available
// by making repeated HTTP GET requests using the given HTTP client.  This
// function blocks until 1) the service responds with an HTTP response or 2) the
// given context expires.
func WaitForSvc(
	ctx context.Context,
	client *http.Client,
	url string,
) (err error) {
	defer errs.Wrap(&err, "failed to wait for service")

	start := time.Now()
	deadline, ok := ctx.Deadline()
	if !ok {
		return errors.New("context has no deadline")
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req = req.WithContext(ctx)

	for {
		log.Print("Making request to service...")
		if _, err := client.Do(req); err == nil {
			log.Print("Service is ready.")
			return nil
		}
		if time.Since(start) > deadline.Sub(start) {
			return errDeadlineExceeded
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// GetCertHash returns the SHA-256 fingerprint of the given certificate.
// Notably, the fingerprint is the same as the one displayed by browsers when
// clicking on the "Details" button of a site's certificate.
func GetCertHash(rawCert []byte) (hash [sha256.Size]byte, err error) {
	defer errs.Wrap(&err, "failed to get fingerprint")

	// Decode the PEM certificate. We expect a single PEM block of type
	// "CERTIFICATE".
	block, rest := pem.Decode(rawCert)
	if block == nil {
		return hash, errors.New("no PEM data found")
	}
	if len(rest) > 0 {
		return hash, errors.New("unexpected extra PEM data")
	}
	if block.Type != "CERTIFICATE" {
		return hash, fmt.Errorf("expected type CERTIFICATE but got %s", block.Type)
	}

	// Parse the certificate and hash its raw bytes.
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return hash, err
	}
	return sha256.Sum256(cert.Raw), nil
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
