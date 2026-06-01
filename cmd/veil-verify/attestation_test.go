package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Amnesic-Systems/veil/internal/config"
	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/Amnesic-Systems/veil/internal/errs"
	"github.com/Amnesic-Systems/veil/internal/httpx"
	"github.com/Amnesic-Systems/veil/internal/nonce"
	"github.com/Amnesic-Systems/veil/internal/service"
	"github.com/Amnesic-Systems/veil/internal/service/attestation"
	"github.com/stretchr/testify/require"
)

func testPCRs() enclave.PCR {
	return enclave.PCR{
		0: []byte(strings.Repeat("a", 48)),
		1: []byte(strings.Repeat("b", 48)),
		2: []byte(strings.Repeat("c", 48)),
	}
}

func newAttestationServer(
	t *testing.T,
	mutate func(*enclave.Document),
) *httptest.Server {
	t.Helper()

	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != service.PathAttestation {
			http.NotFound(w, r)
			return
		}
		n, err := httpx.ExtractNonce(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		certHash := sha256.Sum256(srv.Certificate().Raw)
		doc := &enclave.Document{
			PCRs: testPCRs(),
			AuxInfo: enclave.AuxInfo{
				PublicKey: (&attestation.Hashes{TlsKeyHash: &certHash}).Serialize(),
				Nonce:     n.ToSlice(),
			},
		}
		if mutate != nil {
			mutate(doc)
		}

		docBytes, err := json.Marshal(doc)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		rawDoc := enclave.RawDocument{
			Type: enclave.TypeNoop,
			Doc:  docBytes,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(&rawDoc); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	return srv
}

func TestBuildReq(t *testing.T) {
	n := new(nonce.Nonce)
	req, err := buildReq(t.Context(), "https://example.com/", n)
	require.NoError(t, err)

	u := req.URL
	require.Equal(t, http.MethodGet, req.Method)
	require.Equal(t, "https", u.Scheme)
	require.Equal(t, "example.com", u.Host)
	require.Equal(t, service.PathAttestation, u.Path)
	require.Equal(t, n.B64(), u.Query().Get(httpx.ParamNonce))
}

func TestAttestEnclave(t *testing.T) {
	cases := []struct {
		name      string
		newServer func(*testing.T) *httptest.Server
		localPCRs enclave.PCR
		wantErr   error
	}{
		{
			name: "valid",
			newServer: func(t *testing.T) *httptest.Server {
				return newAttestationServer(t, nil)
			},
			localPCRs: testPCRs(),
		},
		{
			name: "pcr mismatch",
			newServer: func(t *testing.T) *httptest.Server {
				return newAttestationServer(t, nil)
			},
			localPCRs: enclave.PCR{0: []byte(strings.Repeat("z", 48))},
			wantErr:   errs.ErrPCRMismatch,
		},
		{
			name: "tls binding mismatch",
			newServer: func(t *testing.T) *httptest.Server {
				return newAttestationServer(t, func(doc *enclave.Document) {
					otherHash := sha256.Sum256([]byte("other certificate"))
					doc.PublicKey = (&attestation.Hashes{TlsKeyHash: &otherHash}).Serialize()
				})
			},
			localPCRs: testPCRs(),
			wantErr:   errs.ErrBindingMismatch,
		},
		{
			name: "missing tls binding",
			newServer: func(t *testing.T) *httptest.Server {
				return newAttestationServer(t, func(doc *enclave.Document) {
					doc.PublicKey = nil
				})
			},
			localPCRs: testPCRs(),
			wantErr:   errs.ErrIsNil,
		},
		{
			name: "nonce mismatch",
			newServer: func(t *testing.T) *httptest.Server {
				return newAttestationServer(t, func(doc *enclave.Document) {
					doc.Nonce = make([]byte, nonce.Len)
					doc.Nonce[0] = 1
				})
			},
			localPCRs: testPCRs(),
			wantErr:   errs.ErrNonceMismatch,
		},
		{
			name: "http error",
			newServer: func(t *testing.T) *httptest.Server {
				return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Error(w, "nope", http.StatusInternalServerError)
				}))
			},
			localPCRs: testPCRs(),
			wantErr:   errs.ErrEnclaveErr,
		},
		{
			name: "wrong attestation type",
			newServer: func(t *testing.T) *httptest.Server {
				return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					n, err := httpx.ExtractNonce(r)
					if err != nil {
						http.Error(w, err.Error(), http.StatusBadRequest)
						return
					}
					docBytes, err := json.Marshal(&enclave.Document{AuxInfo: enclave.AuxInfo{
						Nonce: n.ToSlice(),
					}})
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					rawDoc := enclave.RawDocument{Type: enclave.TypeNitro, Doc: docBytes}
					if err := json.NewEncoder(w).Encode(&rawDoc); err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
					}
				}))
			},
			localPCRs: testPCRs(),
			wantErr:   errs.ErrTypeMismatch,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := c.newServer(t)
			defer srv.Close()

			cfg := &config.VeilVerify{Addr: srv.URL, Testing: true}
			err := attestEnclave(t.Context(), cfg, c.localPCRs)
			require.ErrorIs(t, err, c.wantErr)
		})
	}
}

func TestAttestEnclaveCanceledContext(t *testing.T) {
	srv := newAttestationServer(t, nil)
	defer srv.Close()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	cfg := &config.VeilVerify{Addr: srv.URL, Testing: true}
	err := attestEnclave(ctx, cfg, testPCRs())
	require.ErrorIs(t, err, context.Canceled)
}

func TestToPCR(t *testing.T) {
	cases := []struct {
		name     string
		in       []byte
		wantPCRs enclave.PCR
		wantErr  bool
	}{
		{
			name:    "invalid json",
			in:      []byte("invalid"),
			wantErr: true,
		},
		{
			name: "invalid hash",
			in: []byte(`{
				"Measurements": {
					"HashAlgorithm": "Sha512 { ... }",
					"PCR0": "616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161",
					"PCR1": "626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262",
					"PCR2": "636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363"
				}
			}`),
			wantErr: true,
		},
		{
			name: "invalid PCR value",
			in: []byte(`{
				"Measurements": {
					"HashAlgorithm": "Sha512 { ... }",
					"PCR0": "foobar",
				}
			}`),
			wantErr: true,
		},
		{
			name: "valid",
			in:   []byte(validPCRs),
			wantPCRs: enclave.PCR{
				0: []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
				1: []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
				2: []byte("cccccccccccccccccccccccccccccccccccccccccccccccc"),
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotPCRs, err := toPCR(c.in)
			require.Equal(t, c.wantErr, err != nil)
			require.True(t, gotPCRs.Equal(c.wantPCRs))
		})
	}
}

func TestVerifyTLSBinding(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte("cert")}
	certHash := sha256.Sum256(cert.Raw)
	otherHash := sha256.Sum256([]byte("other cert"))

	cases := []struct {
		name    string
		resp    *http.Response
		doc     *enclave.Document
		wantErr bool
	}{
		{
			name: "valid",
			resp: &http.Response{TLS: &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{cert},
			}},
			doc: &enclave.Document{AuxInfo: enclave.AuxInfo{
				PublicKey: (&attestation.Hashes{TlsKeyHash: &certHash}).Serialize(),
			}},
		},
		{
			name: "mismatched certificate",
			resp: &http.Response{TLS: &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{cert},
			}},
			doc: &enclave.Document{AuxInfo: enclave.AuxInfo{
				PublicKey: (&attestation.Hashes{TlsKeyHash: &otherHash}).Serialize(),
			}},
			wantErr: true,
		},
		{
			name: "missing tls state",
			resp: &http.Response{},
			doc: &enclave.Document{AuxInfo: enclave.AuxInfo{
				PublicKey: (&attestation.Hashes{TlsKeyHash: &certHash}).Serialize(),
			}},
			wantErr: true,
		},
		{
			name: "missing attested hash",
			resp: &http.Response{TLS: &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{cert},
			}},
			doc:     &enclave.Document{},
			wantErr: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := verifyTLSBinding(c.resp, c.doc)
			require.Equal(t, c.wantErr, err != nil)
		})
	}
}
