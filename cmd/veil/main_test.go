package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Amnesic-Systems/veil/internal/addr"
	"github.com/Amnesic-Systems/veil/internal/config"
	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/Amnesic-Systems/veil/internal/enclave/nitro"
	"github.com/Amnesic-Systems/veil/internal/enclave/noop"
	"github.com/Amnesic-Systems/veil/internal/httperr"
	"github.com/Amnesic-Systems/veil/internal/httpx"
	"github.com/Amnesic-Systems/veil/internal/nonce"
	"github.com/Amnesic-Systems/veil/internal/service"
	"github.com/Amnesic-Systems/veil/internal/service/attestation"
	"github.com/Amnesic-Systems/veil/internal/testutil"
	"github.com/Amnesic-Systems/veil/internal/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func withFlags(flag ...string) []string {
	var f []string
	if !nitro.IsEnclave() {
		f = append(f, "-insecure")
	}
	return append(f, flag...)
}

func startSvc(t *testing.T, cfg []string) (
	context.CancelFunc,
	*sync.WaitGroup,
) {
	var (
		ctx, cancel = context.WithCancel(context.Background())
		wg          = new(sync.WaitGroup)
	)

	wg.Add(1)
	go func(ctx context.Context, wg *sync.WaitGroup) {
		defer wg.Done()
		// run blocks until the context is cancelled.
		assert.NoError(t, run(ctx, os.Stderr, cfg))
		cancel()
	}(ctx, wg)

	// Block until the services are ready.
	deadline, cancelDl := context.WithDeadline(ctx, time.Now().Add(time.Second))
	defer cancelDl()
	if err := httpx.WaitForSvc(deadline, httpx.NewUnauthClient(), intSrv("/")); err != nil {
		t.Logf("error waiting for internal service: %v", err)
		return cancel, wg
	}
	if !slices.Contains(cfg, "-wait-for-app") {
		deadline, cancelDl := context.WithDeadline(ctx, time.Now().Add(time.Second))
		defer cancelDl()
		if err := httpx.WaitForSvc(deadline, httpx.NewUnauthClient(), extSrv("/")); err != nil {
			t.Logf("error waiting for external service: %v", err)
			return cancel, wg
		}
	}
	return cancel, wg
}

func waitForSvc(_ context.CancelFunc, wg *sync.WaitGroup) {
	wg.Wait()
}

func stopSvc(cancel context.CancelFunc, wg *sync.WaitGroup) {
	cancel()
	wg.Wait()
}

func intSrv(path string) string {
	return fmt.Sprintf("http://127.0.0.1:%d%s", defaultIntPort, path)
}

func extSrv(path string) string {
	return fmt.Sprintf("https://127.0.0.1:%d%s", defaultExtPort, path)
}

func errFromBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	var b bytes.Buffer
	resp.Body = io.NopCloser(io.TeeReader(resp.Body, &b))
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	resp.Body = io.NopCloser(&b)

	var e httperr.Error
	if err := json.Unmarshal(body, &e); err != nil {
		return ""
	}
	return "Response body: " + e.Msg
}

func TestBadConfig(t *testing.T) {
	require.Error(t, run(context.Background(), io.Discard, []string{
		// Provide an invalid port, which should cause the service to fail.
		"-ext-pub-port", "foo",
	}))
}

func TestHelp(t *testing.T) {
	require.ErrorIs(t,
		run(context.Background(), io.Discard, []string{
			"-help",
		}),
		flag.ErrHelp,
	)
}

func TestPages(t *testing.T) {
	defer stopSvc(startSvc(t, withFlags()))

	cases := []struct {
		name     string
		url      string
		wantBody string
	}{
		{
			name:     "index",
			url:      extSrv(service.PathIndex),
			wantBody: "AWS Nitro Enclave",
		},
		{
			name: "config",
			url: extSrv(service.PathConfig + "?nonce=" + url.QueryEscape(
				"hJkjpaP/6cVT+vikk06HcN0aOdU=",
			)),
			wantBody: `"Debug":false`,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, err := testutil.Client.Get(c.url)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode, errFromBody(t, resp))

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			defer resp.Body.Close()
			require.Contains(t, string(body), c.wantBody)
		})
	}
}

func TestEnclaveCodeURI(t *testing.T) {
	const codeURI = "https://example.com"
	defer stopSvc(startSvc(t, withFlags("-enclave-code-uri", codeURI)))

	resp, err := testutil.Client.Get(extSrv(service.PathIndex))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()

	body := util.Must(io.ReadAll(resp.Body))
	require.Contains(t, string(body), codeURI)
}

func TestReadyHandler(t *testing.T) {
	defer stopSvc(startSvc(t, withFlags("-wait-for-app")))

	cases := []struct {
		name     string
		url      string
		wantCode int
		wantErr  error
	}{
		{
			name:    "1st attempt public",
			url:     extSrv(service.PathIndex),
			wantErr: syscall.ECONNREFUSED,
		},
		{
			name:     "1st attempt ready",
			url:      intSrv(service.PathReady),
			wantCode: http.StatusOK,
			wantErr:  nil,
		},
		{
			name:     "2nd attempt ready",
			url:      intSrv(service.PathReady),
			wantCode: http.StatusGone,
			wantErr:  nil,
		},
		{
			name:     "2nd attempt public",
			url:      extSrv(service.PathIndex),
			wantCode: http.StatusOK,
			wantErr:  nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, err := testutil.Client.Get(c.url)
			if c.wantErr != nil {
				require.ErrorIs(t, err, c.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, c.wantCode, resp.StatusCode)
		})
	}
}

func TestAttestation(t *testing.T) {
	defer stopSvc(startSvc(t, withFlags()))

	var attester enclave.Attester = nitro.NewAttester()
	if !nitro.IsEnclave() {
		attester = noop.NewAttester()
	}

	cases := []struct {
		name     string
		url      string
		nonce    *nonce.Nonce
		wantCode int
	}{
		{
			name:     "missing nonce",
			url:      extSrv(service.PathAttestation),
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "valid attestation request",
			url:      extSrv(service.PathAttestation),
			nonce:    util.Must(nonce.New()),
			wantCode: http.StatusOK,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Make request and verify response code.
			if c.nonce != nil {
				c.url += "?nonce=" + c.nonce.URLEncode()
			}
			resp, err := testutil.Client.Get(c.url)
			require.NoError(t, err)
			if c.wantCode != http.StatusOK {
				require.Equal(t, c.wantCode, resp.StatusCode)
				return
			}

			// Parse attestation document.
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			defer resp.Body.Close()
			var a enclave.RawDocument
			require.NoError(t, json.Unmarshal(body, &a))

			// Verify the attestation document.  We expect no error but if the
			// test is run inside a Nitro Enclave, we will get ErrDebugMode.
			doc, err := attester.Verify(&a, c.nonce)
			if err != nil {
				require.ErrorIs(t, err, nitro.ErrDebugMode, errFromBody(t, resp))
			}

			// Ensure that the recovered nonce matches what we sent.
			n, err := attestation.GetNonce(&doc.AuxInfo)
			require.NoError(t, err)
			require.Equal(t, c.nonce, n)
		})
	}
}

func TestHashes(t *testing.T) {
	defer stopSvc(startSvc(t, withFlags()))

	var (
		hashes = new(attestation.Hashes)
		doPost = func(body io.Reader) (*http.Response, error) {
			return testutil.Client.Post(
				intSrv(service.PathHash),
				"application/json",
				body,
			)
		}
		doGet = func(_ io.Reader) (*http.Response, error) {
			return testutil.Client.Get(intSrv(service.PathHashes))
		}
	)
	hashes.SetAppHash(addr.Of(sha256.Sum256([]byte("foo"))))

	cases := []struct {
		name       string
		reqFunc    func(io.Reader) (*http.Response, error)
		toMarshal  any
		wantCode   int
		wantHashes *attestation.Hashes
	}{
		{
			name:       "get empty hashes",
			reqFunc:    doGet,
			wantCode:   http.StatusOK,
			wantHashes: new(attestation.Hashes),
		},
		{
			name:      "post application hash",
			reqFunc:   doPost,
			toMarshal: hashes,
			wantCode:  http.StatusOK,
		},
		{
			name:       "get populated hashes",
			reqFunc:    doGet,
			wantCode:   http.StatusOK,
			wantHashes: hashes,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Either POST or GET the hashes.
			reqBody, err := json.Marshal(c.toMarshal)
			require.NoError(t, err)
			resp, err := c.reqFunc(bytes.NewReader(reqBody))
			require.NoError(t, err)
			require.Equal(t, c.wantCode, resp.StatusCode)

			// Abort if we don't expect a response body.
			if c.wantHashes == nil {
				return
			}

			// Read the response body and extract the hashes.
			gotBody, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			defer resp.Body.Close()
			var gotHashes attestation.Hashes
			require.NoError(t, json.Unmarshal(gotBody, &gotHashes))

			// Make sure that the application hashes match.
			require.Equal(t, c.wantHashes.AppKeyHash, gotHashes.AppKeyHash)
			// Make sure that the TLS certificate hash is set.
			require.NotEmpty(t, *gotHashes.TlsKeyHash)
		})
	}
}

func TestReverseProxy(t *testing.T) {
	// Emulate the application's Web server.
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// If we get this code, we know that we hit the reverse proxy.
			w.WriteHeader(http.StatusTeapot)
		},
	))
	defer srv.Close()
	defer stopSvc(startSvc(t, withFlags("-app-web-srv", srv.URL)))

	cases := []struct {
		name     string
		path     string
		wantCode int
	}{
		{
			name:     "reverse proxy index",
			path:     "/",
			wantCode: http.StatusTeapot,
		},
		{
			name:     "reverse proxy document",
			path:     "/not-found",
			wantCode: http.StatusTeapot,
		},
		{
			name:     "another reverse proxy document",
			path:     "/enclave/not-found",
			wantCode: http.StatusTeapot,
		},
		{
			name:     "also not for reverse proxy",
			path:     service.PathIndex,
			wantCode: http.StatusOK,
		},
		{
			name:     "definitely not for reverse proxy",
			path:     service.PathAttestation,
			wantCode: http.StatusBadRequest,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, err := testutil.Client.Get(extSrv(c.path))
			require.NoError(t, err)
			require.Equal(t, c.wantCode, resp.StatusCode)
		})
	}
}

func TestRunApp(t *testing.T) {
	fd, err := os.CreateTemp("", "veil-test")
	require.NoError(t, err)
	defer os.Remove(fd.Name())

	cases := []struct {
		name    string
		command string
	}{
		{
			name: "curl",
			// Run curl to fetch veil's configuration from its external Web
			// server.
			command: fmt.Sprintf("curl --silent --insecure --output %s "+
				"https://localhost:%d"+service.PathConfig+"?nonce=%s",
				fd.Name(),
				defaultExtPort,
				util.Must(nonce.New()).URLEncode(),
			),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			waitForSvc(startSvc(t, withFlags("-app-cmd", c.command, "-insecure")))

			// Read curl's output, which should be our JSON-encoded
			// configuration file.
			content, err := io.ReadAll(fd)
			require.NoError(t, err)

			// Decode the configuration file and verify that the application
			// command is identical to what we just ran.
			var cfg config.Config
			require.NoError(t, json.Unmarshal(content, &cfg))
			require.Equal(t, c.command, cfg.AppCmd)
		})
	}
}
