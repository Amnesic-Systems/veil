package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/Amnesic-Systems/veil/internal/httperr"
	"github.com/Amnesic-Systems/veil/internal/nonce"
	"github.com/Amnesic-Systems/veil/internal/service/attestation"
	"github.com/Amnesic-Systems/veil/internal/testutil"
	"github.com/Amnesic-Systems/veil/internal/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func waitForSvc(t *testing.T, url string) error {
	var (
		start    = time.Now()
		retry    = time.NewTicker(5 * time.Millisecond)
		deadline = time.Second
	)

	for range retry.C {
		if _, err := testutil.Client.Get(url); err == nil {
			return nil
		}
		if time.Since(start) > deadline {
			t.Logf("Web server %s still unavailable after %v.", url, deadline)
			return errors.New("timeout")
		}
	}

	return nil
}

func startSvc(t *testing.T, cfg []string) func() {
	var (
		ctx, cancelCtx = context.WithCancel(context.Background())
		wg             = new(sync.WaitGroup)
		f              = func() {
			cancelCtx()
			wg.Wait()
		}
	)

	wg.Add(1)
	go func(ctx context.Context, wg *sync.WaitGroup) {
		defer wg.Done()
		// run blocks until the context is cancelled.
		assert.NoError(t, run(ctx, os.Stderr, cfg))
	}(ctx, wg)

	// Block until the services are ready.
	if err := waitForSvc(t, intSrv("/")); err != nil {
		t.Logf("error waiting for service: %v", err)
		return f
	}
	if !slices.Contains(cfg, "-wait-for-app") {
		if err := waitForSvc(t, extSrv("/")); err != nil {
			t.Logf("error waiting for service: %v", err)
			return f
		}
	}

	// Return function that shuts down the service.
	return f
}

func stopSvc(stop func()) {
	stop()
}

func intSrv(path string) string {
	return fmt.Sprintf("http://127.0.0.1:%s%s", defaultIntPort, path)
}

func extSrv(path string) string {
	return fmt.Sprintf("https://127.0.0.1:%s%s", defaultExtPubPort, path)
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
	defer stopSvc(startSvc(t, []string{"-insecure"}))

	cases := []struct {
		name     string
		url      string
		wantBody string
	}{
		{
			name:     "index",
			url:      extSrv("/enclave"),
			wantBody: "AWS Nitro Enclave",
		},
		{
			name: "config",
			url: extSrv("/enclave/config?nonce=" + url.QueryEscape(
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

func TestReadyHandler(t *testing.T) {
	defer stopSvc(startSvc(t, []string{"-insecure", "-wait-for-app"}))

	cases := []struct {
		name     string
		url      string
		wantCode int
		wantErr  error
	}{
		{
			name:    "1st attempt public",
			url:     extSrv("/enclave"),
			wantErr: syscall.ECONNREFUSED,
		},
		{
			name:     "1st attempt ready",
			url:      intSrv("/enclave/ready"),
			wantCode: http.StatusOK,
			wantErr:  nil,
		},
		{
			name:     "2nd attempt ready",
			url:      intSrv("/enclave/ready"),
			wantCode: http.StatusGone,
			wantErr:  nil,
		},
		{
			name:     "2nd attempt public",
			url:      extSrv("/enclave"),
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
	defer stopSvc(startSvc(t, []string{"-insecure"}))

	cases := []struct {
		name     string
		url      string
		nonce    *nonce.Nonce
		wantCode int
	}{
		{
			name:     "missing nonce",
			url:      extSrv("/enclave/attestation"),
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "valid attestation request",
			url:      extSrv("/enclave/attestation"),
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
			var a enclave.AttestationDoc
			require.NoError(t, json.Unmarshal(body, &a))

			// "Verify" the attestation document using our noop attester.
			aux, err := enclave.NewNoopAttester().Verify(a.Doc, c.nonce)
			require.NoError(t, err, errFromBody(t, resp))

			// Ensure that the recovered nonce matches what we sent.
			_, n, err := attestation.AuxFromServer(aux)
			require.NoError(t, err)
			require.Equal(t, c.nonce, n)
		})
	}
}

func TestHashes(t *testing.T) {
	defer stopSvc(startSvc(t, []string{"-insecure"}))

	var (
		hashes = new(attestation.Hashes)
		doPost = func(body io.Reader) (*http.Response, error) {
			return testutil.Client.Post(
				intSrv("/enclave/hash"),
				"application/json",
				body,
			)
		}
		doGet = func() (*http.Response, error) {
			return testutil.Client.Get(intSrv("/enclave/hashes"))
		}
	)
	hashes.SetAppHash(util.AddrOf([sha256.Size]byte{1}))

	cases := []struct {
		name       string
		method     string
		toMarshal  any
		wantCode   int
		wantHashes *attestation.Hashes
	}{
		{
			name:       "get empty hashes",
			method:     http.MethodGet,
			wantCode:   http.StatusOK,
			wantHashes: new(attestation.Hashes),
		},
		{
			name:      "post application hash",
			method:    http.MethodPost,
			toMarshal: hashes,
			wantCode:  http.StatusOK,
		},
		{
			name:       "get populated hashes",
			method:     http.MethodGet,
			wantCode:   http.StatusOK,
			wantHashes: hashes,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var b []byte
			var resp *http.Response
			var err error
			if c.method == http.MethodGet {
				resp, err = doGet()
			} else {
				b, err = json.Marshal(c.toMarshal)
				require.NoError(t, err)
				resp, err = doPost(bytes.NewReader(b))
			}
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
			wantBody, err := json.Marshal(c.wantHashes)
			require.NoError(t, err)

			require.Equal(t,
				strings.TrimSpace(string(wantBody)),
				strings.TrimSpace(string(gotBody)),
			)
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
	defer stopSvc(startSvc(t, []string{"-insecure", "-app-web-srv", srv.URL}))

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
			path:     "/enclave",
			wantCode: http.StatusOK,
		},
		{
			name:     "definitely not for reverse proxy",
			path:     "/enclave/attestation",
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
