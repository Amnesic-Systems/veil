package testutil

import (
	"crypto/tls"
	"net/http"
	"time"
)

var Client = &http.Client{
	Timeout: 3 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	},
}
