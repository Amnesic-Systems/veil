package testutil

import (
	"net/http"
	"time"
)

var Client = &http.Client{
	Timeout: 3 * time.Second,
}
