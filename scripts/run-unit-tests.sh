#!/usr/bin/env bash

cd /app
# Needed for Go's build cache.
export HOME=/app
# Needed because otherwise we're getting:
# fork/exec /tmp/go-build1885828642/b001/cmd.test: permission denied
mkdir -p /app/tmp
export TMPDIR=/app/tmp

echo "Running Go unit tests..."
$(which go) test -cover ./...
