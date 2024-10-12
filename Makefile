prog = veil
prog_dir = cmd
godeps = go.mod go.sum $(shell find cmd internal -name "*.go" -type f)

cover_out = cover.out
cover_html = cover.html

all: $(prog)

.PHONY: lint
lint: $(godeps)
	go vet ./...
	govulncheck ./...
	golangci-lint run ./...

.PHONY: test
test: $(godeps)
	go test -race -cover ./...

.PHONY: coverage
coverage: $(cover_html)
	open $(cover_html)

$(cover_out): $(godeps)
	go test -coverprofile=$(cover_out) ./...

$(cover_html): $(cover_out)
	go tool cover -html=$(cover_out) -o $(cover_html)

$(prog): $(godeps)
	@CGO_ENABLED=0 go build \
		-C $(prog_dir) \
		-trimpath \
		-ldflags="-s -w" \
		-buildvcs=false \
		-o $(prog)
	@echo "$(prog_dir)/$(prog)"

.PHONY: clean
clean:
	rm -f $(prog_dir)/$(prog)
	rm -f $(cover_out)
	rm -f $(cover_html)
