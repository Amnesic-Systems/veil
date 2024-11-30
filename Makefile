prog = veil
prog_dir = cmd/veil
verify_prog = veil-verify
verify_prog_dir = cmd/veil-verify
godeps = go.mod go.sum $(shell find cmd internal -name "*.go" -type f)

image_tag := $(prog)
image_tar := $(prog).tar
image_eif := $(prog).eif

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

$(image_tar): $(godeps) docker/Dockerfile-unit-test
	@echo "Building $(image_tar)..."
	@docker run --volume $(PWD):/workspace \
		gcr.io/kaniko-project/executor:v1.9.2 \
		--dockerfile docker/Dockerfile-unit-test \
		--reproducible \
		--no-push \
		--verbosity warn \
		--tarPath $(image_tar) \
		--destination $(image_tag) \
		--custom-platform linux/amd64

$(image_eif): $(image_tar)
	@echo "Building $(image_eif)..."
	@docker load --quiet --input $<
	@nitro-cli build-enclave \
		--docker-uri $(image_tag) \
		--output-file $(image_eif)

.PHONY: terminate
terminate:
	@nitro-cli terminate-enclave \
		--all

.PHONY: enclave
enclave: $(godeps) $(image_eif) $(terminate)
	@echo "Running enclave..."
	@nitro-cli run-enclave \
		--enclave-name veil \
		--eif-path $(image_eif) \
		--cpu-count 2 \
		--memory 3500

.PHONY: enclave-test
enclave-test: $(godeps) $(image_eif) $(terminate)
	@echo "Running enclave tests..."
	@nitro-cli run-enclave \
		--enclave-name veil-unit-tests \
		--eif-path $(image_eif) \
		--attach-console \
		--cpu-count 2 \
		--memory 3500

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
	@-sha1sum "$(prog_dir)/$(prog)"

$(verify_prog): $(godeps)
	@go build -C $(verify_prog_dir) -o $(verify_prog)
	@-sha1sum "$(verify_prog_dir)/$(verify_prog)"

.PHONY: clean
clean:
	rm -f $(prog_dir)/$(prog)
	rm -f $(verify_prog_dir)/$(verify_prog)
	rm -f $(cover_out) $(cover_html)
	rm -f $(image_tar) $(image_eif)
