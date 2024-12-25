veil            = cmd/veil/veil
veil_dir        = cmd/veil
veil_verify     = cmd/veil-verify/veil-verify
veil_verify_dir = cmd/veil-verify
veil_proxy      = cmd/veil-proxy/veil-proxy
veil_proxy_dir  = cmd/veil-proxy
godeps          = go.mod go.sum \
                  $(shell find cmd internal -name "*.go" -type f)

image_tag        = veil
image_dockerfile = docker/Dockerfile
image_tar       := $(image_tag).tar
image_eif       := $(image_tag).eif

cover_out = cover.out
cover_html = cover.html

all: $(veil) $(veil_verify) $(veil_proxy)

.PHONY: lint
lint: $(godeps)
	go vet ./...
	govulncheck ./...
	golangci-lint run ./...

.PHONY: test
test: $(godeps)
	go test -race -cover ./...

$(image_tar): $(godeps) $(image_dockerfile)
	@echo "Building $(image_tar)..."
	@docker run --volume $(PWD):/workspace \
		gcr.io/kaniko-project/executor:v1.9.2 \
		--dockerfile $(image_dockerfile) \
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

$(veil): $(godeps)
	@CGO_ENABLED=0 go build \
		-C $(veil_dir) \
		-trimpath \
		-ldflags="-s -w" \
		-buildvcs=false
	@-sha1sum "$(veil)"

$(veil_verify): $(godeps)
	@go build -C $(veil_verify_dir)
	@-sha1sum "$(veil_verify)"

$(veil_proxy): $(godeps)
	@go build -C $(veil_proxy_dir)
	@-sha1sum "$(veil_proxy)"

.PHONY: clean
clean:
	@rm -f $(veil) $(veil_verify) $(veil_proxy)
	@rm -f $(cover_out) $(cover_html)
	@rm -f $(image_tar) $(image_eif)
