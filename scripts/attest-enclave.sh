#!/usr/bin/env bash

set -e

if [ $# -ne 2 ]
then
    echo "Usage: $0 /path/to/enclave/app/ https://enclave-app.com" >&2
    exit 1
fi
repository="$1"
enclave="$2"
docker_image="enclave-app:latest"

# Build the reproducible enclave app Docker image.
echo "[+] Building reproducible enclave app image." >&2
(cd "$repository" && make)

# The following Dockerfile is used to build the enclave image, which requires
# the nitro-cli tool.
dockerfile=Dockerfile
cat > "$dockerfile" <<EOF
FROM public.ecr.aws/amazonlinux/amazonlinux:2023

# See:
# https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install.html#install-cli
RUN dnf install aws-nitro-enclaves-cli -y
RUN dnf install aws-nitro-enclaves-cli-devel -y

# Compile the Docker image to an enclave image.  We run the command via bash, to
# discard the stderr output, which leaves us with only the JSON output.
CMD ["bash", "-c", "nitro-cli build-enclave --docker-uri $docker_image --output-file /dev/null 2>/dev/null"]
EOF
trap "rm -f $dockerfile" EXIT
trap "rm -f $dockerfile" SIGINT

# We're using --no-cache because AWS's nitro-cli may update, at which point the
# builder image will use an outdated copy, which will result in an unexpected
# PCR0 value.
builder_image="nitro-cli:latest"
echo "[+] Building ephemeral builder image." >&2
docker build \
    --no-cache \
    --quiet \
    --tag "$builder_image" \
    --platform=linux/amd64 \
    - < Dockerfile 2>/dev/null

echo "[+] Running builder image to obtain enclave PCRs." >&2
measurements=$(docker run \
    --tty \
    --interactive \
    --platform=linux/amd64 \
    --volume /var/run/docker.sock:/var/run/docker.sock \
    "$builder_image")

# Request attestation document from the enclave.
echo "[+] Fetching remote attestation." >&2
script_dir=$(dirname "$0")
go run "${script_dir}/../cmd/veil-verify/main.go" \
    -addr "$enclave" \
    -pcrs "$measurements"
