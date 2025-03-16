# Veil

Veil is a tool kit for building networked services on top of
AWS Nitro Enclaves.

## Installation

Veil consists of several CLI tools that are in the cmd directory.
Run the following command to compile all CLI tools:

```bash
make
```

## Usage

Conceptually, there are three components:

1. `veil` (in cmd/veil/veil) implements a service that runs inside the AWS Nitro
   Enclave alongside your application. This service is responsible for
   establishing a network tunnel to the outside world, remote attestation, and
   it provides a REST API for your application to use.

1. `veil-proxy` (in cmd/veil-proxy/veil-proxy) runs on the EC2 host that
   contains the enclave. It helps `veil` use the Internet seamlessly by
   implementing a tun interface.

1. `veil-verify` (in cmd/veil-verify/veil-verify) verifies a given enclave by
   making sure that it runs a copy of the given source code.

The repository
[veil-examples](https://github.com/sriharsh/veil-examples)
contains examples of using Veil to build networked services.