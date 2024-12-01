# veil-verify

This tool performs remote attestation on an enclave that's running
[veil](https://github.com/Amnesic-Systems/veil).
Conceptually, all you need to provide is the *URL of the enclave*
and the enclave's *software repository*.
veil-verify will then create a deterministic build of the software repository,
which results in a set of checksums.
Next, veil-verify establishes a connection to the enclave,
requesting its checksums.
In the final step,
veil-verify compares the locally-created checksums
to the ones provided by the enclave.
If the checksums match,
you have assurance that the enclave is powered by the software repository
that you provided in the first step.

## Usage

First, compile veil-verify:

```
make veil-verify
```

Next, run the tool and provide the address of the enclave and
the software repository that's powering the enclave, e.g.:

```
./cmd/veil-verify/veil-verify \
    -addr https://example.com \
    -dir /path/to/source/code
```

By default,
veil-verify is going to use Dockerfile
in the repository's root directory to make a build.
You can use the `-dockerfile` command line flag to point veil-verify
at a different Dockerfile.
Note that `-dockerfile` a path
that is relative to the given repository's root directory.

Be patient when running veil-verify.
It usually takes at least a minute to create a reproducible build.
Use the command line flag `-verbose`
to get a glimpse of what's going on behind the scenes.

## Known problems

* When using containerd in Docker Desktop on macOS, pulling `amazonlinux` fails
  with the following error message.  Disable containerd to work around that error.
  ```
  Loaded image: enclave:latest
  Step 1/5 : FROM public.ecr.aws/amazonlinux/amazonlinux:2023

  ---> 196476f434b7
  Step 2/5 : RUN dnf install aws-nitro-enclaves-cli -y

  NotFound: content digest sha256:0a61dcc996c38c6175be38477b9930c078dae02aa32f0ae47e716c5a18f18124: not found
  ```
