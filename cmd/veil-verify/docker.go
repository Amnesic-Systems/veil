package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path"

	"github.com/Amnesic-Systems/veil/internal/addr"
	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/Amnesic-Systems/veil/internal/errs"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/fatih/color"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	compilerImage    = "nitro-cli-builder"
	builderImage     = "gcr.io/kaniko-project/executor:v1.9.2"
	builderContainer = "kaniko"
	enclaveTarImage  = "enclave.tar"
)

func removeContainer(cli *client.Client, id string) {
	// Create a new context because the original context may have been
	// cancelled.
	ctx := context.Background()
	if err := cli.ContainerStop(ctx, id, container.StopOptions{
		Timeout: addr.Of(0),
	}); err != nil {
		log.Printf("Failed to stop container %s: %v", id, err)
		return
	}

	if err := cli.ContainerRemove(ctx, id, container.RemoveOptions{
		Force: true,
	}); err != nil {
		log.Printf("Failed to remove container %s: %v", id, err)
		return
	}
	log.Printf("Removed container %s.", id)
}

func buildEnclaveImage(
	ctx context.Context,
	cli *client.Client,
	cfg *config,
) (err error) {
	defer errs.Wrap(&err, "failed to build enclave image")

	// Pull the kaniko image, which we use to reproducibly build the
	// enclave image.
	output, err := cli.ImagePull(ctx, builderImage, image.PullOptions{})
	if err != nil {
		return errs.Add(err, "failed to pull image")
	}
	defer output.Close()
	if cfg.verbose {
		printJSON(output)
	}
	log.Print("Pulled kaniko builder image.")

	// Configure kaniko.  We want a reproducible build for linux/amd64 because
	// that's the platform the enclave is running on.
	containerConfig := &container.Config{
		Tty:   true,
		Image: builderImage,
		Cmd: []string{
			"--dockerfile", cfg.dockerfile,
			"--reproducible",
			"--no-push",
			"--verbosity", "warn",
			"--tarPath", enclaveTarImage,
			"--destination", "enclave",
			"--custom-platform", "linux/amd64",
		},
	}

	// Set our volume mounts, which we need to get the enclave's tar image out.
	hostConfig := &container.HostConfig{
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: cfg.dir,
				Target: "/workspace",
			},
		},
	}

	// Create the container for our builder image.  We are going to remove it
	// after we're done building the enclave image.
	resp, err := cli.ContainerCreate(ctx,
		containerConfig,
		hostConfig,
		&network.NetworkingConfig{},
		&v1.Platform{},
		builderContainer,
	)
	if err != nil {
		return errs.Add(err, "failed to create container")
	}
	defer removeContainer(cli, resp.ID)
	log.Print("Created builder container.")

	// Start the container.  A build will take a minute or so to complete.
	if err := cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return errs.Add(err, "failed to start container")
	}
	log.Print("Started builder container.")

	// If we need verbose logs, request and print the container's logs.
	if cfg.verbose {
		options := container.LogsOptions{
			ShowStdout: true,
			ShowStderr: true,
			Follow:     true,
		}
		reader, err := cli.ContainerLogs(ctx, resp.ID, options)
		if err != nil {
			return errs.Add(err, "failed to get container logs")
		}
		defer reader.Close()
		go printPlain(reader)
	}

	// Wait until the container is no longer running.
	log.Print("Waiting for builder container to build enclave image.")
	if err := waitForContainer(ctx, cli, resp.ID); err != nil {
		return err
	}

	// Check the container's exit code and return an error if the exit code is
	// non-zero.
	return getContainerExitCode(ctx, cli, resp.ID)
}

func waitForContainer(
	ctx context.Context,
	cli *client.Client,
	containerID string,
) (err error) {
	// Wait for the container to stop running.
	waitCh, errCh := cli.ContainerWait(
		ctx,
		containerID,
		container.WaitConditionNotRunning,
	)

	select {
	case err := <-errCh:
		return errs.Add(err, "failed to wait for container")
	case <-waitCh:
		return nil
	case <-ctx.Done():
		return nil
	}
}

func getContainerExitCode(
	ctx context.Context,
	cli *client.Client,
	containerID string,
) error {
	// Inspect the container to get its state.
	containerJSON, err := cli.ContainerInspect(ctx, containerID)
	if err != nil {
		return errs.Add(err, "failed to inspect container")
	}

	// Check if the container has stopped.
	if containerJSON.State.Running {
		return errors.New("container is still running")
	}
	code := containerJSON.State.ExitCode
	if code != 0 {
		return fmt.Errorf("container failed with exit code %d", code)
	}
	return nil
}

func loadEnclaveImage(
	ctx context.Context,
	cli *client.Client,
	cfg *config,
) (err error) {
	defer errs.Wrap(&err, "failed to load enclave image")

	// Read the tar image.
	file, err := os.Open(path.Join(cfg.dir, enclaveTarImage))
	if err != nil {
		return err
	}
	// Ignore the error because the file is already being closed somewhere by
	// our dependencies.
	defer func() { _ = file.Close() }()

	// Load the tar image.
	reader, err := cli.ImageLoad(ctx, file, false)
	if err != nil {
		return errs.Add(err, "failed to load image")
	}
	defer func() { err = reader.Body.Close() }()

	if cfg.verbose {
		printJSON(reader.Body)
	}
	return nil
}

func buildCompilerImage(
	ctx context.Context,
	cli *client.Client,
	verbose bool,
) (err error) {
	defer errs.Wrap(&err, "failed to build compiler image")

	// Install the tooling that we need to compile enclave images.  We run
	// nitro-cli via bash, to discard stderr, which leaves us with only the JSON
	// output.  For more details on the tooling, refer to:
	// https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install.html#install-cli
	const dockerfile = `
FROM public.ecr.aws/amazonlinux/amazonlinux:2023
RUN dnf install aws-nitro-enclaves-cli -y
RUN dnf install aws-nitro-enclaves-cli-devel -y
RUN nitro-cli -V
CMD ["bash", "-c", "nitro-cli build-enclave --docker-uri enclave:latest --output-file /dev/null 2>/dev/null"]
`

	// Create a tar archive containing only the Dockerfile as we don't need a
	// build context.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{
		Name: "Dockerfile",
		Size: int64(len(dockerfile)),
	}); err != nil {
		return errs.Add(err, "failed to write header")
	}
	if _, err := tw.Write([]byte(dockerfile)); err != nil {
		return errs.Add(err, "failed to write Dockerfile")
	}
	if err := tw.Close(); err != nil {
		return errs.Add(err, "failed to close tar writer")
	}

	// Finally, build the compiler image.
	opts := types.ImageBuildOptions{
		Tags:       []string{compilerImage},
		Dockerfile: "Dockerfile",
		Remove:     true, // Clean up intermediate images.
		Platform:   "linux/amd64",
	}
	resp, err := cli.ImageBuild(ctx, &buf, opts)
	if err != nil {
		return errs.Add(err, "failed to build compiler image")
	}
	defer func() { err = resp.Body.Close() }()

	if verbose {
		printJSON(resp.Body)
	}
	return nil
}

func compileEnclaveImage(
	ctx context.Context,
	cli *client.Client,
) (_ enclave.PCR, err error) {
	defer errs.Wrap(&err, "failed to compile enclave image")

	// Set our volume mounts.  We pass the host's Docker socket to the container
	// so that the nitro-cli tool has access to the enclave image that we built
	// in the previous step.
	hostConfig := &container.HostConfig{
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: "/var/run/docker.sock",
				Target: "/var/run/docker.sock",
			},
		},
	}

	// Configure our custom builder image.  We are going to run the nitro-cli
	// tool to compile the enclave image and obtain the PCR values.  These PCR
	// values are subsequently used in remote attestation.
	containerConfig := &container.Config{
		Tty:   true,
		Image: compilerImage,
	}
	// Create the container for our builder image.  It's ephemeral, so we are
	// going to remove it after we've obtained the PCR values.
	resp, err := cli.ContainerCreate(ctx,
		containerConfig,
		hostConfig,
		&network.NetworkingConfig{},
		&v1.Platform{
			Architecture: "amd64",
			OS:           "linux",
		},
		compilerImage,
	)
	if err != nil {
		return nil, errs.Add(err, "failed to create container")
	}
	defer removeContainer(cli, resp.ID)
	log.Print("Created compiler container.")

	// Finally, run the container.  The nitro-cli tool will compile the enclave
	// image and log the PCR values to stdout.
	if err := cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return nil, errs.Add(err, "failed to start container")
	}
	log.Print("Started compiler container.")

	return parsePCRsFromLogs(ctx, cli, resp.ID)
}

func parsePCRsFromLogs(
	ctx context.Context,
	cli *client.Client,
	containerID string,
) (enclave.PCR, error) {
	// Fetch the container's logs.  We are only interested in the PCR values,
	// which are logged to stdout.
	options := container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
	}
	reader, err := cli.ContainerLogs(ctx, containerID, options)
	if err != nil {
		return nil, errs.Add(err, "failed to get container logs")
	}
	defer func() { err = reader.Close() }()

	// Fetch the container's stdout and decode the JSON into our PCR values.
	buf := bytes.NewBufferString("")
	if _, err = io.Copy(buf, reader); err != nil {
		return nil, errs.Add(err, "failed to read container logs")
	}

	// Make sure that the container exited with a zero exit code.
	if err := getContainerExitCode(ctx, cli, containerID); err != nil {
		return nil, err
	}

	pcr, err := toPCR(buf.Bytes())
	return pcr, errs.Add(err, "failed to parse PCR values")
}

func printJSON(from io.Reader) {
	type msg struct {
		Stream string `json:"stream"`
		Status string `json:"status"`
	}

	decoder := json.NewDecoder(from)
	for {
		var m msg
		if err := decoder.Decode(&m); err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("Error decoding JSON: %v", err)
			log.Print()
			break
		}
		if m.Stream != "" {
			color.Cyan(m.Stream)
		}
		if m.Status != "" {
			color.Cyan(m.Status)
		}
	}
}

func printPlain(from io.Reader) {
	scanner := bufio.NewScanner(from)
	for scanner.Scan() {
		color.Cyan(scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Print(err.Error())
	}
}