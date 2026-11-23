# A container image that includes tpt-sandbox.
#
# Running the sandbox inside a container needs user namespaces, which Docker's
# default seccomp profile blocks. Start the container with:
#   docker run --security-opt seccomp=unconfined --security-opt apparmor=unconfined ...
# Narrow this to the minimum for your environment; see docs/troubleshooting.md.
FROM debian:bookworm-slim

ARG TPT_SANDBOX_VERSION=0.1.0
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# Static musl binary from the GitHub release (x86_64 shown; use aarch64 on ARM).
RUN curl -fsSL "https://github.com/TPT-Solutions/tpt-linux-sandbox/releases/download/v${TPT_SANDBOX_VERSION}/tpt-sandbox-x86_64-unknown-linux-musl.tar.gz" \
    | tar -xz -C /tmp \
 && install -m 0755 /tmp/tpt-sandbox-x86_64-unknown-linux-musl/tpt-sandbox /usr/local/bin/tpt-sandbox \
 && rm -rf /tmp/tpt-sandbox-*

# Unprivileged user for the workload.
RUN useradd --create-home --uid 1000 runner
USER runner
WORKDIR /home/runner

ENTRYPOINT ["tpt-sandbox", "--profile", "strict", "--"]
CMD ["/bin/sh", "-c", "echo sandbox ready"]
