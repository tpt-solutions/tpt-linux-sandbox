# tpt-l-sandbox-cli

[![crates.io](https://img.shields.io/crates/v/tpt-l-sandbox-cli.svg)](https://crates.io/crates/tpt-l-sandbox-cli)

A command-line runner that executes a program inside the
[`tpt-l-sandbox`](../tpt-l-sandbox) orchestrator. It is a pure-Rust alternative
to `bwrap` and `firejail` for composing filesystem, namespace, resource, and
capability restrictions from the shell.

The installed binary is named `tpt-sandbox`.

## Features

- Read-only and read-write filesystem allow-lists (`--allow-read`,
  `--allow-write`), each repeatable.
- Network isolation with `--no-network`.
- Memory and CPU limits through a cgroup v2 group (`--memory-limit`,
  `--cpu-quota`).
- Filesystem root change with `--new-root`.
- Capability dropping with `--drop-caps`.
- Replaces itself with the target command (`exec`), so signals and exit status
  go straight to the program.

## Requirements

- Linux. Each option depends on the kernel features of the matching layer (see
  [`tpt-l-sandbox`](../tpt-l-sandbox)).
- Landlock (Linux 5.13+) for `--allow-read` and `--allow-write` to take effect.
  Without it the command fails rather than running unrestricted.
- Unprivileged user namespaces, or root, for `--no-network`, `--new-root`, and
  any option that creates a namespace.
- cgroup v2 with write access for `--memory-limit` and `--cpu-quota`.
- Rust 1.85 or newer to build from source.

## Installation

From crates.io:

```sh
cargo install tpt-l-sandbox-cli
```

From a checkout of this repository:

```sh
cargo install --path crates/tpt-l-sandbox-cli
```

## Usage

```sh
tpt-sandbox [OPTIONS] -- <COMMAND> [ARGS...]
```

| Option | Meaning |
|---|---|
| `--allow-read <PATH>` | Permit reads under `PATH`. Repeatable. |
| `--allow-write <PATH>` | Permit reads and writes under `PATH`. Repeatable. |
| `--no-network` | Run in a network namespace with no external access. |
| `--memory-limit <BYTES>` | Memory limit for the cgroup. |
| `--cpu-quota <PERCENT>` | CPU limit as a percentage of one core (1–100). |
| `--new-root <PATH>` | Use `PATH` as the new root filesystem. |
| `--drop-caps` | Drop all capabilities before running the command. |
| `-h`, `--help` | Show help. |
| `-V`, `--version` | Show the version. |

Examples:

```sh
# Read /etc only; run cat on the hostname.
tpt-sandbox --allow-read /etc -- cat /etc/hostname

# Limit memory to 128 MiB and CPU to half a core, with no network.
tpt-sandbox --no-network --memory-limit 134217728 --cpu-quota 50 \
    --allow-read /usr --allow-read /etc -- ./worker
```

Errors are printed to stderr and the process exits with a non-zero status.

## Behaviour and limitations

- **Syscall filtering is log-only in this release.** The CLI installs a seccomp
  policy whose default action is `Log`. Syscalls that would be denied are logged
  and allowed to proceed, so the CLI does not block them. Do not rely on
  `tpt-sandbox` to restrict system calls. Use `tpt-l-sandbox` directly with a
  stricter `SeccompPolicy` if you need enforcement.
- **Filesystem restrictions use Landlock.** Paths you do not allow are denied
  for the program and its children. Paths must exist when the command starts.
- **No allow-list for execution.** There is no `--allow-exec` flag. The command
  is executed through the process that was restricted, so Landlock's read
  rules must cover the binary and any shared libraries it loads.
- **Network isolation is all-or-nothing.** `--no-network` gives the command a
  network namespace with no external connectivity; there is no per-host policy.
- **Exec replaces the CLI process.** After the sandbox is applied, the CLI calls
  `exec(2)`. A failed `exec` is reported as an error.

## Testing

Unit tests and integration tests for the binary run with:

```sh
cargo test -p tpt-l-sandbox-cli
```

The integration tests in `tests/integration.rs` run the built binary and expect
Linux. They are the end-to-end checks for the layers in this workspace.

Known environment issue: the test `cli_allow_read_etc_hostname_succeeds` fails
on WSL2, where writing the user-namespace UID map is not permitted. The other
integration tests can pass there for the wrong reason, because they expect the
command to fail and the sandbox setup fails first. Run the suite on a native
Linux host with unprivileged user namespaces enabled before relying on it.

## Minimum supported Rust version

Rust 1.85, inherited from the workspace.

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE), at your option.

Part of the [tpt-linux-sandbox](https://github.com/TPT-Solutions/tpt-linux-sandbox) workspace.
