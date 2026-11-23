# tpt-l-sandbox-cli

A command-line runner that executes a program inside the
[`tpt-l-sandbox`](../tpt-l-sandbox) orchestrator. It is a pure-Rust alternative
to `bwrap` and `firejail`. The installed binary is named `tpt-sandbox`.

## Features

- Filesystem allowlists for read, write and execute (`--allow-read`,
  `--allow-write`, `--allow-exec`), each repeatable, enforced by Landlock.
- Standard system directories are readable and executable by default, so
  ordinary programs start. `--no-system-paths` turns this off.
- Network isolation with `--no-network`.
- Memory, CPU and process-count limits through a cgroup v2 group
  (`--memory-limit`, `--cpu-quota`, `--pids-limit`).
- A seccomp syscall allowlist, enforced by default (`--seccomp enforce`).
- Capability dropping with `--drop-caps`.
- A minimal environment: only `PATH`, `TERM`, `LANG`, `LC_ALL` and `LC_CTYPE`
  reach the command, plus any `--pass-env` names.
- Inherited file descriptors are closed, and the command gets a new session
  (no controlling terminal).
- Built-in profiles and TOML policy files, plus import from AppArmor profiles.
- `--dry-run` to show the effective policy, `--doctor` to check the machine,
  and `--learn` to draft a policy from a run.
- `--json` for a machine-readable exit event.

## Requirements

- Linux with Landlock (5.13 or newer). Without it setup fails rather than
  running unrestricted.
- Unprivileged user namespaces. Ubuntu 24.04 needs
  `kernel.apparmor_restrict_unprivileged_userns=0`.
- cgroup v2 with the `cpu`, `memory` and `pids` controllers delegated, for the
  limit flags.
- Rust 1.85 or newer to build from source.

Run `tpt-sandbox --doctor` to see which of these your machine meets. See
[troubleshooting](../../docs/troubleshooting.md) for fixes.

## Installation

From a checkout:

```sh
cargo install --path crates/tpt-l-sandbox-cli
```

Or with the install script, which downloads a release binary:

```sh
curl -fsSL https://raw.githubusercontent.com/TPT-Solutions/tpt-linux-sandbox/master/install.sh | sh
```

Publication to crates.io is still pending.

## Usage

```sh
tpt-sandbox [OPTIONS] -- <COMMAND> [ARGS...]
```

| Option | Meaning |
|---|---|
| `--profile <NAME>` | Start from a built-in profile. Other flags extend it. |
| `--policy <FILE>` | Load a policy file (same schema as profiles). |
| `--from-apparmor <FILE>` | Import the file rules of an AppArmor profile. |
| `--allow-read <PATH>` | Permit reads under `PATH`. Repeatable. |
| `--allow-write <PATH>` | Permit reads and writes under `PATH`. Repeatable. |
| `--allow-exec <PATH>` | Permit executing files under `PATH`. Repeatable. |
| `--no-system-paths` | Do not grant the standard system directories. |
| `--no-network` | Run in a network namespace with no external access. |
| `--memory-limit <BYTES>` | Memory limit (must be greater than 0). |
| `--cpu-quota <PERCENT>` | CPU limit as a percentage of one core (1–100). |
| `--pids-limit <N>` | Maximum number of processes and threads. |
| `--new-root <PATH>` | Use `PATH` as the new root filesystem. |
| `--cwd <PATH>` | Working directory for the command (default `/`). |
| `--drop-caps` | Drop all capabilities before running the command. |
| `--seccomp <MODE>` | `enforce` (default), `log` (log only) or `off`. |
| `--pass-env <NAME>` | Pass this environment variable through. Repeatable. |
| `--json` | Print a JSON exit event to stderr. |
| `--dry-run`, `--explain` | Print the effective policy and exit without running. |
| `--learn` | Run the command unsandboxed under `strace` and print a draft policy. |
| `--doctor` | Check whether this machine can run the sandbox. |
| `--print-profile <NAME>` | Print a built-in profile's TOML and exit. |
| `-h`, `--help` | Show help. |
| `-V`, `--version` | Show the version. |

Built-in profiles: `strict`, `build`, `network-client`, `maintainer-script`,
`untrusted-python`, `untrusted-node`.

Policy values are combined in this order: profile, policy file, AppArmor
profile, then flags. Lists are extended. Flags override scalar values.

Examples:

```sh
# Read /etc only; run cat on the hostname.
tpt-sandbox --allow-read /etc -- cat /etc/hostname

# A profile, with a larger memory limit.
tpt-sandbox --profile build --memory-limit 2147483648 -- make

# Show the policy without running anything.
tpt-sandbox --profile strict --allow-read /srv/data --dry-run -- ./worker
```

## Exit codes

| Code | Meaning |
|---|---|
| the command's code | the command ran and exited |
| 128 + N | the command was killed by signal N |
| 1 | the CLI failed (bad flags or policy) |
| 126 | the sandbox could not be set up; nothing ran |
| 127 | the command could not be executed |

With `--json`, a line like `{"event":"exit","exit_code":3,"signal":null,"reason":null}`
is printed to stderr.

## Behaviour and limitations

- **Seccomp is enforced by default** with a general-purpose allowlist
  (`SeccompPolicy::base_profile`). Calls outside it return `EPERM`. Use
  `--seccomp log` to see what would be blocked. Syscalls such as `ptrace` are
  not in the allowlist.
- **Filesystem restrictions use Landlock.** Paths you do not allow are denied
  for the command and its children. Landlock grants whole directory trees.
- **Resource limits need cgroup delegation.** Without it the limit flags fail
  with a clear error; `--doctor` reports which controllers are missing.
- **The command is restricted, not the CLI.** The CLI forks first, the child
  applies the sandbox and `exec`s the command, and the parent waits, removes the
  child's cgroup, and reports the exit.
- **The PID namespace is not used.** The command can see host process IDs
  through `/proc`.
- **Network isolation is all-or-nothing.** `--no-network` gives the command a
  network namespace with no external connectivity; there is no per-host policy.
- **`--learn` runs the command without a sandbox** to record what it opens.
  Review the draft policy before using it.

## Testing

```sh
cargo test -p tpt-l-sandbox-cli
```

The integration tests in `tests/integration.rs` run the built binary and need
Linux with user namespaces. Negative tests check that the command was blocked
and that the sandbox was set up, so a setup failure cannot pass as a block. The
memory-limit test is skipped when the memory controller is not delegated.

## Minimum supported Rust version

Rust 1.85, inherited from the workspace.

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE), at your option.

Part of the [tpt-linux-sandbox](https://github.com/TPT-Solutions/tpt-linux-sandbox) workspace.
