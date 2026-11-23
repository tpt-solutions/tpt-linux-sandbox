# Changelog

All notable changes to `tpt-l-sandbox-cli` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- PID namespace by default: the command is PID 1 of its own namespace (`--share-pids` turns it off).
- IPC isolation by default: abstract Unix sockets and signals are scoped to the sandbox (`--share-ipc` turns it off).
- `--allow-tcp-bind` and `--allow-tcp-connect` for TCP port rules (Linux 6.7+).
- Built-in profiles and policy files accept `pid_namespace`, `isolate_ipc`, `allow_tcp_bind` and `allow_tcp_connect`.
- `--doctor --json` prints the doctor report as one JSON object (`checks` and `exit_code`) on stdout.
- `--check-policy FILE` parses a policy, validates its values and confirms its paths exist, without running anything.
- `--print-schema` prints the JSON Schema for policy files. The schema is embedded in the binary, so it works offline.
- `--print-profile` starts its output with a `#:schema` header for Taplo and VS Code.
- `--move-cgroup-processes` moves processes that share a delegated cgroup into a leaf, so limits can be enabled. Off by default.
- `--memory-limit` accepts K, M and G suffixes (for example `512M`).
- `tpt-sandbox` binary running a command inside `tpt-l-sandbox`.
- Options for allowlists (`--allow-read`, `--allow-write`, `--allow-exec`),
  network (`--no-network`), limits (`--memory-limit`, `--cpu-quota`,
  `--pids-limit`), root and working directory (`--new-root`, `--cwd`),
  capabilities (`--drop-caps`), seccomp (`--seccomp`), environment
  (`--pass-env`), and output (`--json`).
- Built-in profiles (`strict`, `build`, `network-client`, `maintainer-script`,
  `untrusted-python`, `untrusted-node`), selectable with `--profile` and
  printable with `--print-profile`.
- Policy files (`--policy`) using the schema in `schemas/policy.schema.json`.
- `--from-apparmor` to import the file rules of an AppArmor profile.
- `--dry-run` (alias `--explain`) to show the effective policy.
- `--doctor` to check the machine for Landlock, user namespaces, cgroup
  delegation, WSL and AppArmor restrictions.
- `--learn` to draft a policy from the paths a command opens (runs unsandboxed
  under `strace`). Opens for writing are recorded as `allow_write`.
- Exit reporting for signals, including a seccomp (SIGSYS) and OOM (SIGKILL)
  explanation, with an optional JSON event.
- Integration tests that check output and exit status, not only failure.
- Recipes in `docs/recipes/` and a smoke test that runs their commands in CI.

### Changed

- The sandbox runs in a forked child. The parent is not restricted, removes the
  child's cgroup after it exits, and reports how it ended.
- Seccomp is enforced by default with the base allowlist. The earlier log-only
  default is available as `--seccomp log`.
- System directories are readable and executable by default; disable with
  `--no-system-paths`.
- The environment is cleared; only the default variables and `--pass-env` names
  are kept. A `--pass-env` name that is not set produces a warning.
- Inherited file descriptors are closed, and the command runs in a new session.
- Limit values are rejected when out of range instead of being clamped.
- A missing command is a usage error and exits 2 (it previously exited 1), with or
  without `--learn`. Exit 2 is documented for all usage errors.
- The command starts in the invoking directory. It previously started in `/`.
  With `--new-root` it still starts in `/`.
- `--dry-run` runs the same checks as a real run, so it reports problems that
  would stop the command.

### Fixed

- The user-namespace UID and GID are read before `unshare`. The old code read
  them after `unshare`, when they show the overflow id, so the UID map write
  used the wrong id.
- The command can be executed by default: system directories grant execute
  rights, and `--allow-exec` adds more. Previously `--allow-read` granted no
  execute right, so the final `exec` was denied.
- Negative tests now assert that the sandbox was set up, so a setup failure
  cannot pass as a block.
- Built-in profiles no longer set cgroup limits. Limits need cgroup delegation,
  so `--profile strict` failed on most machines. Limits now come only from flags
  or policy files.
- Cgroups are created under the caller's own cgroup, so delegated services
  (systemd `Delegate=yes`) work without root.
- `SIGHUP`, `SIGINT` and `SIGTERM` are forwarded to the command, and the command
  is killed if the CLI dies.
- `--learn` writes to a private directory and handles escaped quotes in `strace`
  output.
- GNU make runs under the default seccomp allowlist. It previously reported
  `Operation not permitted` because `faccessat2`, `getrusage`, `setresuid` and
  `setresgid` were blocked.
