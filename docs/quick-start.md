# Quick start

`tpt-sandbox` runs one command with filesystem, syscall, network, capability
and resource restrictions. It needs Linux.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/TPT-Solutions/tpt-linux-sandbox/master/install.sh | sh
```

Or, from crates.io with prebuilt binaries:

```sh
cargo binstall tpt-l-sandbox-cli
```

Or from source (Rust 1.85+):

```sh
cargo install --path crates/tpt-l-sandbox-cli
```

## Check the machine

```sh
tpt-sandbox --doctor
```

Each line is `ok`, `info` or `warn`. Warnings say what will not work and link
to [troubleshooting](troubleshooting.md).

## Run a command

```sh
# Read /etc only. System directories are readable and executable by default.
tpt-sandbox --allow-read /etc -- cat /etc/hostname

# Use a built-in profile: no network, no capabilities, syscall allowlist.
tpt-sandbox --profile untrusted-python -- python3 script.py

# Add limits on top of a profile.
tpt-sandbox --profile build --memory-limit 2147483648 --pids-limit 512 -- make
```

Everything after `--` is the command and its arguments.

## See what a policy does before running it

```sh
tpt-sandbox --profile build --dry-run
```

`--dry-run` (also spelled `--explain`) prints the effective policy and any
warnings. It does not run the command.

## Write a policy

Start from a profile and save it:

```sh
tpt-sandbox --print-profile build > sandbox.toml
tpt-sandbox --policy sandbox.toml -- make test
```

The file uses the schema in [`schemas/policy.schema.json`](../schemas/policy.schema.json).
Editors that support JSON Schema can check it when the file is associated
with that schema.

## Learn a policy from a run

```sh
tpt-sandbox --learn -- ./my-tool --flag
```

`--learn` runs the command **unsandboxed** under `strace` and prints a starter
`allow_read` list built from the files it opened. Review the list before you
use it. It records only what that one run touched.

## Exit codes

| Code | Meaning |
|---|---|
| the command's own code | the command ran and exited normally |
| 128 + N | the command was killed by signal N |
| 1 | the CLI itself failed (bad flags, policy error) |
| 126 | the sandbox could not be set up; nothing ran |
| 127 | the command could not be executed |

With `--json`, the CLI also prints one JSON line to stderr at exit, for example
`{"event":"exit","exit_code":137,"signal":9,"reason":"killed with SIGKILL; ..."}`.
