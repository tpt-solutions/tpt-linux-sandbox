# Policy cookbook

Each recipe is a command or a policy file. To use a policy file, save the TOML
and run `tpt-sandbox --policy <file> -- <command>`.

## Run an untrusted script

```toml
# untrusted.toml
allow_read = ["/etc/localtime", "/usr/share/zoneinfo"]
no_network = true
drop_caps = true
seccomp = "enforce"
memory_limit = 268435456
pids_limit = 32
```

```sh
tpt-sandbox --policy untrusted.toml -- python3 untrusted.py
```

Or use the built-in profile: `tpt-sandbox --profile untrusted-python -- python3 untrusted.py`.

## Sandbox a build in the project directory

```sh
cd my-project
tpt-sandbox --profile build -- make -j4
```

The `build` profile lets the command write to the current directory and read
`/etc`, `/usr/share`, `/usr/include` and `/usr/lib`. Network access stays on so
dependencies can be fetched. Add `--no-network` to block it.

## CI test isolation

Use the GitHub Action (see [`templates/github-actions-step.yml`](../templates/github-actions-step.yml)),
or on any Linux runner:

```sh
tpt-sandbox --profile build --no-network --memory-limit 4294967296 -- cargo test --workspace
```

## Restrict a long-running service

Use `--json` so a supervisor can read the exit reason:

```sh
tpt-sandbox --profile network-client --memory-limit 536870912 --pids-limit 128 --json -- ./worker
```

Pair this with `Delegate=yes` in the systemd unit, so the limits can be set.
See [`templates/systemd-hardening.service`](../templates/systemd-hardening.service).

## Plugin host: a plugin that reads its own data directory

```toml
# plugin.toml
allow_read = ["/opt/host/plugins/acme"]
allow_write = ["/var/lib/host/plugins/acme"]
no_network = true
drop_caps = true
pass_env = ["PLUGIN_CONFIG"]
cwd = "/var/lib/host/plugins/acme"
```

## Start from an AppArmor profile

```sh
tpt-sandbox --from-apparmor /etc/apparmor.d/usr.bin.worker -- /usr/bin/worker
```

File rules are converted to Landlock grants. Glob patterns such as `/usr/lib/**`
grant the whole directory. The CLI prints a warning for each widened or
unmapped rule. Deny rules never become grants.

## Maintainer scripts (package install)

The `maintainer-script` profile is the default for package maintainer scripts
(spec section 5). It reads the system and writes only the package database and
`/etc`. It has no network access and no capabilities:

```sh
tpt-sandbox --profile maintainer-script -- sh ./postinst configure
```

## Find what a command needs

```sh
tpt-sandbox --learn -- ./tool --check > learned.toml
tpt-sandbox --policy learned.toml --dry-run -- ./tool --check
```

Review `learned.toml` before you run it under the sandbox.
