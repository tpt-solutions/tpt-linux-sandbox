# Threat model

What tpt-sandbox is for, what it protects against, and what it does not.

## Goal

Limit what a single command can do to the host, so that a bug or hostile input
in that command has a smaller effect. It is a sandbox for running untrusted or
third-party programs. It is not a boundary against an attacker who can exploit
the kernel.

## What each layer does

| Layer | Restricts |
|---|---|
| User and mount namespaces | the command runs as root inside an unprivileged user namespace; its mounts are private |
| PID namespace (default) | the command is PID 1 of its own process tree; it cannot see or signal host processes by PID (`--share-pids` turns this off) |
| Landlock (filesystem) | reads, writes and execution outside the allowlist fail with `EACCES` |
| Landlock (TCP, Linux 6.7+) | only the listed ports can be bound or connected to, when any port is listed |
| Landlock (IPC, Linux 6.12+, default) | connecting to abstract Unix sockets and signalling processes outside the sandbox's domain is denied (`--share-ipc` turns this off) |
| seccomp (`enforce`) | syscalls outside the base allowlist fail with `EPERM` |
| Network namespace (`--no-network`) | no external network; loopback only |
| Capability drop (`--drop-caps`) | removes every capability from the bounding, ambient, permitted, effective and inheritable sets; sets `no_new_privs` and locks securebits |
| cgroup v2 limits | memory (swap disabled alongside), CPU share, number of processes and threads (needs delegation) |
| Environment scrub | only PATH, TERM, LANG, LC_ALL and LC_CTYPE, plus `--pass-env` names, reach the command |
| Descriptor close | file descriptors 3 and above that the caller held are closed |
| Terminal detach | `setsid` runs first, so the command has no controlling terminal (blocks `TIOCSTI`) |

On kernels older than a layer's minimum, the behaviour depends on the layer.
Explicit port rules fail the run. IPC isolation and the filesystem rights added
in later ABIs are dropped, and the sandbox runs without them. See the
[kernel matrix](kernel-matrix.md).

## What it does not protect against

- **Kernel vulnerabilities.** Every layer runs in the host kernel. A kernel bug
  that lets a process escape the sandbox is out of scope.
- **Allowed syscalls used against you.** The base profile allows `clone` and
  `clone3` without filtering their flags, `ioctl` without argument filtering,
  and `socket` for any address family. Those calls are not limited beyond the
  network namespace and the Landlock port rules.
- **Unix sockets on allowed paths.** Landlock controls filesystem access to a
  socket path, so a socket file under an allowed directory is reachable.
- **Information in allowed paths.** Whatever you allow to be read is readable.
  `/proc` is not granted by default. Without `--new-root`, the host's `/proc`
  is not mounted into a new namespace, so it still lists host processes by
  process ID even though the sandboxed command cannot signal them.
- **Processes started before the sandbox.** Only the command and its children
  are restricted.
- **The seccomp `log` mode and `--seccomp off`.** Neither enforces anything.
- **PID 1 reaping.** The command is PID 1 of its namespace. Orphaned children
  are reparented to it, and it must reap them, as any init process must.
- **The `--new-root` jail.** Mounts are made private before pivoting, but the
  jail is only as strong as the rootfs you provide.
- **Side channels and timing.** Also not covered: resource exhaustion beyond
  the configured cgroup limits, and disk usage (not limited).

## Defaults worth knowing

- `--seccomp enforce` is the default.
- The PID namespace and IPC isolation are on by default.
- System directories (`/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`) are readable and
  executable by default. Use `--no-system-paths` to remove that.
- The network is shared with the host unless you pass `--no-network` or use a
  profile that sets it (`strict`, `maintainer-script`, `untrusted-*`).
- Built-in profiles set no resource limits. Add `--memory-limit`, `--cpu-quota`
  or `--pids-limit`, which need cgroup delegation.

## Reporting

Report security issues privately to the maintainers before opening a public
issue.
