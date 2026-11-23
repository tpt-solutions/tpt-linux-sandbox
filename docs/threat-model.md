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
| Landlock (filesystem) | reads, writes and execution outside the allowlist fail with `EACCES` |
| seccomp (`enforce`) | syscalls outside the base allowlist fail with `EPERM` |
| Network namespace (`--no-network`) | no external network; loopback only |
| Capability drop (`--drop-caps`) | removes every capability from the bounding, ambient, permitted, effective and inheritable sets; sets `no_new_privs` and locks securebits |
| cgroup v2 limits | memory (swap disabled alongside), CPU share, number of processes and threads |
| Environment scrub | only PATH, TERM, LANG, LC_ALL and LC_CTYPE, plus `--pass-env` names, reach the command |
| Descriptor close | file descriptors 3 and above that the caller held are closed |
| Terminal detach | `setsid` runs first, so the command has no controlling terminal (blocks `TIOCSTI`) |

## What it does not protect against

- **Kernel vulnerabilities.** Every layer runs in the host kernel. A kernel bug
  that lets a process escape the sandbox is out of scope.
- **Allowed syscalls used against you.** The base profile allows `clone` and
  `clone3` without filtering their flags, `ioctl` without argument filtering,
  and `socket` for any address family. Those calls are not limited beyond the
  network namespace.
- **Network access inside the allowlist.** `--no-network` is off by default.
  Unix sockets on allowed paths remain reachable. Landlock network rules
  (ABI 4) are not used yet.
- **Abstract Unix sockets and signals.** Landlock ABI 6 scopes these. This
  project does not use that ABI yet, so a sandboxed process can reach abstract
  sockets and signal processes outside the sandbox.
- **Side channels and timing.** Also not covered: resource exhaustion beyond
  the configured cgroup limits, and disk usage (not limited).
- **Information in allowed paths.** Whatever you allow to be read is readable.
  `/proc` is not granted by default.
- **Processes started before the sandbox.** Only the command and its children
  are restricted.
- **The seccomp `log` mode and `--seccomp off`.** Neither enforces anything.
- **PID namespace.** The CLI does not create one, so the command can see host
  process IDs in `/proc`. The library's `NamespaceSet::pid` affects children
  only and needs an init process; see its documentation.
- **The `--new-root` jail.** Mounts are made private before pivoting, but the
  jail is only as strong as the rootfs you provide.

## Defaults worth knowing

- `--seccomp enforce` is the default.
- System directories (`/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`) are readable and
  executable by default. Use `--no-system-paths` to remove that.
- The network is shared with the host unless you pass `--no-network` or use a
  profile that sets it (`strict`, `maintainer-script`, `untrusted-*`).

## Reporting

Report security issues privately to the maintainers before opening a public
issue.
