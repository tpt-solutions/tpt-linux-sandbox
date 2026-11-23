# Troubleshooting

Start with `tpt-sandbox --doctor`. Most problems below show up there first.

## `sandbox setup failed: ... unshare(2) failed: Operation not permitted`

Unprivileged user namespaces are blocked.

- **Ubuntu 24.04 and later** restrict them with AppArmor. Check
  `cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns`. If it prints
  `1`, allow user namespaces until reboot with
  `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`. To make the
  change permanent, put the setting in `/etc/sysctl.d/99-userns.conf`. A
  narrower option is an AppArmor profile that grants `userns` to
  `tpt-sandbox`.
- **Containers** need `--security-opt seccomp=unconfined`, because Docker's
  default profile blocks `unshare`. They usually also need
  `--security-opt apparmor=unconfined`.
- **`max_user_namespaces` is 0.** Raise it with
  `sudo sysctl -w user.max_user_namespaces=15000`.

## `failed to write ... cgroup.subtree_control: Device or resource busy`

The cgroup controllers (`cpu`, `memory`, `pids`) are not delegated to your
user. The limit flags need one of:

- a systemd unit or scope with `Delegate=yes` (see
  [`templates/systemd-hardening.service`](../templates/systemd-hardening.service));
- root; or
- no limit flags. The sandbox still applies every other layer.

`--doctor` reports which controllers are missing. The sandbox refuses to reuse
a cgroup left over from an earlier run and reports "already exists" instead.

## `UID/GID map write failed`

- The process is multi-threaded. User namespaces must be created before any
  thread starts. The CLI does this by design. If you use the library, call
  `Sandbox::apply` before spawning threads. The error message names the thread
  count.
- The map could not be written because the kernel refused the mapping. The
  CLI maps only the calling uid and gid, so this is rare. `--doctor` shows
  whether user namespaces are enabled at all.

## WSL2

WSL2 can work, but cgroup delegation and some user-namespace setups are not
enabled by default. Symptoms:

- `uid_map` write failures on some WSL2 kernels;
- the limit flags failing with `EBUSY` or `EACCES`.

What to try: update WSL (`wsl --update`), run `tpt-sandbox --doctor`, and use
the flags that work. If you need the limit flags, run them on a Linux system
that has delegation.

## `Permission denied` on a file the command should read

The path is not in the allowlist, so Landlock blocked it with `EACCES`. Check
with:

```sh
tpt-sandbox --dry-run --allow-read /path -- cmd
tpt-sandbox --learn -- cmd            # paths the command opens
```

Also check the parent directory. Landlock grants a path and everything beneath
it, so a directory must be allowed for the files inside it to be read.

## Exit code 159 (SIGSYS), or "terminated by seccomp"

The command made a system call that the seccomp allowlist does not include.

- Re-run with `--seccomp log`. Log mode allows every call and records it, so
  you can see which call the policy would block. Use `strace -f` to see calls
  made by the command itself.
- If the call is legitimate, the base profile needs it. Open an issue with the
  command and the syscall name.
- `--seccomp off` disables the filter. It is weaker, so do not use it on
  untrusted code.

## Exit code 137 (SIGKILL) with `--memory-limit`

The command exceeded its memory limit and the kernel OOM-killed it. Raise the
limit or reduce the command's memory use.

## Exit code 126 or 127

- **126**: the sandbox could not be set up. The message before the exit line
  says which stage failed. Nothing was executed.
- **127**: the command could not be started. Check that its path is in
  `allow_exec`. System directories are included by default, unless
  `--no-system-paths` is set.
