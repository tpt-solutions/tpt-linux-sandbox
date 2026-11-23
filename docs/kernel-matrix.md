# Kernel and feature matrix

Which kernel features tpt-sandbox uses, and what happens when one is missing.

| Feature | Needed for | Minimum kernel | If missing |
|---|---|---|---|
| Landlock ABI 1 (filesystem read, write, exec) | `--allow-read`, `--allow-write`, `--allow-exec` | 5.13 | setup fails with a clear error (Landlock is always applied) |
| Landlock ABI 2 (Refer: rename across directories) | write paths | 5.19 | rights are dropped by best-effort compatibility |
| Landlock ABI 3 (Truncate) | write paths | 6.2 | rights are dropped by best-effort compatibility |
| Landlock ABI 4 (TCP bind/connect) | `--allow-tcp-bind`, `--allow-tcp-connect` | 6.7 | `apply` fails with a clear error (the sandbox does not start) |
| Landlock ABI 5 (ioctl on devices) | not used yet | 6.10 | not applied |
| Landlock ABI 6 (scoped signals, abstract sockets) | IPC isolation (on by default; `--share-ipc` turns it off) | 6.12 | not applied; the sandbox runs with abstract sockets and signals unscoped |
| seccomp filter mode | `--seccomp enforce` (default) and `log` | 3.5 (log action: 4.14) | seccomp setup fails |
| Unprivileged user namespaces | every run (user and mount namespaces) | 3.8 with `CONFIG_USER_NS` | setup fails; see troubleshooting |
| Network namespaces | `--no-network` | 2.6.29 | setup fails |
| PID namespaces | the default (`--share-pids` turns it off) | 2.6.24 | setup fails; use `--share-pids` |
| cgroup v2 (unified hierarchy) | `--memory-limit`, `--cpu-quota`, `--pids-limit` | 4.5 | limits fail; no sandbox effect |
| cgroup v2 delegation to this user | the same limit flags | systemd `Delegate=yes`, or root | `EBUSY` or `EACCES` when writing controllers |
| `close_range(2)` | closing inherited descriptors | 5.9 | falls back to closing descriptors 3–4095 one by one |
| Securebits, ambient capability set | `--drop-caps` | 4.3 | the drop fails with an error |

Kernel minimums are from the kernel documentation for each feature. They have
not all been checked on hardware, so treat them as a guide and confirm with
`--doctor` on your system.

## Landlock must be in the active LSM list

```sh
cat /sys/kernel/security/lsm
```

The output must contain `landlock`. If it does not, add it to the `lsm=` boot
parameter and reboot.

## Tested environments

| Environment | Status |
|---|---|
| Ubuntu 24.04, root and unprivileged user | configured in `.github/workflows/ci.yml`; not yet run on GitHub |
| Docker container, privileged, Linux 6.x | full test suite run locally, including ignored tests |
| WSL2 | known problems; see troubleshooting |
| Other distributions | not yet tested |
