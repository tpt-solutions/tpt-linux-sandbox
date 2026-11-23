# tpt-l-sandbox

The orchestrator for the `tpt-linux-sandbox` workspace. It combines Landlock,
seccomp, namespaces, cgroups and capability dropping behind one builder.
Stages run in a fixed order, and the irreversible ones run last, after the
whole policy has been checked.

## Example

```rust
use tpt_l_landlock_highlevel::RulesetBuilder;
use tpt_l_namespaces_rs::NamespaceSet;
use tpt_l_sandbox::Sandbox;

Sandbox::new()
    .namespaces(NamespaceSet::new().user().mount().network())
    .landlock(RulesetBuilder::new().allow_read("/etc").allow_read("/usr"))
    .apply()
    .expect("sandbox setup failed");
```

To sandbox only a child process, use the `Command` extension. The parent is not
restricted:

```rust
use std::process::Command;
use tpt_l_sandbox::{CommandSandboxExt, Sandbox};
use tpt_l_landlock_highlevel::RulesetBuilder;

let status = Command::new("/bin/cat")
    .arg("/etc/hostname")
    .sandboxed(Sandbox::new().landlock(RulesetBuilder::new().allow_read("/etc")))
    .status()?;
```

Runnable version: `cargo run -p tpt-l-sandbox --example sandboxed_command`.

## Stage order

`Sandbox::apply` runs these stages. Only configured layers do anything.

| Stage | Layer | Reversible? |
|---|---|---|
| 1 | Validation: syscall names, errnos, Landlock path existence, jail and namespace rules | — (no enforcement) |
| 2 | cgroup creation and entry (released if a later stage fails) | Yes |
| 3 | Namespaces (`unshare`) | Yes |
| 4 | Filesystem jail (`pivot_root`, pseudo-filesystems) | Yes |
| 5 | Capability drop | Yes |
| 6 | Seccomp | **No** |
| 7 | Landlock | **No** |

Stage 1 can be run on its own with `Sandbox::validate`, so a configuration
error is reported before anything changes.

## Builder methods

| Method | Layer | Stage |
|---|---|---|
| `namespaces(NamespaceSet)` | namespaces | 3 |
| `cgroup(CgroupConfig)` | cgroup limits | 2 |
| `jail(JailConfig)` | filesystem jail | 4 |
| `caps(CapsPolicy)` | capabilities | 5 |
| `seccomp(SeccompPolicy)` | seccomp | 6 |
| `landlock(RulesetBuilder)` | Landlock | 7 |
| `validate(&self)` | checks only | 1 |
| `apply(self)` | runs all stages | 1–7 |

## Behaviour

- **Validation rejects:** a jail without a mount namespace; unknown syscall
  names; errno values outside 1–4095; Landlock paths that cannot be opened.
- **Failure cleanup:** if a stage fails, the cgroup created in stage 2 is moved
  out of and removed. Stages 3–5 are not undone. A process that has entered a
  namespace or dropped capabilities stays that way, so treat a failed `apply`
  as a reason to exit.
- **A warning** is printed when a user namespace is requested without a mount
  namespace or a jail, because the sandbox cannot then mount its own `/proc` or
  `/dev`.
- **Threads.** Namespaces, seccomp, Landlock and capabilities apply to the
  calling thread. Call `apply` before starting threads. A user namespace cannot
  be created from a multi-threaded process.
- **Seccomp with Landlock.** When both are configured, the syscalls Landlock
  needs (`landlock_*`, `openat`, `close`, `prctl`) are allowed automatically, so
  the seccomp filter cannot kill the process during stage 7.
- **Process-wide effect.** Every stage affects the calling process and anything
  it forks later. The cgroup stays in place after a successful `apply`; the
  process that created it is responsible for removing it.
- **Jail paths.** When a jail is configured, Landlock paths are checked under the
  jail's new root, because the rules are resolved after the pivot. A missing path
  is reported by name.

## Not wired in

`tpt-l-audit-logger` is a standalone reader and is not part of the stages.
Use it directly to watch audit events.

## Known gaps

- Only the calling thread is restricted (see above).
- `NamespaceSet::pid` affects children only. The process that calls `apply` stays
  in its original PID namespace, so it must fork before the namespace has an
  effect. The `tpt-sandbox` CLI does this; a direct user of this crate must too.
- Landlock TCP port rules (ABI 4) are passed through with the rest of the
  `RulesetBuilder`. They are enforced only when set, and `apply` fails on kernels
  without ABI 4.
