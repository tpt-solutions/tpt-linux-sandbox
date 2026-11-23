# tpt-l-cgroup-v2

[![crates.io](https://img.shields.io/crates/v/tpt-l-cgroup-v2.svg)](https://crates.io/crates/tpt-l-cgroup-v2)
[![docs.rs](https://docs.rs/tpt-l-cgroup-v2/badge.svg)](https://docs.rs/tpt-l-cgroup-v2)

Create and manage a cgroup v2 hierarchy to limit the CPU, memory, and I/O of a
group of processes. The crate writes directly to the cgroup filesystem, so it
has no dependencies beyond the standard library and `thiserror`.

## Features

- `CgroupConfig` describes a named group and its limits.
- CPU limit as a percentage of one core (`cpu.max`), clamped to 1–100.
- Memory limit in bytes (`memory.max`).
- I/O weight (`io.weight`), clamped to 1–10000. The kernel default is 100.
- Process-count limit (`pids.max`) with `pids_limit`.
- `apply` creates the group under the caller's own cgroup and writes the control
  files. It enables only the controllers that are missing.
- `enter` moves the calling process into the group (`cgroup.procs`).
- `release` moves the caller out of the group, then removes it. `destroy`
  removes the group directory.

## Requirements

- Linux with the **unified cgroup v2 hierarchy** mounted at `/sys/fs/cgroup`.
- Write access to the caller's own cgroup (the directory in
  `/proc/self/cgroup`), where the new group is created. Typically this means
  root, or a systemd-delegated unit (`Delegate=yes`).
- The controllers a configuration uses (`cpu`, `memory`, `io`, `pids`) available
  in the parent group. `apply` enables the missing ones, and a failure surfaces
  as a `CgroupError` from `apply`.
- Rust 1.85 or newer.

## Installation

```toml
[dependencies]
tpt-l-cgroup-v2 = "0.1"
```

## Quick start

```rust,no_run
use tpt_l_cgroup_v2::CgroupConfig;

let cg = CgroupConfig::new("my-sandbox")
    .cpu_quota(50)            // 50% of one core
    .memory_limit(128 << 20)  // 128 MiB
    .io_weight(50);

cg.apply().expect("cgroup setup failed");
cg.enter().expect("failed to join cgroup");

// ... run the restricted work ...

cg.destroy().expect("cgroup cleanup failed");
```

## API overview

| Item | Kind | Purpose |
|---|---|---|
| `CgroupConfig::new(name)` | fn | Start a configuration for a named group. |
| `cpu_quota(percent)` | method | CPU limit, clamped to 1–100. |
| `memory_limit(bytes)` | method | Hard memory limit. |
| `io_weight(weight)` | method | I/O weight, clamped to 1–10000. |
| `pids_limit(max)` | method | Maximum number of processes and threads (`pids.max`). |
| `move_existing_processes()` | method | Let `apply` move other processes of the caller's cgroup into a leaf when needed. Off by default. |
| `name()`, `parent()` | methods | The group name, and the cgroup directory it is created under. |
| `apply(&self)` | method | Create the group and write its limits. |
| `enter(&self)` | method | Move the calling process into the group. |
| `release(&self)` | method | Move the caller out of the group and remove it. |
| `destroy(&self)` | method | Remove the group directory. |
| `CgroupError` | enum | Errors from any filesystem operation, including `InvalidName`, `AlreadyExists` and `SharedCgroup`. |

## Behaviour and limitations

- **Parent is the caller's cgroup.** The group is created under the directory
  the process is in when the `CgroupConfig` is made (`CgroupConfig::parent`),
  not under the cgroupfs root. Custom parents are not supported.
- **Shared cgroups.** Controllers cannot be enabled in a cgroup that also holds
  other processes. The error says so. `move_existing_processes()` moves those
  processes into a leaf (`tpt-sandbox-host`) to make it work; they stay there
  afterwards. It is off by default.
- **Names are checked.** The name must be a single path component without `/`
  or `..` (`InvalidName`).
- **Stale groups are refused.** If a group with the same name already exists,
  `apply` returns `AlreadyExists` rather than reusing it.
- **Cleanup is manual.** The group is not removed on drop. Call `release` or
  `destroy` after all processes have exited. The kernel refuses to remove a group
  that still has processes.
- **Clamping is silent.** Out-of-range values are clamped rather than rejected.
  Read back the values you need if exact limits matter.
- **Limits are per group, not per process.** Every process in the group shares
  the same quota.

## Testing

```sh
cargo test -p tpt-l-cgroup-v2
```

The unit tests check the CPU quota arithmetic, the clamping of CPU and I/O
values, name validation and the stored limits. They do not create cgroups, so
they need no privileges. Forked-child tests create, join and remove a group. They
skip when the caller has no cgroup write access.

## Minimum supported Rust version

Rust 1.85, inherited from the workspace.

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE), at your option.

Part of the [tpt-linux-sandbox](https://github.com/TPT-Solutions/tpt-linux-sandbox) workspace.
