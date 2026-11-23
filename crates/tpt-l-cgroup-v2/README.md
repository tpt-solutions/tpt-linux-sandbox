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
- `apply` creates the group directory and writes the control files.
- `enter` moves the calling process into the group (`cgroup.procs`).
- `destroy` removes the group directory.

## Requirements

- Linux with the **unified cgroup v2 hierarchy** mounted at `/sys/fs/cgroup`.
- Write access to the caller's own cgroup (the directory in
  `/proc/self/cgroup`), where the new group is created. Typically this means
  root, or a systemd-delegated unit (`Delegate=yes`).
- The relevant controllers (`cpu`, `memory`, `io`) enabled for the parent
  group. Missing controllers surface as `CgroupError` values from `apply`.
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
| `apply(&self)` | method | Create the group and write its limits. |
| `enter(&self)` | method | Move the calling process into the group. |
| `destroy(&self)` | method | Remove the group directory. |
| `CgroupError` | enum | Errors from any filesystem operation. |

## Behaviour and limitations

- **Parent is the caller's cgroup.** The group is created under the directory
  the process is in when the `CgroupConfig` is made (`CgroupConfig::parent`),
  not under the cgroupfs root. Custom parents are not supported.
- **Cleanup is manual.** The group is not removed on drop. Call `destroy`
  after all processes have exited. The kernel refuses to remove a group that
  still has processes.
- **Clamping is silent.** Out-of-range values are clamped rather than rejected.
  Read back the values you need if exact limits matter.
- **Limits are per group, not per process.** Every process in the group shares
  the same quota.

## Testing

```sh
cargo test -p tpt-l-cgroup-v2
```

The unit tests check the CPU quota arithmetic, the clamping of CPU and I/O
values, and that memory limits are stored. They do not create cgroups, so they
need no privileges.

## Minimum supported Rust version

Rust 1.85, inherited from the workspace.

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE), at your option.

Part of the [tpt-linux-sandbox](https://github.com/TPT-Solutions/tpt-linux-sandbox) workspace.
