# Changelog

All notable changes to `tpt-l-sandbox` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `Sandbox` builder with `namespaces`, `cgroup`, `jail`, `caps`, `seccomp`,
  and `landlock` layers.
- `apply` running the seven documented stages in order, with irreversible
  stages last.
- `Sandbox::validate`, which checks syscall names, errnos, Landlock paths and
  the jail/namespace rule without changing kernel state.
- `CommandSandboxExt::sandboxed`, which sandboxes a `std::process::Command`
  child between fork and exec.
- Re-exports of the layer types for single-dependency use.
- `SandboxError` for validation and per-layer failures.
- The `sandboxed_command` example.

### Changed

- When a jail is configured, Landlock paths are validated under the jail's new
  root, and a missing path is reported by name.
- `validate` runs before any stage, so a configuration error is reported before
  anything changes.

### Fixed

- Read the mount-namespace request through `NamespaceSet::has_mount`, because
  the field is crate-private in `tpt-l-namespaces-rs`.
- The cgroup created in stage 2 is released if a later stage fails.
- Seccomp and Landlock are no longer applied in an order that kills the process
  during Landlock setup. Landlock's setup syscalls are allowed under the seccomp
  filter.
- Warns when a user namespace is requested without a mount namespace (the
  warning was documented but never printed).
