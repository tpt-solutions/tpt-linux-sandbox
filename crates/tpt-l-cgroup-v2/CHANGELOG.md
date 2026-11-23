# Changelog

All notable changes to `tpt-l-cgroup-v2` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `CgroupConfig` builder with `cpu_quota`, `memory_limit`, `io_weight` and
  `pids_limit` (`pids.max`).
- `apply`, `enter`, `release` and `destroy` for managing a cgroup v2 group.
- `CgroupConfig::name` and `CgroupConfig::parent`. The parent is the caller's own
  cgroup, read from `/proc/self/cgroup`.
- `CgroupConfig::move_existing_processes`, which lets `apply` move other processes
  of the caller's cgroup into a leaf when controllers can only be enabled that
  way. Off by default.
- `CgroupError` for filesystem and validation failures, including `InvalidName`,
  `AlreadyExists` and `SharedCgroup`.
- Unit tests for clamping, limit storage, name validation and the parent lookup,
  and forked-child tests for create, join and remove. The forked-child tests skip
  without cgroup write access.
- The `limited_group` example.

### Changed

- Groups are created under the caller's own cgroup, not the cgroupfs root. When
  controllers cannot be enabled there, the process moves into a leaf first, as
  systemd delegation expects. The root is used only if that also fails.
- Only the controllers that are missing are enabled.
- Enabling controllers in a cgroup that holds other processes fails with
  `CgroupError::SharedCgroup`, which names the cause, instead of a bare `EBUSY`.

### Fixed

- Names are validated: a single path component without `/` or `..`.
- A directory whose limit write failed is removed.
- A stale group with the same name is refused instead of being reused.
