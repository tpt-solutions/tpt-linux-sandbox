# Changelog

All notable changes to `tpt-l-cgroup-v2` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `CgroupConfig` builder with `cpu_quota`, `memory_limit`, and `io_weight`.
- `apply`, `enter`, and `destroy` for managing a cgroup v2 group under
  `/sys/fs/cgroup`.
- `CgroupError` for filesystem and validation failures.
- Unit tests for clamping and limit storage.
