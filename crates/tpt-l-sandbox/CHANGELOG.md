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
- Validation before any kernel call, including the jail-requires-mount-namespace
  rule.
- Re-exports of the layer types for single-dependency use.
- `SandboxError` for validation and per-layer failures.
- Unit tests for builder composition and the empty sandbox.

### Fixed

- Read the mount-namespace request through `NamespaceSet::has_mount`, because
  the field is crate-private in `tpt-l-namespaces-rs`.
