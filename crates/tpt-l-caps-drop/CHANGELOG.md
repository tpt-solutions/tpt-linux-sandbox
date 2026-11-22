# Changelog

All notable changes to `tpt-l-caps-drop` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `CapsPolicy` builder with `new`, `drop_all`, `keep`, and `apply`.
- Case-insensitive acceptance of full and short capability names.
- `CapsError` with `UnknownCap` and `Operation` variants.
- Unit tests for the default policy and keep-list accumulation.
