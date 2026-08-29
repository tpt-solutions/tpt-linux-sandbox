# tpt-linux-sandbox — Todo

> Dual-licensed MIT OR Apache-2.0 · Copyright TPT Solutions · Rust 2024 · MSRV 1.82
> GitHub: https://github.com/TPT-Solutions/tpt-linux-sandbox
> Crate prefix: `tpt-l-*`

---

## Phase 1: Workspace Scaffold ✅

- [x] `Cargo.toml` — workspace root with all 11 members, `[workspace.package]`, `[workspace.dependencies]`
- [x] `LICENSE-MIT`
- [x] `LICENSE-APACHE`
- [x] `NOTICE` — TPT Solutions copyright notice
- [x] `rust-toolchain.toml` — pin stable channel, MSRV 1.82
- [x] `.github/workflows/ci.yml` — `cargo test`, `cargo clippy` on ubuntu-latest
- [x] `README.md` — overview, architecture diagram, state machine table
- [x] Crate skeleton `Cargo.toml` files (all 11 crates)
- [x] Crate skeleton `src/lib.rs` / `src/main.rs` files (all 11 crates)

---

## Phase 2: Core Sandboxing Primitives ✅

### `tpt-l-landlock-highlevel`
- [x] `RulesetBuilder` with `.allow_read()`, `.allow_write()`, `.allow_exec()`
- [x] `.build()` — full validation, no kernel calls
- [x] Runtime Landlock ABI version detection (≥ v1 / Linux 5.13)
- [x] `.apply()` — irreversible enforcement via `landlock` crate

### `tpt-l-seccomp-builder`
- [x] `SeccompPolicy` with `.allow_syscall()`, `.deny_syscall()`, `.default_action()`
- [x] Default-deny policy; explicit allowlist approach
- [x] BPF compilation via `seccompiler`
- [x] `.apply()` — irreversible `seccomp_load`

### `tpt-l-namespaces-rs`
- [x] `NamespaceSet` builder: `.user()`, `.mount()`, `.pid()`, `.network()`
- [x] `unshare(2)` call with correct `CLONE_NEW*` flags
- [x] UID/GID mapping for user namespaces (`/proc/self/uid_map`, `gid_map`)

---

## Phase 3: Resource & Access Control ✅

### `tpt-l-cgroup-v2`
- [x] `CgroupConfig` builder: `.cpu_quota()`, `.memory_limit()`, `.io_weight()`
- [x] Create `/sys/fs/cgroup/<name>/` hierarchy
- [x] Write `cpu.max`, `memory.max`, `io.weight` control files
- [x] `.enter()` — write PID to `cgroup.procs`
- [x] `.destroy()` — rmdir cleanup

### `tpt-l-caps-drop`
- [x] `CapsPolicy` builder: `.drop_all()`, `.keep(cap)`
- [x] Bounding set validation before dropping
- [x] `.apply()` via `caps` crate (permitted, effective, inheritable sets)

### `tpt-l-chroot-jail`
- [x] `JailConfig` builder: `.new_root()`, `.mount_proc()`, `.mount_dev_minimal()`, `.mount_sys_ro()`
- [x] `pivot_root(2)` implementation
- [x] `chroot(2)` fallback with logged warning
- [x] Pseudo-filesystem mounting (`/proc`, minimal `/dev`, `/sys` read-only)

---

## Phase 4: Policy Analysis & Auditing ✅

### `tpt-l-apparmor-parser`
- [x] AppArmor profile textual format parser → typed AST (pure Rust, `nom`)
- [x] Landlock rule emitter for filesystem rules with a direct mapping
- [x] Warning for rules with no Landlock equivalent

### `tpt-l-selinux-context`
- [x] `SecurityContext` struct (`user:role:type:level`)
- [x] `SecurityContext::parse()` from string
- [x] `SecurityContext::current_process()` from `/proc/self/attr/current`
- [x] No `libselinux` dependency

### `tpt-l-audit-logger`
- [x] Open `NETLINK_AUDIT` raw socket
- [x] Bind and receive kernel audit netlink messages
- [x] Parse records into typed `AuditEvent { record_type, fields }`
- [x] `subscribe(buffer)` async fn returning `mpsc::Receiver<AuditEvent>` (Tokio)

---

## Phase 5: Sandbox Orchestrator Library (`tpt-l-sandbox`) ✅

- [x] `Sandbox::new()` top-level builder with per-layer setter methods
- [x] 7-stage state machine in `Sandbox::apply()`:
  1. Validation (no kernel calls)
  2. Cgroup setup + enter
  3. Namespace creation
  4. Filesystem jail (pivot_root / chroot + pseudo-fs)
  5. Capability dropping
  6. Seccomp enforcement *(irreversible)*
  7. Landlock enforcement *(irreversible, last)*
- [x] Full policy validation before any irreversible stage begins
- [x] Clear, descriptive error messages on invalid combinations

---

## Phase 6: CLI (`tpt-l-sandbox-cli`) ✅

- [x] `clap` argument definitions: `--allow-read`, `--allow-write`, `--no-network`, `--memory-limit`, `--cpu-quota`, `--new-root`, `--drop-caps`
- [x] Map CLI flags → `Sandbox` builder calls
- [x] `execvp(2)` the child command after `sandbox.apply()`
- [x] Non-zero exit with descriptive `eprintln!` on any error

---

## Phase 7: Tests, Docs & CI Polish

- [x] Unit tests: `tpt-l-landlock-highlevel` (builder, validation)
- [x] Unit tests: `tpt-l-seccomp-builder` (policy construction)
- [x] Unit tests: `tpt-l-namespaces-rs` (flag bitmask logic)
- [x] Unit tests: `tpt-l-cgroup-v2` (config builder, path construction)
- [x] Unit tests: `tpt-l-caps-drop` (policy builder)
- [x] Unit tests: `tpt-l-chroot-jail` (config builder)
- [x] Unit tests: `tpt-l-apparmor-parser` (parse → AST round-trips)
- [x] Unit tests: `tpt-l-selinux-context` (parse / format)
- [x] Unit tests: `tpt-l-audit-logger` (record parsing)
- [x] Unit tests: `tpt-l-sandbox` (state machine ordering, validation errors)
- [x] Integration test stubs: `tpt-l-sandbox-cli` (Linux-only, 5 tests)
- [x] `#![deny(missing_docs)]` workspace-wide
- [x] Rustdoc for all public APIs
- [x] `clippy::pedantic` lint pass clean (pure-Rust crates)
- [x] `cargo deny` config — license audit + dependency advisory check
- [x] crates.io publish metadata (`keywords`, `categories`, `description`) for all 11 crates

---

## Open Questions (from spec §5)

- [ ] Define default syscall/filesystem allowlist for maintainer-script execution (tpt-deb-toolkit integration)
- [ ] Confirm minimum kernel version matrix for all Landlock ruleset features actually used

---

## Notes

- Pure-Rust crates (`tpt-l-apparmor-parser`, `tpt-l-selinux-context`, `tpt-l-cgroup-v2`) compile and pass tests on Windows.
- Linux-specific crates (`tpt-l-landlock-highlevel`, `tpt-l-seccomp-builder`, `tpt-l-namespaces-rs`, `tpt-l-caps-drop`, `tpt-l-chroot-jail`, `tpt-l-audit-logger`) require Linux to compile (use Linux-only `libc` symbols).
- Integration tests and full CI verification require a Linux environment.
