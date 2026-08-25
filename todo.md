# tpt-linux-sandbox — Todo

> Dual-licensed MIT OR Apache-2.0 · Copyright TPT Solutions · Rust 2024 · MSRV 1.82
> GitHub: https://github.com/TPT-Solutions/tpt-linux-sandbox
> Crate prefix: `tpt-l-*`

---

## Phase 1: Workspace Scaffold

- [ ] `Cargo.toml` — workspace root with all 11 members, `[workspace.package]`, `[workspace.dependencies]`
- [ ] `LICENSE-MIT`
- [ ] `LICENSE-APACHE`
- [ ] `NOTICE` — TPT Solutions copyright notice
- [ ] `rust-toolchain.toml` — pin stable channel, MSRV 1.82
- [ ] `.github/workflows/ci.yml` — `cargo test`, `cargo clippy` on ubuntu-latest
- [ ] `README.md` — overview, architecture diagram, state machine table
- [ ] Crate skeleton `Cargo.toml` files (all 11 crates)
- [ ] Crate skeleton `src/lib.rs` / `src/main.rs` files (all 11 crates)

---

## Phase 2: Core Sandboxing Primitives

### `tpt-l-landlock-highlevel`
- [ ] `RulesetBuilder` with `.allow_read()`, `.allow_write()`, `.allow_exec()`
- [ ] `.build()` — full validation, no kernel calls
- [ ] Runtime Landlock ABI version detection (≥ v1 / Linux 5.13)
- [ ] `.apply()` — irreversible enforcement via `landlock` crate

### `tpt-l-seccomp-builder`
- [ ] `SeccompPolicy` with `.allow_syscall()`, `.deny_syscall()`, `.default_action()`
- [ ] Default-deny policy; explicit allowlist approach
- [ ] BPF compilation via `seccompiler`
- [ ] `.apply()` — irreversible `seccomp_load`

### `tpt-l-namespaces-rs`
- [ ] `NamespaceSet` builder: `.user()`, `.mount()`, `.pid()`, `.network()`
- [ ] `unshare(2)` call with correct `CLONE_NEW*` flags
- [ ] UID/GID mapping for user namespaces (`/proc/self/uid_map`, `gid_map`)

---

## Phase 3: Resource & Access Control

### `tpt-l-cgroup-v2`
- [ ] `CgroupConfig` builder: `.cpu_quota()`, `.memory_limit()`, `.io_weight()`
- [ ] Create `/sys/fs/cgroup/<name>/` hierarchy
- [ ] Write `cpu.max`, `memory.max`, `io.weight` control files
- [ ] `.enter()` — write PID to `cgroup.procs`
- [ ] `.destroy()` — rmdir cleanup

### `tpt-l-caps-drop`
- [ ] `CapsPolicy` builder: `.drop_all()`, `.keep(cap)`
- [ ] Bounding set validation before dropping
- [ ] `.apply()` via `caps` crate (permitted, effective, inheritable sets)

### `tpt-l-chroot-jail`
- [ ] `JailConfig` builder: `.new_root()`, `.mount_proc()`, `.mount_dev_minimal()`, `.mount_sys_ro()`
- [ ] `pivot_root(2)` implementation
- [ ] `chroot(2)` fallback with logged warning
- [ ] Pseudo-filesystem mounting (`/proc`, minimal `/dev`, `/sys` read-only)

---

## Phase 4: Policy Analysis & Auditing

### `tpt-l-apparmor-parser`
- [ ] AppArmor profile textual format parser → typed AST (pure Rust, `nom` or hand-rolled)
- [ ] Landlock rule emitter for filesystem rules with a direct mapping
- [ ] Warning for rules with no Landlock equivalent

### `tpt-l-selinux-context`
- [ ] `SecurityContext` struct (`user:role:type:level`)
- [ ] `SecurityContext::parse()` from string
- [ ] `SecurityContext::current_process()` from `/proc/self/attr/current`
- [ ] No `libselinux` dependency

### `tpt-l-audit-logger`
- [ ] Open `NETLINK_AUDIT` raw socket
- [ ] Bind and receive kernel audit netlink messages
- [ ] Parse records into typed `AuditEvent { record_type, fields }`
- [ ] `subscribe(buffer)` async fn returning `mpsc::Receiver<AuditEvent>` (Tokio)

---

## Phase 5: Sandbox Orchestrator Library (`tpt-l-sandbox`)

- [ ] `Sandbox::new()` top-level builder with per-layer setter methods
- [ ] 7-stage state machine in `Sandbox::apply()`:
  1. Validation (no kernel calls)
  2. Cgroup setup + enter
  3. Namespace creation
  4. Filesystem jail (pivot_root / chroot + pseudo-fs)
  5. Capability dropping
  6. Seccomp enforcement *(irreversible)*
  7. Landlock enforcement *(irreversible, last)*
- [ ] Full policy validation before any irreversible stage begins
- [ ] Clear, descriptive error messages on invalid combinations

---

## Phase 6: CLI (`tpt-l-sandbox-cli`)

- [ ] `clap` argument definitions: `--allow-read`, `--allow-write`, `--no-network`, `--memory-limit`, `--cpu-quota`, `--new-root`, `--drop-caps`
- [ ] Map CLI flags → `Sandbox` builder calls
- [ ] `exec(2)` the child command after `sandbox.apply()`
- [ ] Non-zero exit with descriptive `eprintln!` on any error

---

## Phase 7: Tests, Docs & CI Polish

- [ ] Unit tests: `tpt-l-landlock-highlevel` (builder, validation)
- [ ] Unit tests: `tpt-l-seccomp-builder` (policy construction)
- [ ] Unit tests: `tpt-l-namespaces-rs` (flag bitmask logic)
- [ ] Unit tests: `tpt-l-cgroup-v2` (config builder, path construction)
- [ ] Unit tests: `tpt-l-caps-drop` (policy builder)
- [ ] Unit tests: `tpt-l-chroot-jail` (config builder)
- [ ] Unit tests: `tpt-l-apparmor-parser` (parse → AST round-trips)
- [ ] Unit tests: `tpt-l-selinux-context` (parse / format)
- [ ] Unit tests: `tpt-l-audit-logger` (record parsing)
- [ ] Unit tests: `tpt-l-sandbox` (state machine ordering, validation errors)
- [ ] Integration test: `tpt-l-sandbox-cli --allow-read /etc -- cat /etc/hostname` succeeds
- [ ] Integration test: `tpt-l-sandbox-cli --allow-read /etc -- cat /tmp/secret` fails/blocked
- [ ] `#![deny(missing_docs)]` workspace-wide
- [ ] Rustdoc for all public APIs
- [ ] `clippy::pedantic` lint pass clean
- [ ] `cargo deny` config — license audit + dependency advisory check
- [ ] crates.io publish metadata (`keywords`, `categories`, `description`) for all 11 crates

---

## Open Questions (from spec §5)

- [ ] Define default syscall/filesystem allowlist for maintainer-script execution (tpt-deb-toolkit integration)
- [ ] Confirm minimum kernel version matrix for all Landlock ruleset features actually used
