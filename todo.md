# tpt-linux-sandbox — Todo

> Dual-licensed MIT OR Apache-2.0 · Copyright TPT Solutions · Rust 2024 · MSRV 1.85
> GitHub: https://github.com/TPT-Solutions/tpt-linux-sandbox
> Crate prefix: `tpt-l-*`

Status key: `[x]` done · `[ ]` not done (reason given) · **verified** = ran in a Linux container (privileged root and unprivileged UID 1000, kernel 6.18, debug and release builds; 22 test suites, all ignored tests included) · **checked** = type-checked and clippy-clean for the target (Linux x86_64, aarch64, riscv64), not run.

---

## Phase 1: Workspace Scaffold

- [x] `Cargo.toml` — workspace root with all 11 members, `[workspace.package]`, `[workspace.dependencies]`
- [x] `LICENSE-MIT`, `LICENSE-APACHE`, `NOTICE`
- [x] `rust-toolchain.toml` — pin stable channel
- [x] `.github/workflows/ci.yml` — see Phase 9
- [x] `README.md` — rewritten to match the code (Phase 10)
- [x] Crate skeletons (all 11 crates)

---

## Phase 2: Core Sandboxing Primitives

### `tpt-l-landlock-highlevel`
- [x] `RulesetBuilder` with `.allow_read()`, `.allow_write()`, `.allow_exec()`
- [x] `.build()` — opens every path to confirm it exists (no enforcement) — **verified** (unit test)
- [x] ABI v3 filesystem rights (`Refer`, `Truncate`), `RemoveDir`; best-effort on older kernels — **verified** (CLI tests)
- [x] `require_full_enforcement()` — opt-in error on partial enforcement — **checked**
- [x] **ABI 4 — TCP bind and connect port rules** (`allow_tcp_bind`, `allow_tcp_connect`). Explicit port rules are a hard requirement: on kernels before 6.7, `apply` fails with a clear error — **verified** (denial test on 6.18)
- [x] **ABI 6 — scoped abstract Unix sockets and signals** (`isolate_abstract_sockets_and_signals`), best-effort, on by default in the CLI — **checked** (applied on 6.18; not separately tested against a second process)
- [x] Forked-child regression test: the allowlist holds for a child — **verified** (root and unprivileged)
- [ ] ABI 5 (ioctl on devices) — not added; no use case in the CLI yet

### `tpt-l-seccomp-builder`
- [x] `SeccompPolicy` with `.allow_syscall()`, `.deny_syscall()`, `.default_action()`
- [x] `deny_syscall` enforced: each deny action goes into its own filter loaded before the allowlist — **checked** (the deny path itself has no runtime test)
- [x] `Errno` range validated (1–4095) — **verified** (unit test)
- [x] Syscall table (~135 names); every name confirmed against `libc` for x86_64, aarch64 and riscv64 — **checked** (`cargo check` and clippy for aarch64 and riscv64)
- [x] **riscv64**: `renameat` does not exist there, so the shared table uses `renameat2` and adds `renameat` only where it exists — **checked**
- [x] `base_profile()` — general-purpose allowlist; `ptrace` returns EPERM — **verified** (forked-child test)
- [x] `validate()` — resolves names before any irreversible stage — **verified**

### `tpt-l-namespaces-rs`
- [x] `NamespaceSet` builder: `.user()`, `.mount()`, `.pid()`, `.network()`
- [x] `unshare(2)` with correct `CLONE_NEW*` flags
- [x] **uid/gid read before `unshare`** — fixes the `uid_map` write — **verified** (forked-child test, root and unprivileged)
- [x] `MultiThreaded` error for user namespaces from a multi-threaded process — **verified** (unit test on thread counting)
- [x] PID namespace: children-only, documented; the CLI forks once more so the command is PID 1 (see Phase 6). Reaping of orphans is left to the command, as with any init process — **verified** (`pid = 1` integration test)

---

## Phase 3: Resource & Access Control

### `tpt-l-cgroup-v2`
- [x] `CgroupConfig` builder: `.cpu_quota()`, `.memory_limit()`, `.io_weight()`, `.pids_limit()`, `.name()`
- [x] Name validated: one path component, no `/`, `..` or NUL — **verified** (unit tests)
- [x] `mkdir` (no reuse of stale directories); `AlreadyExists` reported — **verified**
- [x] Only missing controllers are written to `cgroup.subtree_control` — **verified**
- [x] `memory.swap.max = 0` with the memory limit; `pids.max` — **checked**
- [x] `.enter()`, `.destroy()`, `.release()` — **verified** (forked-child create, enter, release test, root; skips when the user cannot create cgroups)

### `tpt-l-caps-drop`
- [x] `CapsPolicy` builder: `.drop_all()`, `.keep(cap)`
- [x] Bounding dropped first; ambient cleared; securebits locked; inheritable cleared; `no_new_privs` set — **verified** (forked-child test, root and unprivileged)
- [x] **Fixed a release-only bug**: `prctl(2)` takes five arguments and the wrapper passed four, so `PR_CAP_AMBIENT` failed with EINVAL in release builds. Errors now name the failing step — **verified** (release suite)
- [x] `keep()` without `drop_all()` is an error — **verified** (unit test)

### `tpt-l-chroot-jail`
- [x] `JailConfig` builder: `.new_root()`, `.mount_proc()`, `.mount_dev_minimal()`, `.mount_sys_ro()`, `.allow_chroot_fallback()`
- [x] Mount tree made private before any mount or pivot; `pivot_root(".", ".put_old")` — **verified** (forked-child pivot test, root and unprivileged)
- [x] `chroot` fallback is opt-in — **checked**
- [x] `/dev` is a tmpfs with bind-mounted `null`, `zero`, `random`, `urandom`, `tty` only — **checked**
- [x] Symlinks refused when creating mount points — **verified** (unit test)
- [x] Proc mounted `nosuid,nodev,noexec`; `umount` failure is fatal — **checked**

---

## Phase 4: Policy Analysis & Auditing

### `tpt-l-apparmor-parser`
- [x] AppArmor parser → typed AST (hand-rolled); portable (builds on every platform) — **verified**
- [x] Nested profiles rejected; unterminated or unexpected braces rejected — **verified**
- [x] Several rules per line; quoted paths (with `#` and spaces); `@{VAR}` expansion; undefined variables rejected — **verified**
- [x] `deny` rules never become grants — **verified**
- [x] `networkfoo` is not a network rule; unknown permission characters rejected — **verified**
- [x] No `eprintln!` in library code; `unmapped_rules()` returns the rules not converted
- [x] Example: `cargo run -p tpt-l-apparmor-parser --example convert_profile` — **checked** (compiled)

### `tpt-l-selinux-context`
- [x] `SecurityContext` parse; rejects empty fields, whitespace and control characters — **verified**
- [x] `current_process()` distinguishes a missing attr file (`NotEnabled`) from a read error — **verified** (via `--doctor` on a non-SELinux system)

### `tpt-l-audit-logger`
- [x] `NETLINK_AUDIT` socket; bind to the audit group; `EPERM` mapped to `PermissionDenied`
- [x] Sender checked (`nl_pid == 0`); `MSG_TRUNC` detects truncated datagrams
- [x] Netlink header read unaligned; every message in a datagram parsed with `NLMSG_ALIGN`; malformed lengths stop the scan — **verified** (unit tests)
- [x] Receive errors delivered through the channel; reader stops within ~0.5 s of the receiver being dropped
- [x] `subscribe` returns `Result<AuditEvent, AuditError>` items (API change)
- [x] Live subscription test — **verified**: subscribes as root; as an unprivileged user it reports a skip (no `CAP_AUDIT_READ`)
- [ ] Example for the live stream — `tail_audit` compiles; not run (needs `CAP_AUDIT_READ`)

---

## Phase 5: Sandbox Orchestrator Library (`tpt-l-sandbox`)

- [x] `Sandbox::new()` builder with per-layer setter methods (`Clone`)
- [x] 7-stage order in `apply()`; cgroup released if a later stage fails
- [x] `validate()` (public) before any stage: jail/mount rule, seccomp names and errnos, Landlock paths — **verified**
- [x] Landlock setup syscalls allowed automatically when seccomp is applied first — **verified** (CLI runs)
- [x] Warning for user namespaces without a mount namespace
- [x] `CommandSandboxExt::sandboxed()` — sandbox a child process between fork and exec — **verified** (`sandboxed_command` example run)
- [x] Audit logger is not wired in; README says so

---

## Phase 6: CLI (`tpt-l-sandbox-cli`)

- [x] Flags: `--allow-read`, `--allow-write`, `--allow-exec`, `--no-system-paths`, `--no-network`, `--memory-limit`, `--cpu-quota`, `--pids-limit`, `--new-root`, `--cwd`, `--drop-caps`, `--seccomp`, `--pass-env`, `--json`, `--dry-run`, `--doctor`, `--learn`, `--print-profile`, `--from-apparmor`
- [x] **PID namespace by default**: the command is PID 1 of its own namespace. The namespace-creating process forks once more and relays the exit status; signal deaths are explained by the relay (it cannot re-raise a signal, because `tgkill` is not in the allowlist) — **verified** (`cli_runs_command_as_pid_one_by_default`, `cli_share_pids_keeps_host_pid_space`)
- [x] **IPC isolation by default** (`--share-ipc` turns it off) — **checked** (applied on 6.18)
- [x] **TCP port rules**: `--allow-tcp-bind`, `--allow-tcp-connect` — **verified** (`cli_tcp_allowlist_denies_other_ports`: connect to port 9 is denied with EACCES)
- [x] Fork before any restriction; the parent waits, removes the cgroup, and reports the exit — **verified**
- [x] Exit reporting: signals, SIGSYS and SIGKILL explained; `--json` event — **verified**
- [x] Child: environment cleared — **verified**; `setsid` and closing descriptors 3+ — **checked** (no runtime test)
- [x] Argument values validated, not clamped — **verified**
- [x] Integration tests check output and exit status; negative tests assert setup succeeded — **verified** (root and unprivileged)
- [x] Seccomp enforced by default (base profile); `--seccomp log` and `off` — **verified**
- [x] **Built-in profiles no longer set cgroup limits**, because limits need delegation and made `--profile strict` fail on most machines — **verified** (`--profile strict` runs in a container without delegation)

---

## Phase 7: Tests, Docs & CI Polish

- [x] Unit tests for every library crate and the CLI policy and tools modules — **verified**
- [x] Forked-child regression tests (ignored by default, run with `--include-ignored`): namespaces, caps, seccomp, cgroup, jail, Landlock — **verified** (root and unprivileged; skips where a privilege is missing, and says so)
- [x] Integration tests: hostname read; `/tmp` read denied; `--no-network` blocks connect; memory limit kills (skipped without a usable cgroup); `mount` blocked after `--drop-caps`; env scrubbing; `--pass-env`; JSON exit; validation; dry-run; print-profile; unknown profile; PID 1; `--share-pids`; TCP port denial — **verified**
- [x] `missing_docs` and `unsafe_op_in_unsafe_fn` warn — `[workspace.lints.rust]`
- [x] `clippy::pedantic` warn, with four deliberate allows (builder `must_use`, boolean structs, `# Errors` sections, doc prose) — **checked**: clean with `-D warnings` on x86_64, aarch64 and riscv64
- [x] Rustdoc for public APIs; examples for the main crates (Phase 10)
- [x] `cargo deny` config — `deny.toml`; CI job configured, not run
- [x] Publish metadata (`keywords`, `categories`, `description`, `version` on path dependencies)

---

## Phase 8: Correctness Fixes (from platform review, 2026-11-23)

> Found by source reading. Each item has a regression test or a note on how it was checked.

- [x] **namespaces-rs** — uid/gid read before `unshare` — **verified**
- [x] **sandbox-cli** — `--allow-exec`; system directories grant read and exec by default — **verified**
- [x] **sandbox-cli tests** — assertions check output and exit codes; `--no-network` tries a real connect — **verified**
- [x] **caps-drop** — bounding, ambient, securebits, `no_new_privs`; `keep()` without `drop_all()` is an error — **verified**; release-build EINVAL fixed (see Phase 3)
- [x] **chroot-jail** — private mounts before `pivot_root`; opt-in `chroot`; tmpfs `/dev`; symlink-safe mount points — **verified** (pivot test) / **checked**
- [x] **cgroup-v2** — name validated; `subtree_control` (missing controllers only); `pids.max`; `memory.swap.max`; no reuse of stale directories — **verified**
- [x] **cgroup lifecycle** — `release()` on failure and CLI cleanup after the child exits — **verified**
- [x] **seccomp-builder** — `deny_syscall` enforced — **checked**; `Errno` validated — **verified**; table expanded and checked on three architectures — **checked**
- [x] **seccomp-builder** — `landlock_*` syscalls allowed when seccomp runs first — **verified**
- [x] **seccomp (CLI)** — default is the base allowlist — **verified**
- [x] **sandbox `validate()`** — before stage 2 — **verified**
- [x] **landlock-highlevel** — `PartiallyEnforced` rejected only with `require_full_enforcement()`; ABI v3 rights; `RemoveDir`; **port rules fail on kernels without ABI 4** — **verified**
- [x] **sandbox-cli hygiene** — `close_range`, env scrub with `--pass-env`, `setsid`, working directory; invalid limits rejected — **verified**
- [x] **audit-logger** — unaligned read; multi-message datagrams; sender check; errors surfaced; `EPERM` mapped — **verified**
- [x] **apparmor-parser** — nested profiles, unterminated blocks, multi-rule lines, `@{VAR}`, no `eprintln!`, `networkfoo`, unknown permission characters — **verified**
- [x] **threading** — documented; `MultiThreaded` error for user namespaces — **verified**
- [x] **selinux-context** — permission-denied vs not-enabled distinguished; empty fields rejected — **verified**
- [x] **sandbox docs** — audit-logger and stage-2 rollback claims corrected

---

## Phase 9: Housekeeping & CI

- [x] Portable build: `default-members` lists the portable crates — **checked** on Windows
- [x] `version = "0.1.0"` on every path dependency; `apparmor-parser`, `selinux-context` in `[workspace.dependencies]`
- [x] `homepage` — not added: `repository` already provides the link
- [x] `exclude` / `include` — **checked** with `cargo package --list` for `tpt-l-sandbox` and `tpt-l-sandbox-cli`: the package lists contain only the crate's files, and the CLI includes the profiles it embeds. No rule is needed.
- [x] `unsafe_op_in_unsafe_fn` lint
- [x] CI: `cargo deny check` job — configured, not run
- [x] CI: MSRV job (1.85) — configured, not run; some dependency releases may need a newer compiler
- [x] CI: docs job (`cargo doc` with `-D warnings`) — configured, not run
- [x] CI: unprivileged test job (userns sysctl on Ubuntu 24.04) and privileged (root) job — configured, not run; both pass locally in the container
- [x] CI: clippy with `--all-targets -D warnings` — clean locally
- [x] CI: macOS and Windows `cargo check` of the portable crates — configured, not run
- [x] `.github/workflows/ci.yml` and `release.yml` parse as YAML — **verified**
- [x] Forked-child tests for namespaces, caps, seccomp, cgroup, jail and Landlock — **verified**
- [x] Negative-input tests: cgroup name, Errno range, nested and unterminated AppArmor, multi-rule lines, malformed and multipart netlink, symlink mount point
- [x] Table test: every syscall name is unique
- [x] Release workflow (`release.yml`): static musl binaries for x86_64 and aarch64 on version tags — configured, not run
- [ ] Publish crates to crates.io in dependency order — **excluded at your request**

---

## Phase 10: Adoption — Presets, Examples, Docs, Packaging

### Profiles & policy files
- [x] `--profile <name>` with six built-in TOML profiles — **verified**; they set no cgroup limits, so they work without delegation
- [x] `--policy <file>` with the same schema; `schemas/policy.schema.json` — **verified** (parses; deserialization rejects unknown fields)
- [x] Schema covers `pid_namespace`, `isolate_ipc`, `allow_tcp_bind`, `allow_tcp_connect`
- [x] Deviation: `init --profile` became `--print-profile <name> > file`, because the CLI has a trailing command

### Examples & templates
- [x] Examples for the eight main crates (`cargo run -p <crate> --example <name>`) — **verified** to compile; **run**: `sandboxed_command`, `enter_jail` (root and unprivileged)
- [x] `chroot-jail` example: `enter_jail` — **verified**
- [x] Not run (they change the calling process or need a privilege): `readonly_etc`, `base_profile`, `enter_namespaces`, `drop_caps`, `limited_group`, `tail_audit`, `convert_profile`. Each example says what it needs.
- [x] `templates/` — GitHub Actions workflow, systemd unit with `Delegate=yes`, Dockerfile, devcontainer
- [x] Policy cookbook — `docs/policy-cookbook.md`

### Docs
- [x] `docs/quick-start.md`
- [x] `docs/kernel-matrix.md` — ABI 4 and ABI 6 rows now describe what the CLI uses; minimums from kernel documentation, not measured
- [x] `docs/troubleshooting.md`
- [x] `docs/threat-model.md` — updated for the PID namespace, IPC isolation and TCP rules

### Distribution
- [x] **`.deb`** — built with `cargo deb` in a container. Asset paths for the binary and profiles are correct. Dependency: `libc6 (>= 2.39)`, from the build machine's glibc. **verified**
- [x] `cargo-binstall` metadata in the CLI manifest — the `pkg-url` and `bin-dir` match the release workflow's archive names; the remote download is not run — **checked**
- [x] `install.sh` — `sh -n` syntax check passes — **checked**; the download is not run (no release yet)
- [x] **GitHub Action** command step simulated locally with the strict profile — **verified**; the action itself has not run on GitHub
- [ ] Nix flake (`flake.nix`) — **untested**: Nix is not available here
- [ ] Docker image — `templates/Dockerfile` downloads a release that does not exist yet, so it cannot be built until `v0.1.0` is released
- [x] One-line install in the README

---

## Phase 11: Usability & Innovation

- [x] `--doctor` — kernel, WSL, user namespaces, AppArmor userns restriction, Landlock LSM, seccomp actions, cgroup controllers (per controller), SELinux context — **verified**
- [x] `--learn` — runs the command under `strace` and prints a draft policy — **partly verified**: the missing-`strace` error path is tested; parsing is unit-tested; a full run needs `strace`
- [x] `--dry-run` / `--explain` — shows namespaces (including pid), IPC, TCP rules, per-layer policy — **verified**
- [x] `--json` — exit event with the reason for signals — **verified**
- [ ] Landlock denials reported as events — **not done, by recommendation**: the supervising parent cannot see Landlock denials; they need the audit stream and `CAP_AUDIT_READ`. Revisit if audit-based reporting is wanted.
- [x] `--from-apparmor <file>` — maps file rules; warns on widened globs and unmapped rules — **verified**
- [x] SELinux — `--doctor` reports the process context; the sandbox does not check or set contexts. Sufficient for the current scope.
- [x] `std::process::Command` extension (`CommandSandboxExt::sandboxed`) — **verified** (example)
- [ ] `build.rs` helper — **not built, by recommendation**: `CommandSandboxExt` covers the same use without a build step
- [x] GitHub Action (`action.yml`) — **verified** locally (command step); not run on GitHub
- [x] Landlock ABI 4 (TCP) — see Phase 2
- [x] Landlock ABI 6 (scoped abstract sockets and signals) — see Phase 2

---

## Open Questions (from spec §5)

- [x] Default syscall and filesystem allowlist for maintainer scripts — proposed as the `maintainer-script` profile. **Needs review** against tpt-deb-toolkit's real scripts.
- [x] Minimum kernel version matrix — `docs/kernel-matrix.md`. Based on kernel documentation, not measured.

---

## Not verified yet (run before relying on it)

- CI workflows (`ci.yml`, `release.yml`) have not run on GitHub.
- `install.sh` download, `cargo binstall` download and the composite action have not run against a real release.
- Nix flake: untested. Docker image: not built (needs a published release).
- Landlock ABI 6 scoping has not been tested with two processes across a domain boundary.
- The release-mode suite ran as root only; the unprivileged suite ran in debug only.
