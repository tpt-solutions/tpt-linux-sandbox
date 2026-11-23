//! Install the general-purpose seccomp allowlist and check it.
//!
//! The filter is irreversible for this process, so run it on its own.
//! Run with `cargo run -p tpt-l-seccomp-builder --example base_profile`.

use tpt_l_seccomp_builder::{DenyAction, SeccompPolicy};

fn main() {
    // Inspect the profile before loading it. Validation resolves every name
    // and errno without touching the kernel.
    let profile = SeccompPolicy::base_profile();
    profile.validate().expect("base profile is valid");

    // A custom policy is built the same way: allow what you need, pick the
    // default action, and apply it.
    let _custom = SeccompPolicy::new()
        .default_action(DenyAction::Errno(libc::EPERM))
        .allow_syscall("read")
        .allow_syscall("write")
        .allow_syscall("exit_group")
        .deny_syscall("ptrace", DenyAction::Kill);

    profile.apply().expect("seccomp enforcement failed");
    println!("base profile loaded; getpid() = {}", std::process::id());
}
