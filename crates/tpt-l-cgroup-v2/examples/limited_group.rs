//! Create a cgroup with a process limit, join it, and show the membership.
//!
//! Needs write access to /sys/fs/cgroup and the `memory` and `pids` controllers
//! delegated to this user (root, or a systemd unit with `Delegate=yes`).
//! Run with `cargo run -p tpt-l-cgroup-v2 --example limited_group`.

use tpt_l_cgroup_v2::CgroupConfig;

fn main() {
    let name = format!("tpt-cgroup-example-{}", std::process::id());
    let cg = CgroupConfig::new(name)
        .pids_limit(64)
        .memory_limit(256 << 20);

    if let Err(e) = cg.apply() {
        eprintln!("cannot create the limited cgroup here: {e}");
        eprintln!("the memory and pids controllers must be delegated; run `tpt-sandbox --doctor`");
        return;
    }
    if let Err(e) = cg.enter() {
        eprintln!("failed to join the cgroup: {e}");
        let _ = cg.release();
        return;
    }

    let procs = std::fs::read_to_string(format!("/sys/fs/cgroup/{}/cgroup.procs", cg.name()))
        .unwrap_or_default();
    println!("processes in the group: {}", procs.trim());

    // The group must be empty before it can be removed, so leave it first.
    if let Err(e) = cg.release() {
        eprintln!("failed to remove the cgroup: {e}");
    }
}
