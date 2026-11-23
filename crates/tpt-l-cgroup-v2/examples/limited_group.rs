//! Create a cgroup with a process limit, join it, and show the membership.
//!
//! Needs write access to /sys/fs/cgroup (root, or a systemd unit with
//! `Delegate=yes`). Run with `cargo run -p tpt-l-cgroup-v2 --example limited_group`.

use tpt_l_cgroup_v2::CgroupConfig;

fn main() {
    let name = format!("tpt-cgroup-example-{}", std::process::id());
    let cg = CgroupConfig::new(name)
        .pids_limit(64)
        .memory_limit(256 << 20);

    cg.apply().expect("cgroup setup failed");
    cg.enter().expect("failed to join the cgroup");

    let procs = std::fs::read_to_string(format!("/sys/fs/cgroup/{}/cgroup.procs", cg.name()))
        .expect("read cgroup.procs");
    println!("processes in the group: {}", procs.trim());

    // The group must be empty before it can be removed, so leave it first.
    cg.release().expect("failed to remove the cgroup");
}
