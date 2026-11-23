//! Build a tiny rootfs, pivot into it, and show what the process can see.
//!
//! The process needs a user and mount namespace first; this example creates
//! them itself, so it runs without root. The pivot is irreversible for this
//! process, so the example is a standalone program.
//!
//! Run with `cargo run -p tpt-l-chroot-jail --example enter_jail`.
//! The temporary rootfs stays in the host's temp directory afterwards, because
//! the process cannot reach it once it has pivoted.

use tpt_l_chroot_jail::JailConfig;

fn main() {
    let root = std::env::temp_dir().join(format!("tpt-jail-example-{}", std::process::id()));
    std::fs::create_dir_all(&root).expect("create rootfs");
    std::fs::write(root.join("hello.txt"), "inside the jail\n").expect("write marker");

    // SAFETY: unshare has no memory-safety preconditions. This example is
    // single-threaded at this point.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } != 0 {
        eprintln!("cannot create user and mount namespaces");
        std::process::exit(1);
    }

    JailConfig::new(&root).apply().expect("jail setup failed");

    println!("entries visible at /:");
    for entry in std::fs::read_dir("/").expect("read /") {
        let name = entry.expect("dir entry").file_name();
        println!("  {}", name.to_string_lossy());
    }
    let hello = std::fs::read_to_string("/hello.txt").expect("read marker");
    print!("/hello.txt: {hello}");
}
