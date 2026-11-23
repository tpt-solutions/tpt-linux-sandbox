//! Enter a new user and mount namespace, then show the identity inside it.
//!
//! Run with `cargo run -p tpt-l-namespaces-rs --example enter_namespaces`.
//! This changes the calling process, so the example runs as its own program.

use tpt_l_namespaces_rs::NamespaceSet;

fn main() {
    NamespaceSet::new()
        .user()
        .mount()
        .apply()
        .expect("namespace setup failed (needs unprivileged user namespaces)");

    println!("uid inside the namespace: {}", nix::unistd::getuid());
}
