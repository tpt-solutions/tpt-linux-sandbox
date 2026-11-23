//! Apply a read-only Landlock ruleset to the current process, then show what
//! is still allowed. This is irreversible for the process, so run it on its own.
//!
//! Run with `cargo run -p tpt-l-landlock-highlevel --example readonly_etc`.

use tpt_l_landlock_highlevel::RulesetBuilder;

fn main() {
    RulesetBuilder::new()
        .allow_read("/etc")
        .allow_read("/usr")
        .build()
        .expect("invalid ruleset")
        .apply()
        .expect("Landlock enforcement failed (needs Linux 5.13+)");

    match std::fs::read_to_string("/etc/hostname") {
        Ok(name) => println!("read /etc/hostname: {}", name.trim()),
        Err(e) => println!("read /etc/hostname failed: {e}"),
    }

    match std::fs::write("/tmp/tpt-landlock-example", "hello") {
        Ok(()) => println!("unexpected: wrote to /tmp"),
        Err(e) => println!("write to /tmp denied as expected: {e}"),
    }
}
