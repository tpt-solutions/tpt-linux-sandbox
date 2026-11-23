//! Run a child process under a sandbox without restricting this program.
//!
//! Only the child is restricted: `sandboxed` applies the policy between fork
//! and exec. Run with `cargo run -p tpt-l-sandbox --example sandboxed_command`.

use std::process::Command;

use tpt_l_landlock_highlevel::RulesetBuilder;
use tpt_l_sandbox::{CommandSandboxExt, Sandbox};

fn main() -> std::io::Result<()> {
    // The child may read /etc, and may read and execute from /usr. Execute
    // rights are needed for the command itself and the libraries it loads.
    // The library does not add these for you; the CLI does.
    let sandbox = Sandbox::new().landlock(
        RulesetBuilder::new()
            .allow_read("/etc")
            .allow_read("/usr")
            .allow_exec("/usr"),
    );

    let status = Command::new("/bin/cat")
        .arg("/etc/hostname")
        .sandboxed(sandbox)
        .status()?;

    println!("child exited with {status}");
    Ok(())
}
