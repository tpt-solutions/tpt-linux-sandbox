//! Drop every capability except CAP_NET_BIND_SERVICE, then show the result.
//!
//! Run with `cargo run -p tpt-l-caps-drop --example drop_caps`.
//! Dropping the bounding set needs CAP_SETPCAP, so run this inside a user
//! namespace (`unshare -Ur cargo run ...`) or as root.

use tpt_l_caps_drop::CapsPolicy;

fn main() {
    if let Err(e) = CapsPolicy::new()
        .drop_all()
        .keep("CAP_NET_BIND_SERVICE")
        .apply()
    {
        // Usually a missing privilege, not a bug: say what to do and stop.
        eprintln!("cannot drop capabilities here: {e}");
        eprintln!("run as root, or inside a user namespace: unshare -Ur cargo run ...");
        std::process::exit(1);
    }

    match caps::read(None, caps::CapSet::Permitted) {
        Ok(permitted) => println!("permitted after drop: {permitted:?}"),
        Err(e) => {
            eprintln!("could not read the permitted set: {e}");
            std::process::exit(1);
        }
    }
}
