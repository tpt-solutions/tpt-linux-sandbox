//! Drop every capability except CAP_NET_BIND_SERVICE, then show the result.
//!
//! Run with `cargo run -p tpt-l-caps-drop --example drop_caps`.
//! Dropping the bounding set needs CAP_SETPCAP, so run this inside a user
//! namespace (`unshare -Ur cargo run ...`) or as root.

use tpt_l_caps_drop::CapsPolicy;

fn main() {
    CapsPolicy::new()
        .drop_all()
        .keep("CAP_NET_BIND_SERVICE")
        .apply()
        .expect("capability drop failed");

    let permitted = caps::read(None, caps::CapSet::Permitted).expect("read permitted set");
    println!("permitted after drop: {permitted:?}");
}
