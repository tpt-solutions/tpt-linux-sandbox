//! Parse an AppArmor profile and show which rules map to Landlock.
//!
//! Runs on any platform. Run with
//! `cargo run -p tpt-l-apparmor-parser --example convert_profile`.

use tpt_l_apparmor_parser::AppArmorProfile;

const PROFILE: &str = r"
/usr/bin/my-worker {
  # Deny rules never grant access.
  deny /etc/shadow r,
  /etc/my-worker/** r,
  /var/lib/my-worker/** rw,
  /usr/lib/** rix,
  network inet stream,
}
";

fn main() {
    let profile = AppArmorProfile::parse(PROFILE).expect("profile parses");
    println!("profile {}", profile.name);

    println!("landlock rules:");
    for rule in profile.landlock_rules() {
        println!("  {} {:?}", rule.path_pattern, rule.permissions);
    }

    println!("not enforced by Landlock:");
    for rule in profile.unmapped_rules() {
        println!("  {rule:?}");
    }
}
