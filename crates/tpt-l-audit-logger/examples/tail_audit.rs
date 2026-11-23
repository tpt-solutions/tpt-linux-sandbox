//! Print kernel audit events as they arrive.
//!
//! Needs CAP_AUDIT_READ (run as root, or grant the capability).
//! Run with `cargo run -p tpt-l-audit-logger --example tail_audit`.

#[tokio::main]
async fn main() {
    let mut rx = match tpt_l_audit_logger::subscribe(128).await {
        Ok(rx) => rx,
        Err(e) => {
            eprintln!("cannot subscribe to the audit log: {e}");
            std::process::exit(1);
        }
    };

    while let Some(item) = rx.recv().await {
        match item {
            Ok(event) => println!("type={} fields={:?}", event.record_type, event.fields),
            Err(e) => {
                eprintln!("audit stream ended: {e}");
                break;
            }
        }
    }
}
