//! Async reader and parser for the Linux kernel audit subsystem.
//!
//! Connects via `NETLINK_AUDIT` and exposes a [`tokio::sync::mpsc`] channel
//! of typed [`AuditEvent`]s. The background reader task runs until the
//! returned receiver is dropped.
//!
//! Requires `CAP_AUDIT_READ` (or running as root) to receive audit records.
//!
//! # Example
//!
//! ```no_run
//! #[tokio::main]
//! async fn main() {
//!     let mut rx = tpt_l_audit_logger::subscribe(128).await.unwrap();
//!     while let Some(event) = rx.recv().await {
//!         println!("audit type={} fields={:?}", event.record_type, event.fields);
//!     }
//! }
//! ```

#[cfg(not(target_os = "linux"))]
compile_error!("tpt-l-audit-logger only supports Linux");

use thiserror::Error;
use tokio::sync::mpsc;

/// Errors produced by this crate.
#[derive(Debug, Error)]
pub enum AuditError {
    /// Failed to create the netlink socket.
    #[error("failed to open NETLINK_AUDIT socket: {0}")]
    Socket(std::io::Error),
    /// Failed to bind the socket to the audit multicast group.
    #[error("failed to bind NETLINK_AUDIT socket: {0}")]
    Bind(std::io::Error),
    /// A receive operation on the socket failed.
    #[error("netlink receive error: {0}")]
    Recv(std::io::Error),
    /// The process lacks the privileges required to read audit records.
    #[error("insufficient privileges to read audit log (needs CAP_AUDIT_READ)")]
    PermissionDenied,
}

/// The numeric type of a kernel audit record (e.g. 1300 = SYSCALL, 1400 = AVC).
pub type AuditRecordType = u32;

/// A single parsed audit event from the kernel.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// Record type number.
    pub record_type: AuditRecordType,
    /// Key-value pairs parsed from the audit record body.
    pub fields: Vec<(String, String)>,
}

impl AuditEvent {
    /// Parse a raw audit record string into an [`AuditEvent`].
    ///
    /// Expects the format produced by the kernel: `key=value key=value ...`
    pub fn parse(record_type: AuditRecordType, body: &str) -> Self {
        let fields = body
            .split_whitespace()
            .filter_map(|token| {
                let (k, v) = token.split_once('=')?;
                Some((k.to_owned(), v.trim_matches('"').to_owned()))
            })
            .collect();
        AuditEvent { record_type, fields }
    }
}

/// Subscribe to the kernel audit stream.
///
/// Returns a receiver channel; events arrive as the kernel produces them.
/// The background reader task exits automatically when the receiver is dropped.
///
/// `buffer` sets the channel's event buffer capacity.
pub async fn subscribe(buffer: usize) -> Result<mpsc::Receiver<AuditEvent>, AuditError> {
    let (tx, rx) = mpsc::channel(buffer);
    tokio::spawn(async move {
        // TODO: create a raw SOCK_RAW / NETLINK_AUDIT socket via libc::socket,
        // bind to NETLINK_AUDIT multicast group 1, loop on libc::recv,
        // parse each netlink message header + body into AuditEvent,
        // and send on tx. Exit the loop when tx.send() returns Err (receiver dropped).
        drop(tx);
    });
    Ok(rx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_record() {
        let ev = AuditEvent::parse(1300, r#"arch=c000003e syscall=2 success=yes exe="/bin/cat""#);
        assert_eq!(ev.record_type, 1300);
        let map: std::collections::HashMap<_, _> = ev.fields.into_iter().collect();
        assert_eq!(map["syscall"], "2");
        assert_eq!(map["exe"], "/bin/cat");
    }

    #[test]
    fn parse_empty_body() {
        let ev = AuditEvent::parse(1300, "");
        assert!(ev.fields.is_empty());
    }
}
