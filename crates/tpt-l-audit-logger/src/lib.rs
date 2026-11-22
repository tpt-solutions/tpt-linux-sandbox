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
        AuditEvent {
            record_type,
            fields,
        }
    }
}

// Netlink message header layout.
#[repr(C)]
struct NlMsgHdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

const NL_HDR_LEN: usize = std::mem::size_of::<NlMsgHdr>();
// Maximum netlink message size.
const RECV_BUF: usize = 8192;

/// Subscribe to the kernel audit stream.
///
/// Returns a receiver channel; events arrive as the kernel produces them.
/// The background reader task exits automatically when the receiver is dropped.
///
/// `buffer` sets the channel's event buffer capacity.
pub async fn subscribe(buffer: usize) -> Result<mpsc::Receiver<AuditEvent>, AuditError> {
    // Open the NETLINK_AUDIT socket synchronously before spawning the task
    // so that socket-creation errors are returned to the caller immediately.
    let fd = open_audit_socket()?;

    let (tx, rx) = mpsc::channel(buffer);
    tokio::task::spawn_blocking(move || {
        reader_loop(fd, tx);
    });

    Ok(rx)
}

fn open_audit_socket() -> Result<std::os::fd::OwnedFd, AuditError> {
    use std::os::fd::FromRawFd;

    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_AUDIT,
        )
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(if err.kind() == std::io::ErrorKind::PermissionDenied {
            AuditError::PermissionDenied
        } else {
            AuditError::Socket(err)
        });
    }

    // Bind to multicast group 1 (AUDIT_NLGRP_READLOG).
    let addr = libc::sockaddr_nl {
        nl_family: libc::AF_NETLINK as u16,
        nl_pad: 0,
        nl_pid: 0,
        nl_groups: 1,
    };
    let ret = unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(AuditError::Bind(err));
    }

    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

fn reader_loop(fd: std::os::fd::OwnedFd, tx: mpsc::Sender<AuditEvent>) {
    use std::os::fd::AsRawFd;

    let raw = fd.as_raw_fd();
    let mut buf = vec![0u8; RECV_BUF];

    loop {
        let n = unsafe { libc::recv(raw, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n <= 0 {
            break;
        }
        let n = n as usize;
        if n < NL_HDR_LEN {
            continue;
        }

        // Read the netlink header.
        let hdr = unsafe { &*(buf.as_ptr() as *const NlMsgHdr) };
        let record_type = u32::from(hdr.nlmsg_type);

        // The body follows the header, null-terminated.
        let body_start = NL_HDR_LEN;
        let body_end = (hdr.nlmsg_len as usize).min(n);
        if body_end <= body_start {
            continue;
        }
        let body_bytes = &buf[body_start..body_end];
        let body = std::str::from_utf8(body_bytes)
            .unwrap_or("")
            .trim_end_matches('\0');

        let event = AuditEvent::parse(record_type, body);

        // Exit the loop if the receiver has been dropped.
        if tx.blocking_send(event).is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_record() {
        let ev = AuditEvent::parse(
            1300,
            r#"arch=c000003e syscall=2 success=yes exe="/bin/cat""#,
        );
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

    #[test]
    fn parse_quoted_values() {
        let ev = AuditEvent::parse(1300, r#"key="some value""#);
        let map: std::collections::HashMap<_, _> = ev.fields.into_iter().collect();
        assert_eq!(map["key"], "some value");
    }
}
