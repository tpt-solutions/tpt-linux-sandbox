//! Async reader and parser for the Linux kernel audit subsystem.
//!
//! Connects via `NETLINK_AUDIT` and exposes a [`tokio::sync::mpsc`] channel of
//! `Result<AuditEvent, AuditError>`. Socket errors are delivered through the
//! channel, after which the stream ends. The background reader stops when the
//! receiver is dropped, within about half a second.
//!
//! Requires `CAP_AUDIT_READ` (or running as root) to receive audit records.
//!
//! # Example
//!
//! ```no_run
//! #[tokio::main]
//! async fn main() {
//!     let mut rx = tpt_l_audit_logger::subscribe(128).await.unwrap();
//!     while let Some(item) = rx.recv().await {
//!         match item {
//!             Ok(event) => println!("audit type={} fields={:?}", event.record_type, event.fields),
//!             Err(e) => eprintln!("audit stream error: {e}"),
//!         }
//!     }
//! }
//! ```

// Netlink ABI casts: every length read from the kernel is checked against the
// buffer bounds before use, and the libc constants are small and fixed.
#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]

#[cfg(not(target_os = "linux"))]
compile_error!("tpt-l-audit-logger only supports Linux");

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use thiserror::Error;
use tokio::sync::mpsc;

/// Errors produced by this crate.
#[derive(Debug, Error)]
pub enum AuditError {
    /// Failed to create the netlink socket.
    #[error("failed to open NETLINK_AUDIT socket: {0}")]
    Socket(io::Error),
    /// Failed to bind the socket to the audit multicast group.
    #[error("failed to bind NETLINK_AUDIT socket: {0}")]
    Bind(io::Error),
    /// A receive operation on the socket failed (for example a buffer overrun,
    /// reported as ENOBUFS).
    #[error("netlink receive error: {0}")]
    Recv(io::Error),
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
        let fields = split_fields(body)
            .into_iter()
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

/// Split an audit body on whitespace, keeping double-quoted sections intact so
/// that `key="some value"` remains a single token.
fn split_fields(body: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    let mut start: Option<usize> = None;
    let mut in_quotes = false;

    for (i, c) in body.char_indices() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                start.get_or_insert(i);
            }
            c if c.is_whitespace() && !in_quotes => {
                if let Some(s) = start.take() {
                    tokens.push(&body[s..i]);
                }
            }
            _ => {
                start.get_or_insert(i);
            }
        }
    }
    if let Some(s) = start {
        tokens.push(&body[s..]);
    }
    tokens
}

// Netlink message header layout (struct nlmsghdr, 16 bytes). Field names
// mirror the kernel's struct.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(clippy::struct_field_names)]
struct NlMsgHdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

const NL_HDR_LEN: usize = std::mem::size_of::<NlMsgHdr>();
// Receive buffer. Audit datagrams are normally far smaller.
const RECV_BUF: usize = 8192;
// How often the reader wakes to check whether the receiver is still alive.
const POLL_INTERVAL_MS: libc::c_int = 500;

/// Subscribe to the kernel audit stream.
///
/// Returns a receiver channel; each item is an event or an error. The
/// background reader exits when the receiver is dropped.
///
/// `buffer` sets the channel's capacity.
///
/// The reader runs on Tokio's blocking pool, so this must be called from
/// inside a Tokio runtime; outside one it panics.
///
/// # Errors
///
/// Returns [`AuditError::PermissionDenied`] without `CAP_AUDIT_READ`, or a
/// `Socket`/`Bind` error for other setup failures.
// Kept `async` so the signature matches the Tokio-based API this crate exposes.
#[allow(clippy::unused_async)]
pub async fn subscribe(
    buffer: usize,
) -> Result<mpsc::Receiver<Result<AuditEvent, AuditError>>, AuditError> {
    // Open the socket synchronously so setup errors reach the caller directly.
    let fd = open_audit_socket()?;

    let (tx, rx) = mpsc::channel(buffer);
    tokio::task::spawn_blocking(move || {
        reader_loop(fd, &tx);
    });

    Ok(rx)
}

fn open_audit_socket() -> Result<OwnedFd, AuditError> {
    // SAFETY: plain socket(2) call; the return value is checked below.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_AUDIT,
        )
    };
    if fd < 0 {
        return Err(map_socket_error(
            io::Error::last_os_error(),
            AuditError::Socket,
        ));
    }
    // SAFETY: `fd` is a freshly created descriptor that nothing else owns.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    // Bind to multicast group 1 (AUDIT_NLGRP_READLOG).
    // SAFETY: sockaddr_nl is a plain C struct; all-zero is a valid bit pattern.
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_groups = 1;
    // SAFETY: `addr` outlives the call and its size is passed correctly.
    let ret = unsafe {
        libc::bind(
            owned.as_raw_fd(),
            (&raw const addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(map_socket_error(
            io::Error::last_os_error(),
            AuditError::Bind,
        ));
    }

    Ok(owned)
}

fn map_socket_error(err: io::Error, wrap: fn(io::Error) -> AuditError) -> AuditError {
    if err.kind() == io::ErrorKind::PermissionDenied || err.raw_os_error() == Some(libc::EPERM) {
        AuditError::PermissionDenied
    } else {
        wrap(err)
    }
}

/// Wait up to `POLL_INTERVAL_MS` for the socket to become readable.
fn wait_readable(fd: RawFd) -> io::Result<bool> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `pfd` is a valid pollfd for the duration of the call.
    let ret = unsafe { libc::poll(&raw mut pfd, 1, POLL_INTERVAL_MS) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        return if err.kind() == io::ErrorKind::Interrupted {
            Ok(false)
        } else {
            Err(err)
        };
    }
    Ok(ret > 0)
}

// Takes the descriptor by value so it is closed when the reader exits.
#[allow(clippy::needless_pass_by_value)]
fn reader_loop(fd: OwnedFd, tx: &mpsc::Sender<Result<AuditEvent, AuditError>>) {
    let raw = fd.as_raw_fd();
    let mut buf = vec![0u8; RECV_BUF];

    loop {
        // Stop as soon as nobody is listening, even if no audit event arrives.
        if tx.is_closed() {
            break;
        }

        match wait_readable(raw) {
            Ok(false) => continue,
            Ok(true) => {}
            Err(e) => {
                let _ = tx.blocking_send(Err(AuditError::Recv(e)));
                break;
            }
        }

        // MSG_TRUNC makes recvfrom return the full datagram length, so an
        // oversized datagram can be detected.
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut addr_len = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        // SAFETY: `buf`, `addr` and `addr_len` are valid for the lengths passed.
        let n = unsafe {
            libc::recvfrom(
                raw,
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
                libc::MSG_TRUNC,
                (&raw mut addr).cast::<libc::sockaddr>(),
                &raw mut addr_len,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            match err.kind() {
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock => continue,
                _ => {
                    let _ = tx.blocking_send(Err(AuditError::Recv(err)));
                    break;
                }
            }
        }
        let n = n as usize;

        // Only the kernel (netlink pid 0) may send audit records to us.
        if addr.nl_pid != 0 {
            continue;
        }
        if n > buf.len() {
            let err = io::Error::other(format!("audit datagram truncated ({n} bytes)"));
            if tx.blocking_send(Err(AuditError::Recv(err))).is_err() {
                break;
            }
            continue;
        }

        for event in parse_datagram(&buf[..n]) {
            if tx.blocking_send(Ok(event)).is_err() {
                return;
            }
        }
    }
}

/// Round a netlink length up to the 4-byte alignment netlink uses.
fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

/// Parse every netlink message in a datagram. Malformed lengths end the scan
/// rather than reading past the buffer.
fn parse_datagram(buf: &[u8]) -> Vec<AuditEvent> {
    let mut events = Vec::new();
    let mut offset = 0;

    while offset + NL_HDR_LEN <= buf.len() {
        // The header may not be aligned inside the Vec, so read it unaligned.
        // SAFETY: the bounds check above guarantees NL_HDR_LEN readable bytes.
        let hdr: NlMsgHdr =
            unsafe { std::ptr::read_unaligned(buf[offset..].as_ptr().cast::<NlMsgHdr>()) };
        let len = hdr.nlmsg_len as usize;
        if len < NL_HDR_LEN || offset + len > buf.len() {
            break;
        }

        let text = String::from_utf8_lossy(&buf[offset + NL_HDR_LEN..offset + len]);
        let body = text.trim_end_matches('\0');
        events.push(AuditEvent::parse(u32::from(hdr.nlmsg_type), body));

        offset += nlmsg_align(len);
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_msg(ty: u16, body: &[u8]) -> Vec<u8> {
        let len = NL_HDR_LEN + body.len();
        let mut v = Vec::new();
        v.extend_from_slice(&(len as u32).to_ne_bytes());
        v.extend_from_slice(&ty.to_ne_bytes());
        v.extend_from_slice(&[0u8; 10]); // flags, seq, pid
        v.extend_from_slice(body);
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }

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
        assert_eq!(ev.fields.len(), 0);
    }

    #[test]
    fn parse_quoted_values() {
        let ev = AuditEvent::parse(1300, r#"key="some value""#);
        let map: std::collections::HashMap<_, _> = ev.fields.into_iter().collect();
        assert_eq!(map["key"], "some value");
    }

    #[test]
    fn datagram_with_two_messages_yields_two_events() {
        let mut buf = build_msg(1300, b"syscall=2 success=yes");
        // Odd-length body so the second message starts at an unaligned-looking offset.
        buf.extend(build_msg(1400, b"avc=denied"));
        let events = parse_datagram(&buf);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].record_type, 1300);
        assert_eq!(events[1].record_type, 1400);
    }

    #[test]
    fn datagram_with_bad_length_stops_cleanly() {
        let mut buf = build_msg(1300, b"a=b");
        // Claim a length longer than the buffer.
        buf[0..4].copy_from_slice(&9999u32.to_ne_bytes());
        assert_eq!(parse_datagram(&buf).len(), 0);
    }

    #[test]
    fn datagram_with_zero_length_is_ignored() {
        let buf = vec![0u8; NL_HDR_LEN];
        assert_eq!(parse_datagram(&buf).len(), 0);
    }

    /// Subscribing needs CAP_AUDIT_READ and a kernel with audit netlink. Without
    /// the privilege the test reports a skip; any other failure is a real error.
    #[tokio::test]
    #[ignore = "reads the kernel audit stream; needs CAP_AUDIT_READ"]
    async fn subscribe_reports_missing_privilege_cleanly() {
        match subscribe(8).await {
            Ok(rx) => drop(rx),
            Err(AuditError::PermissionDenied) => {
                eprintln!("skipping: no CAP_AUDIT_READ");
            }
            Err(e) => panic!("unexpected audit error: {e}"),
        }
    }

    #[test]
    fn invalid_utf8_body_is_kept_lossily() {
        let buf = build_msg(1300, b"msg=\xff\xfe ok=1");
        let events = parse_datagram(&buf);
        assert_eq!(events.len(), 1);
        assert!(events[0].fields.iter().any(|(k, _)| k == "ok"));
    }
}
