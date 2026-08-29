//! Async reader/parser for the kernel audit subsystem via `NETLINK_AUDIT`.

#![deny(missing_docs)]

use libc::{c_int, c_void, nlmsghdr, recvfrom, sa_family_t, sockaddr_nl, socklen_t,
           AF_NETLINK, NETLINK_AUDIT, SOCK_RAW};
use std::collections::HashMap;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Errors that can occur when interacting with the audit subsystem.
#[derive(Debug, Error)]
pub enum AuditError {
    /// Failed to create the netlink socket.
    #[error("failed to create netlink socket: {0}")]
    SocketCreation(io::Error),
    /// Failed to bind the netlink socket.
    #[error("failed to bind netlink socket: {0}")]
    BindFailed(io::Error),
    /// Failed to receive audit data.
    #[error("recvfrom failed: {0}")]
    ReceiveFailed(io::Error),
    /// Invalid netlink message.
    #[error("invalid netlink message: {0}")]
    InvalidMessage(String),
}

/// A parsed kernel audit event.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditEvent {
    /// The audit record type (e.g., SYSCALL, PATH, USER_LOGIN).
    pub record_type: u16,
    /// Key-value fields extracted from the record.
    pub fields: HashMap<String, String>,
    /// The raw message text.
    pub raw: String,
}

/// An async audit log subscriber.
///
/// Opens a `NETLINK_AUDIT` raw socket and parses incoming audit records
/// into typed [`AuditEvent`]s, delivered via an `mpsc` channel.
pub struct AuditLogger {
    fd: RawFd,
}

impl AuditLogger {
    /// Creates a new `AuditLogger` by opening and binding a `NETLINK_AUDIT` socket.
    pub fn new() -> Result<Self, AuditError> {
        let fd = unsafe {
            libc::socket(AF_NETLINK as c_int, SOCK_RAW, NETLINK_AUDIT as c_int)
        };
        if fd < 0 {
            return Err(AuditError::SocketCreation(io::Error::last_os_error()));
        }

        let addr = sockaddr_nl {
            nl_family: AF_NETLINK as sa_family_t,
            nl_pid: std::process::id(),
            nl_groups: 0,
            nl_pad: 0,
        };

        let ret = unsafe {
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<sockaddr_nl>() as socklen_t,
            )
        };
        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(AuditError::BindFailed(io::Error::last_os_error()));
        }

        info!(fd, "NETLINK_AUDIT socket opened");
        Ok(Self { fd })
    }

    /// Returns the raw file descriptor of the netlink socket.
    pub fn fd(&self) -> RawFd {
        self.fd
    }

    /// Subscribes to audit events, returning a receiver channel.
    ///
    /// The `buffer` parameter specifies the channel capacity.
    pub fn subscribe(self, buffer: usize) -> mpsc::Receiver<AuditEvent> {
        let (tx, rx) = mpsc::channel(buffer);
        let fd = self.fd;

        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                let len = unsafe {
                    recvfrom(
                        fd,
                        buf.as_mut_ptr() as *mut c_void,
                        buf.len(),
                        0,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    )
                };
                if len < 0 {
                    error!("recvfrom error: {}", io::Error::last_os_error());
                    break;
                }

                let data = &buf[..len as usize];
                if let Some(event) = Self::parse_message(data) {
                    if tx.send(event).await.is_err() {
                        debug!("audit receiver dropped, stopping");
                        break;
                    }
                }
            }
        });

        rx
    }

    fn parse_message(data: &[u8]) -> Option<AuditEvent> {
        // Netlink message header: length (4) + type (2) + flags (2) + seq (4) + pid (4) = 16 bytes
        if data.len() < 16 {
            return None;
        }

        let nlmsg_len = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let nlmsg_type = u16::from_ne_bytes([data[4], data[5]]);

        if data.len() < nlmsg_len {
            return None;
        }

        let payload = &data[16..nlmsg_len];
        let raw = String::from_utf8_lossy(payload).to_string();

        let mut fields = HashMap::new();

        // Parse key=value pairs from the audit record
        for part in raw.split(&[' ', '\n'][..]) {
            if let Some((key, value)) = part.split_once('=') {
                let value = value.trim_matches('"').to_string();
                if !value.is_empty() {
                    fields.insert(key.to_string(), value);
                }
            }
        }

        Some(AuditEvent {
            record_type: nlmsg_type,
            fields,
            raw,
        })
    }
}

impl Drop for AuditLogger {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_message_extracts_fields() {
        // Simulated audit message payload
        let payload = b"1700\0type=SYSCALL msg=audit(1234567890.123:1): arch=c000003e syscall=59 success=yes exit=0";
        let event = AuditLogger::parse_message(payload).unwrap();
        assert_eq!(event.record_type, 1700);
        assert!(event.fields.contains_key("msg"));
    }

    #[test]
    fn parse_message_short_data_returns_none() {
        let data = &[0u8; 10];
        assert!(AuditLogger::parse_message(data).is_none());
    }

    #[test]
    fn parse_message_extracts_key_value() {
        let payload = b"1700\0pid=1234 uid=0 comm=\"test\"";
        let event = AuditLogger::parse_message(payload).unwrap();
        assert_eq!(event.fields.get("pid").map(|s| s.as_str()), Some("1234"));
        assert_eq!(event.fields.get("uid").map(|s| s.as_str()), Some("0"));
        assert_eq!(event.fields.get("comm").map(|s| s.as_str()), Some("test"));
    }
}
