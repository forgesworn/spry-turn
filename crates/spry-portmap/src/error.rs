use crate::Method;
use std::fmt;

/// Why a mapping operation did not succeed.
///
/// Messages never include addresses, so they are safe to log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// A local socket or file operation failed.
    Io(std::io::ErrorKind),
    /// No default gateway could be found, or it is not an IPv4 address.
    NoGateway,
    /// Nothing answered before the deadline.
    NoAnswer,
    /// Replies arrived, but none was a valid answer to this request.
    Malformed(&'static str),
    /// The gateway answered and declined. `code` is the protocol's own
    /// result or error code.
    Refused {
        method: Method,
        code: u16,
        reason: &'static str,
    },
    /// The gateway speaks another version of the protocol (for PCP, a
    /// NAT-PMP-only gateway).
    UnsupportedVersion,
    /// A UPnP gateway grants only permanent leases and the caller did not
    /// allow them.
    PermanentOnly,
    /// A URL or address pointed outside the local network.
    OffLan,
    /// No UPnP Internet Gateway Device with a WAN connection service was found.
    NoIgd,
    /// A UPnP mapping did not show this process's client, port and tag, so it
    /// was left alone.
    NotOurs,
    /// The mapping belongs to a protocol this mapper is not using.
    WrongMethod,
    /// Every protocol failed; one entry per protocol tried, in order.
    NoMethod(Vec<(Method, Error)>),
    /// The record file is unreadable, too large or malformed.
    Record(&'static str),
    /// A caller-supplied value is out of range.
    Invalid(&'static str),
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => Self::NoAnswer,
            kind => Self::Io(kind),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(kind) => write!(f, "local I/O failed ({kind})"),
            Self::NoGateway => f.write_str("no IPv4 default gateway"),
            Self::NoAnswer => f.write_str("no answer"),
            Self::Malformed(reason) => write!(f, "invalid reply ({reason})"),
            Self::Refused {
                method,
                code,
                reason,
            } => write!(f, "{method} refused: {reason} (code {code})"),
            Self::UnsupportedVersion => f.write_str("gateway speaks another protocol version"),
            Self::PermanentOnly => f.write_str("gateway grants only permanent leases"),
            Self::OffLan => f.write_str("address is not the local gateway"),
            Self::NoIgd => f.write_str("no UPnP gateway with a WAN connection service"),
            Self::NotOurs => f.write_str("mapping is not this relay's"),
            Self::WrongMethod => f.write_str("mapping was made with another protocol"),
            Self::NoMethod(attempts) => {
                f.write_str("no protocol granted a mapping")?;
                for (method, error) in attempts {
                    write!(f, "; {method}: {error}")?;
                }
                Ok(())
            }
            Self::Record(reason) => write!(f, "mapping record unusable ({reason})"),
            Self::Invalid(reason) => write!(f, "invalid request ({reason})"),
        }
    }
}

impl std::error::Error for Error {}
