//! Request and retry over UDP to the gateway, shared by PCP and NAT-PMP.

use crate::Error;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

/// Largest PCP message (RFC 6887 section 7); NAT-PMP replies are smaller.
pub(crate) const MAX_DATAGRAM: usize = 1100;
/// First retransmission interval, doubled each time (RFC 6886 3.1).
const FIRST_WAIT: Duration = Duration::from_millis(250);

pub(crate) enum Verdict<T> {
    /// A valid answer to this request.
    Done(T),
    /// Not an answer to this request (stale, mismatched or malformed); keep
    /// listening.
    Ignore(&'static str),
    /// A valid answer that ends the request with an error.
    Fail(Error),
}

/// A fresh socket that hears only from `gateway`, and the local address the
/// host uses to reach it. Connecting a UDP socket sends nothing.
pub(crate) fn connect(gateway: SocketAddrV4) -> Result<(UdpSocket, Ipv4Addr), Error> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.connect(gateway)?;
    let SocketAddr::V4(local) = socket.local_addr()? else {
        return Err(Error::NoGateway);
    };
    if local.ip().is_unspecified() {
        return Err(Error::NoGateway);
    }
    Ok((socket, *local.ip()))
}

fn unreachable(error: &std::io::Error) -> bool {
    // An ICMP port-unreachable surfaces as refused (Unix) or reset (Windows).
    matches!(
        error.kind(),
        ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset
    )
}

/// Send `request`, retransmitting at 250 ms, 500 ms, 1 s and so on until
/// `budget` runs out, and return the first reply `judge` accepts. Replies from
/// any other address never arrive, because the socket is connected.
pub(crate) fn exchange<T>(
    socket: &UdpSocket,
    request: &[u8],
    budget: Duration,
    mut judge: impl FnMut(&[u8]) -> Verdict<T>,
) -> Result<T, Error> {
    let deadline = Instant::now() + budget;
    let mut wait = FIRST_WAIT;
    let mut problem: Option<&'static str> = None;
    let mut buffer = [0u8; MAX_DATAGRAM + 1];
    let give_up = |problem: Option<&'static str>| problem.map_or(Error::NoAnswer, Error::Malformed);
    loop {
        let sent_at = Instant::now();
        if sent_at >= deadline {
            return Err(give_up(problem));
        }
        match socket.send(request) {
            Ok(_) => {}
            Err(error) if unreachable(&error) => return Err(give_up(problem)),
            Err(error) => return Err(error.into()),
        }
        let resend = (sent_at + wait).min(deadline);
        wait = wait.saturating_mul(2);
        loop {
            let now = Instant::now();
            if now >= resend {
                break;
            }
            socket.set_read_timeout(Some(resend - now))?;
            match socket.recv(&mut buffer) {
                Ok(size) if size > MAX_DATAGRAM => problem = Some("oversized"),
                Ok(size) => match judge(&buffer[..size]) {
                    Verdict::Done(value) => return Ok(value),
                    Verdict::Ignore(reason) => problem = Some(reason),
                    Verdict::Fail(error) => return Err(error),
                },
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                {
                    break;
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) if unreachable(&error) => return Err(give_up(problem)),
                Err(error) => return Err(error.into()),
            }
        }
    }
}
