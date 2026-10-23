//! Receive-queue experiment, not TURN forwarding or maximum network capacity.
#![forbid(unsafe_code)]

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This development-only recvmmsg experiment requires Linux");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    linux::main()
}

#[cfg(target_os = "linux")]
mod linux {
    use nix::sys::socket::{MsgFlags, MultiHeaders, SockaddrIn, getsockopt, recvmmsg, sockopt};
    use std::io::{self, IoSliceMut};
    use std::net::{SocketAddr, UdpSocket};
    use std::os::fd::AsRawFd;
    use std::time::{Duration, Instant};

    const WINDOW: usize = 32;
    const MAX_PAYLOAD: usize = 1200;
    const WARMUP_WINDOWS: usize = 32;
    type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    struct Pair {
        sender: UdpSocket,
        receiver: UdpSocket,
        source: SocketAddr,
        destination: SocketAddr,
    }

    impl Pair {
        fn new() -> Result<Self> {
            let sender = UdpSocket::bind("127.0.0.1:0")?;
            let receiver = UdpSocket::bind("127.0.0.1:0")?;
            sender.set_write_timeout(Some(Duration::from_secs(1)))?;
            receiver.set_nonblocking(true)?;
            Ok(Self {
                source: sender.local_addr()?,
                destination: receiver.local_addr()?,
                sender,
                receiver,
            })
        }
    }

    fn invalid(message: &str) -> Box<dyn std::error::Error> {
        io::Error::new(io::ErrorKind::InvalidData, message).into()
    }

    fn check_payload(data: &[u8], expected: u64, size: usize) -> Result<()> {
        if data.len() != size || data.get(..8) != Some(expected.to_be_bytes().as_slice()) {
            return Err(invalid("Lost, reordered, truncated or incorrect sequence"));
        }
        if data[8..]
            .iter()
            .enumerate()
            .any(|(i, byte)| *byte != ((i + 8) * 17) as u8)
        {
            return Err(invalid("Payload corruption"));
        }
        Ok(())
    }

    // Views are stack storage, rebuilt per call without a heap allocation.
    // MultiHeaders and payload arenas are reused for the complete sample.
    fn receive_batch<const B: usize>(
        pair: &Pair,
        headers: &mut MultiHeaders<SockaddrIn>,
        buffers: &mut [[u8; MAX_PAYLOAD]; B],
        size: usize,
        expected: u64,
        stride: usize,
    ) -> Result<usize> {
        let mut chunks = buffers.iter_mut();
        let mut views: [[IoSliceMut<'_>; 1]; B] =
            std::array::from_fn(|_| [IoSliceMut::new(&mut chunks.next().unwrap()[..size])]);
        let messages = recvmmsg(
            pair.receiver.as_raw_fd(),
            headers,
            views.iter_mut(),
            MsgFlags::MSG_DONTWAIT,
            None,
        )?;
        let mut received = 0;
        for message in messages {
            if message
                .flags
                .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC)
                || message
                    .address
                    .map(|address| SocketAddr::from((address.ip(), address.port())))
                    != Some(pair.source)
            {
                return Err(invalid("Truncation or unexpected source"));
            }
            let mut slices = message.iovs();
            let data = slices
                .next()
                .ok_or_else(|| invalid("Missing receive view"))?;
            if message.bytes != size || slices.next().is_some() {
                return Err(invalid("Unexpected datagram framing"));
            }
            check_payload(
                &data[..message.bytes],
                expected + (received * stride) as u64,
                size,
            )?;
            received += 1;
        }
        if received == 0 {
            return Err(invalid("Empty receive from a prefilled queue"));
        }
        Ok(received)
    }

    fn sample<const B: usize>(
        batched: bool,
        packets: usize,
        size: usize,
        socket_count: usize,
        repetition: usize,
    ) -> Result<()> {
        let pairs: Vec<_> = (0..socket_count)
            .map(|_| Pair::new())
            .collect::<Result<_>>()?;
        let receive_limits: usize = pairs
            .iter()
            .map(|pair| getsockopt(&pair.receiver, sockopt::RcvBuf))
            .collect::<std::result::Result<Vec<_>, _>>()?
            .iter()
            .sum();
        let mut headers = batched.then(|| MultiHeaders::<SockaddrIn>::preallocate(B, None));
        let mut buffers = [[0u8; MAX_PAYLOAD]; B];
        let mut frame = [0u8; MAX_PAYLOAD];
        for (i, byte) in frame.iter_mut().enumerate().skip(8) {
            *byte = (i * 17) as u8;
        }
        let mut receive_ns = 0u128;
        let mut receive_calls = 0usize;
        let mut largest_batch = 0usize;
        let mut total_started = Instant::now();
        let deadline = Instant::now() + Duration::from_secs(20);
        for window in 0..WARMUP_WINDOWS + packets / WINDOW {
            if Instant::now() > deadline {
                return Err(invalid("Experiment sample exceeded its time bound"));
            }
            if window == WARMUP_WINDOWS {
                total_started = Instant::now();
            }
            let first = window * WINDOW;
            // The identical offered window is queued before receiver timing.
            for offset in 0..WINDOW {
                let pair = &pairs[offset % socket_count];
                frame[..8].copy_from_slice(&((first + offset) as u64).to_be_bytes());
                if pair.sender.send_to(&frame[..size], pair.destination)? != size {
                    return Err(invalid("Incomplete datagram send"));
                }
            }
            let started = Instant::now();
            for (index, pair) in pairs.iter().enumerate() {
                let mut received = 0;
                while received < WINDOW / socket_count {
                    let expected = (first + index + received * socket_count) as u64;
                    let count = if let Some(headers) = &mut headers {
                        receive_batch(pair, headers, &mut buffers, size, expected, socket_count)?
                    } else {
                        let (bytes, source) = pair.receiver.recv_from(&mut buffers[0][..size])?;
                        if source != pair.source {
                            return Err(invalid("Unexpected source"));
                        }
                        check_payload(&buffers[0][..bytes], expected, size)?;
                        1
                    };
                    received += count;
                    if received > WINDOW / socket_count {
                        return Err(invalid("Receive escaped the offered window"));
                    }
                    if window >= WARMUP_WINDOWS {
                        receive_calls += 1;
                        largest_batch = largest_batch.max(count);
                    }
                }
            }
            if window >= WARMUP_WINDOWS {
                receive_ns += started.elapsed().as_nanos();
            }
        }
        let total_ns = total_started.elapsed().as_nanos();
        let arena_bytes = std::mem::size_of_val(&buffers);
        let views_bytes = if batched {
            B * std::mem::size_of::<IoSliceMut<'_>>()
        } else {
            0
        };
        let header_storage_bytes = if batched {
            B * (std::mem::size_of::<nix::libc::mmsghdr>() + std::mem::size_of::<SockaddrIn>())
                + std::mem::size_of::<MultiHeaders<SockaddrIn>>()
        } else {
            0
        };
        let method = if batched { "recvmmsg" } else { "recv_from" };
        println!(
            "{{\"type\":\"sample\",\"method\":\"{method}\",\"batch_capacity\":{B},\"repetition\":{repetition},\"payload_bytes\":{size},\"receiver_sockets\":{socket_count},\"total_udp_sockets\":{},\"offered_window_packets\":{WINDOW},\"packets_verified\":{packets},\"receiver_validation_ns\":{receive_ns},\"whole_workload_ns\":{total_ns},\"receive_calls\":{receive_calls},\"largest_returned_batch\":{largest_batch},\"packets_per_receive_call\":{},\"payload_arena_bytes\":{arena_bytes},\"ioview_stack_bytes\":{views_bytes},\"header_storage_bytes\":{header_storage_bytes},\"receiver_rcvbuf_limits_sum_bytes\":{receive_limits},\"loss_reorder_corruption\":0}}",
            socket_count * 2,
            packets as f64 / receive_calls as f64,
        );
        Ok(())
    }

    fn argument(args: &[String], key: &str, default: usize) -> Result<usize> {
        match args.iter().position(|value| value == key) {
            None => Ok(default),
            Some(i) => args
                .get(i + 1)
                .ok_or_else(|| invalid("Missing option value"))?
                .parse()
                .map_err(Into::into),
        }
    }

    pub fn main() -> Result<()> {
        let args: Vec<_> = std::env::args().skip(1).collect();
        if args.len() % 2 != 0
            || args
                .chunks_exact(2)
                .any(|pair| !["--packets", "--runs"].contains(&pair[0].as_str()))
        {
            return Err(invalid(
                "Usage: spry-linux-batch-experiment [--packets N] [--runs N]",
            ));
        }
        let packets = argument(&args, "--packets", 65_536)?;
        let runs = argument(&args, "--runs", 3)?;
        if !(WINDOW..=10_000_000).contains(&packets)
            || packets % WINDOW != 0
            || !(1..=9).contains(&runs)
        {
            return Err(invalid(
                "Packets must be a multiple of 32 in 32..10000000; runs must be 1..9",
            ));
        }
        let kernel: String = std::fs::read_to_string("/proc/sys/kernel/osrelease")?
            .trim()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || ".-_+".contains(*c))
            .collect();
        println!(
            "{{\"type\":\"method\",\"schema\":1,\"experiment\":\"prefilled-linux-udp-receive-queue\",\"architecture\":\"{}\",\"kernel\":\"{kernel}\",\"warmup_windows_per_sample\":{WARMUP_WINDOWS},\"packets_per_sample\":{packets},\"runs\":{runs},\"receiver_timing_includes_validation\":true,\"receiver_timing_excludes_sender\":true,\"forwarding_performance_claim\":false,\"kernel_memory_measured\":false}}",
            std::env::consts::ARCH
        );
        for repetition in 0..runs {
            for size in [160, 1200] {
                for sockets in [1, 32] {
                    let mut modes = [0, 1, 8, 32];
                    modes.rotate_left(repetition % 4);
                    for mode in modes {
                        match mode {
                            0 => sample::<1>(false, packets, size, sockets, repetition)?,
                            1 => sample::<1>(true, packets, size, sockets, repetition)?,
                            8 => sample::<8>(true, packets, size, sockets, repetition)?,
                            32 => sample::<32>(true, packets, size, sockets, repetition)?,
                            _ => unreachable!(),
                        }
                    }
                }
            }
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn validation_rejects_every_corrupted_byte_and_wrong_sequence() {
            let mut payload = [0u8; 160];
            payload[..8].copy_from_slice(&17u64.to_be_bytes());
            for (i, byte) in payload.iter_mut().enumerate().skip(8) {
                *byte = (i * 17) as u8;
            }
            assert!(check_payload(&payload, 17, 160).is_ok());
            assert!(check_payload(&payload, 18, 160).is_err());
            assert!(check_payload(&payload[..159], 17, 160).is_err());
            for i in 0..payload.len() {
                payload[i] ^= 1;
                assert!(check_payload(&payload, 17, 160).is_err());
                payload[i] ^= 1;
            }
        }

        #[test]
        fn prefilled_one_and_many_socket_paths_preserve_packets() {
            // Small real-socket acceptance; performance runs use release builds.
            for sockets in [1, 32] {
                sample::<1>(false, 32, 160, sockets, 0).unwrap();
                sample::<1>(true, 32, 160, sockets, 0).unwrap();
                sample::<8>(true, 32, 160, sockets, 0).unwrap();
                sample::<32>(true, 32, 160, sockets, 0).unwrap();
            }
        }
    }
}
