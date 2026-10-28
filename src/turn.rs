//! One non-blocking event loop, bounded per-allocation sockets and state.
use crate::{
    auth,
    limits::{Bucket, SWEEP_INTERVAL, Stats},
    wire::{self, *},
};
use mio::{
    Events, Interest, Poll, Token,
    net::{TcpListener, TcpStream, UdpSocket},
};
use std::collections::{HashMap, VecDeque};
#[cfg(feature = "tls")]
use std::sync::Arc;
use std::{
    collections::HashSet,
    io::{self, Read, Write},
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const UDP: Token = Token(0);
const TCP: Token = Token(1);
const TLS: Token = Token(2);
const MAX_PACKET: usize = 65_536;
const HEADROOM: usize = 64;
const MAX_QUEUE: usize = 131_072;
// Keep ordinary control replies admissible when relayed UDP fills the queue.
// Control traffic retains the full queue cap and its existing close policy.
const STREAM_CONTROL_RESERVE: usize = 1024;
const MAX_PEERS: usize = 32;
const STREAM_READS_PER_TURN: usize = 16;
const STREAM_BYTES_PER_TURN: usize = MAX_QUEUE;
const STREAM_FRAMES_PER_TURN: usize = 64;

fn local_bridge_address(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v) if v.octets()[0] == 127 && (64..=127).contains(&v.octets()[1]))
}

/// Maximum explicit local/advertised UDP port pairs accepted by one server.
pub const MAX_RELAY_PORT_MAPPINGS: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayPortMapping {
    pub local_port: u16,
    pub advertised_port: u16,
}

#[derive(Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub relay_ip: IpAddr,
    /// Inclusive UDP peer-relay range. None retains OS-assigned ephemeral ports.
    /// A configured range never falls back to an ephemeral port on exhaustion.
    pub relay_port_range: Option<(u16, u16)>,
    /// Explicit bounded UDP port pairs, mutually exclusive with a relay range.
    /// None retains range/ephemeral behaviour; Some must contain 1..=1024 pairs.
    /// Translation requires an explicit advertised_ip different from relay_ip.
    pub relay_port_mappings: Option<Vec<RelayPortMapping>>,
    pub advertised_ip: Option<IpAddr>,
    pub realm: String,
    pub secret: Vec<u8>,
    /// Explicit local testing opt-in, never enabled by default.
    pub allow_loopback_peers: bool,
    /// Explicit local bridge domain: 127.64.0.0/10 on the configured relay ports.
    /// The client listener is a concrete IPv4 address; the bridge owns peer transport.
    pub local_peer_bridge: bool,
    /// Authorised virtual peer aliases, changed by the embedding bridge host.
    pub bridge_peer_ips: HashSet<std::net::Ipv4Addr>,
    pub max_allocations: usize,
    pub max_per_user: usize,
    pub max_connections: usize,
    /// Aggregate bytes across both directions per allocation.
    pub bytes_per_second: u64,
    #[cfg(feature = "tls")]
    pub tls: Option<(SocketAddr, Arc<rustls::ServerConfig>)>,
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    fn drive_until(server: &mut Server, ready: impl Fn(&Server) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !ready(server) && Instant::now() < deadline {
            server.poll_once(Duration::from_millis(10)).unwrap();
        }
        assert!(ready(server), "stream did not progress before the deadline");
    }

    fn accept_stream(server: &mut Server) {
        let connections = server.connections.len();
        drive_until(server, |server| server.connections.len() > connections);
    }

    fn wait_for_queued(server: &Server, token: Token, bytes: usize) {
        let mut queued = vec![0; bytes];
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut received = 0;
        while received < bytes && Instant::now() < deadline {
            match server.connections[&token].socket.peek(&mut queued) {
                Ok(n) => received = n,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => (),
                Err(error) => panic!("peek failed: {error}"),
            }
            std::thread::yield_now();
        }
        assert_eq!(received, bytes, "the valid burst is fully queued");
    }

    fn binding_response(client: &mut std::net::TcpStream, transaction: [u8; 12]) {
        let mut header = [0; 20];
        client.read_exact(&mut header).unwrap();
        let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let mut bytes = vec![0; 20 + len];
        bytes[..20].copy_from_slice(&header);
        client.read_exact(&mut bytes[20..]).unwrap();
        let response = Message::parse(&bytes).unwrap();
        assert_eq!((response.method, response.class), (BINDING, 2));
        assert_eq!(response.transaction, transaction);
    }

    #[test]
    #[cfg(all(feature = "connected-udp", unix))]
    fn stream_processes_valid_batch_larger_than_input_limit() {
        let mut config = Config::local(vec![1; 32]);
        config.listen.set_port(0);
        let mut server = Server::bind(config).unwrap();
        let mut client = std::net::TcpStream::connect(server.local_addr().unwrap()).unwrap();
        client.set_nodelay(true).unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        accept_stream(&mut server);
        let token = *server.connections.keys().next().unwrap();
        socket2::SockRef::from(&server.connections[&token].socket)
            .set_recv_buffer_size(1_048_576)
            .unwrap();
        socket2::SockRef::from(&client)
            .set_send_buffer_size(1_048_576)
            .unwrap();

        let padding = vec![0x5a; 60_000];
        let mut batch = Vec::new();
        for value in 1..=4 {
            let mut request = Builder::new(BINDING, 0, [value; 12]);
            request.attr(0xc001, &padding); // Comprehension-optional padding.
            let frame = request.finish(None);
            assert!(frame.len() <= MAX_PACKET);
            assert!(Message::parse(&frame).is_some());
            batch.extend_from_slice(&frame);
        }
        assert!(batch.len() > MAX_QUEUE);
        client.write_all(&batch).unwrap();
        wait_for_queued(&server, token, batch.len());

        server.stream(token, &mut [0; MAX_PACKET + HEADROOM]);
        assert!(
            server.connections.contains_key(&token),
            "{} valid queued bytes must be parsed without closing at the {}-byte input cap",
            batch.len(),
            MAX_QUEUE
        );
        assert!(server.connections[&token].queued);
        assert!(server.connections[&token].input.len() <= MAX_QUEUE);
        // No second OS edge: the budget continuation must drain the rest.
        server
            .poll
            .registry()
            .deregister(&mut server.connections.get_mut(&token).unwrap().socket)
            .unwrap();
        drive_until(&mut server, |server| server.pending_streams.is_empty());
        assert!(server.connections[&token].input.is_empty());
        for value in 1..=4 {
            binding_response(&mut client, [value; 12]);
        }
    }

    #[test]
    fn stream_retains_partial_frames_and_cleans_up_only_closed_connections() {
        let mut config = Config::local(vec![1; 32]);
        config.listen.set_port(0);
        let mut server = Server::bind(config).unwrap();
        let mut client = std::net::TcpStream::connect(server.local_addr().unwrap()).unwrap();
        client.set_nodelay(true).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        accept_stream(&mut server);
        let token = *server.connections.keys().next().unwrap();
        let requests: Vec<_> = (1..=4)
            .map(|value| Builder::new(BINDING, 0, [value; 12]).finish(None))
            .collect();

        // A complete request and the next partial header share one read turn.
        let mut first = requests[0].clone();
        first.extend_from_slice(&requests[1][..9]);
        client.write_all(&first).unwrap();
        drive_until(&mut server, |server| {
            server.connections[&token].input == requests[1][..9]
        });
        binding_response(&mut client, [1; 12]);

        // Complete that header and coalesce another whole request behind it.
        let mut next = requests[1][9..].to_vec();
        next.extend_from_slice(&requests[2]);
        client.write_all(&next).unwrap();
        drive_until(&mut server, |server| {
            server.connections[&token].input.is_empty()
        });
        binding_response(&mut client, [2; 12]);
        binding_response(&mut client, [3; 12]);

        let mut healthy = std::net::TcpStream::connect(server.local_addr().unwrap()).unwrap();
        healthy
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        accept_stream(&mut server);
        let healthy_token = *server
            .connections
            .keys()
            .find(|other| **other != token)
            .unwrap();
        client.write_all(&[0x80, 0, 0, 0]).unwrap();
        drive_until(&mut server, |server| {
            !server.connections.contains_key(&token)
        });
        assert_eq!(client.read(&mut [0]).unwrap(), 0);
        assert!(server.connections.contains_key(&healthy_token));

        healthy.write_all(&requests[3]).unwrap();
        drive_until(&mut server, |server| {
            server.connections[&healthy_token].last_active
                > server.connections[&healthy_token].created
        });
        binding_response(&mut healthy, [4; 12]);
        drop(healthy);
        drive_until(&mut server, |server| server.connections.is_empty());
    }

    #[test]
    fn stream_processes_complete_frames_before_eof() {
        let mut config = Config::local(vec![1; 32]);
        config.listen.set_port(0);
        let mut server = Server::bind(config).unwrap();
        let mut client = std::net::TcpStream::connect(server.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        accept_stream(&mut server);
        let mut batch = Builder::new(BINDING, 0, [1; 12]).finish(None);
        batch.extend_from_slice(&Builder::new(BINDING, 0, [2; 12]).finish(None));
        // The incomplete final header is discarded at EOF, after complete frames.
        batch.extend_from_slice(&[0, 1, 0]);
        client.write_all(&batch).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !server.connections.is_empty() && Instant::now() < deadline {
            server.poll_once(Duration::from_millis(10)).unwrap();
        }
        assert!(server.connections.is_empty());
        binding_response(&mut client, [1; 12]);
        binding_response(&mut client, [2; 12]);
        assert_eq!(client.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn stream_frame_budget_resumes_buffered_frames_without_new_readiness() {
        let mut config = Config::local(vec![1; 32]);
        config.listen.set_port(0);
        let mut server = Server::bind(config).unwrap();
        let mut client = std::net::TcpStream::connect(server.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        accept_stream(&mut server);
        let token = *server.connections.keys().next().unwrap();
        let mut batch = Vec::new();
        for value in 0..=STREAM_FRAMES_PER_TURN {
            batch.extend_from_slice(&Builder::new(BINDING, 0, [value as u8; 12]).finish(None));
        }
        client.write_all(&batch).unwrap();
        wait_for_queued(&server, token, batch.len());
        server.stream(token, &mut [0; MAX_PACKET + HEADROOM]);
        let conn = &server.connections[&token];
        assert!(conn.queued);
        assert!(conn.input_offset != 0 && conn.input_offset < conn.input.len());
        assert_eq!(
            conn.input.len(),
            batch.len(),
            "consumed prefix stays in place"
        );
        assert_eq!(server.pending_streams.len(), 1);

        server
            .poll
            .registry()
            .deregister(&mut server.connections.get_mut(&token).unwrap().socket)
            .unwrap();
        // Consume any old listener event as well. Only the deferred work can
        // wake the next turn, which must parse input before another read.
        let mut old_events = Events::with_capacity(16);
        server
            .poll
            .poll(&mut old_events, Some(Duration::ZERO))
            .unwrap();
        let started = Instant::now();
        server.poll_once(Duration::from_secs(5)).unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(server.pending_streams.is_empty());
        assert!(server.connections[&token].input.is_empty());
        for value in 0..=STREAM_FRAMES_PER_TURN {
            binding_response(&mut client, [value as u8; 12]);
        }
    }

    #[test]
    fn deferred_streams_deduplicate_and_remove_closed_or_stale_tokens() {
        let mut config = Config::local(vec![1; 32]);
        config.listen.set_port(0);
        config.max_connections = 1;
        let mut server = Server::bind(config).unwrap();
        for _ in 0..16 {
            let client = std::net::TcpStream::connect(server.local_addr().unwrap()).unwrap();
            drive_until(&mut server, |server| !server.connections.is_empty());
            let token = *server.connections.keys().next().unwrap();
            for _ in 0..4 {
                server.queue_stream(token);
            }
            assert_eq!(server.pending_streams.len(), 1);
            server.close(token);
            assert!(server.pending_streams.is_empty());
            server.queue_stream(token);
            assert!(server.pending_streams.is_empty());
            // A stale token is harmless even if already dequeued elsewhere.
            server.pending_streams.push_back(token);
            server.poll_once(Duration::from_secs(1)).unwrap();
            assert!(server.pending_streams.is_empty());
            drop(client);
        }
    }

    #[test]
    fn hot_stream_yields_to_other_clients_and_expiry_sweeps() {
        let mut config = Config::local(vec![1; 32]);
        config.listen.set_port(0);
        let mut server = Server::bind(config).unwrap();
        let mut hot = std::net::TcpStream::connect(server.local_addr().unwrap()).unwrap();
        hot.set_nodelay(true).unwrap();
        accept_stream(&mut server);
        let hot_token = *server.connections.keys().next().unwrap();
        let indication = Builder::new(BINDING, 1, [1; 12]).finish(None);
        let backlog = indication.repeat(STREAM_FRAMES_PER_TURN * 16);
        hot.write_all(&backlog).unwrap();
        wait_for_queued(&server, hot_token, backlog.len());

        let mut healthy = std::net::TcpStream::connect(server.local_addr().unwrap()).unwrap();
        healthy
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        accept_stream(&mut server);
        let healthy_token = *server
            .connections
            .keys()
            .max_by_key(|token| token.0)
            .unwrap();
        let expired = std::net::TcpStream::connect(server.local_addr().unwrap()).unwrap();
        accept_stream(&mut server);
        let expired_token = *server
            .connections
            .keys()
            .max_by_key(|token| token.0)
            .unwrap();
        server.connections.get_mut(&expired_token).unwrap().created =
            Instant::now() - Duration::from_secs(16);
        server.sweep_at = Instant::now();
        let sweep_before = server.sweep_at;

        let request = Builder::new(BINDING, 0, [254; 12]).finish(None);
        healthy.write_all(&request).unwrap();
        wait_for_queued(&server, healthy_token, request.len());
        // Force both clients through the same bounded ready snapshot.
        server.queue_stream(hot_token);
        server.queue_stream(healthy_token);
        server.poll_once(Duration::from_secs(5)).unwrap();
        binding_response(&mut healthy, [254; 12]);
        assert!(
            server.connections[&hot_token].queued,
            "hot work remains for the next turn"
        );
        assert!(server.pending_streams.len() <= server.config.max_connections);
        assert!(
            server
                .connections
                .values()
                .all(|conn| conn.input.len() <= MAX_QUEUE)
        );
        assert!(!server.connections.contains_key(&expired_token));
        assert!(server.sweep_at > sweep_before);
        drop(expired);
    }

    #[test]
    #[cfg(feature = "tls")]
    fn tls_control_reads_consume_budget_without_plaintext_or_false_eof() {
        #[derive(Debug)]
        struct NoCertificate;
        impl rustls::server::ResolvesServerCert for NoCertificate {
            fn resolve(
                &self,
                _: rustls::server::ClientHello<'_>,
            ) -> Option<Arc<rustls::sign::CertifiedKey>> {
                None
            }
        }

        let mut config = Config::local(vec![1; 32]);
        config.listen.set_port(0);
        let mut server = Server::bind(config).unwrap();
        let mut client = std::net::TcpStream::connect(server.local_addr().unwrap()).unwrap();
        accept_stream(&mut server);
        let token = *server.connections.keys().next().unwrap();
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(NoCertificate));
        server.connections.get_mut(&token).unwrap().tls =
            Some(rustls::ServerConnection::new(Arc::new(tls)).unwrap());
        // A TLS handshake-record fragment produces no application plaintext.
        client.write_all(&[22]).unwrap();
        wait_for_queued(&server, token, 1);
        let mut budget = StreamBudget {
            reads: 2,
            bytes: 16,
            frames: STREAM_FRAMES_PER_TURN,
        };
        let conn = server.connections.get_mut(&token).unwrap();
        assert!(matches!(
            conn.read(&mut [0; 32], &mut budget).unwrap(),
            StreamRead::Yielded
        ));
        assert_eq!((budget.reads, budget.bytes), (0, 15));
        assert!(conn.input.is_empty());
        budget.reads = 2;
        budget.bytes = 0;
        assert!(matches!(
            conn.read(&mut [0; 32], &mut budget).unwrap(),
            StreamRead::Yielded
        ));
    }

    #[test]
    #[cfg(all(feature = "tls", feature = "connected-udp", unix))]
    fn tls_flush_retries_application_after_ciphertext_drain() {
        use std::{
            fs::{self, File, OpenOptions},
            io::BufReader,
            os::unix::fs::{DirBuilderExt, OpenOptionsExt},
            path::PathBuf,
            process::{Child, Command, Stdio},
        };

        struct FixtureDirectory(PathBuf);
        impl Drop for FixtureDirectory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        struct CertificateProcess(Child);
        impl Drop for CertificateProcess {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        // Ephemeral localhost material only: no fixed key/certificate is kept
        // in source, and both the process and its private directory have owners.
        let mut random = [0; 12];
        getrandom::fill(&mut random).unwrap();
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let directory = std::env::temp_dir().join(format!("spry-tls-flush-{suffix}"));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let fixture = FixtureDirectory(directory);
        let certificate = fixture.0.join("certificate.pem");
        let private_key = fixture.0.join("private-key.pem");
        let openssl_config = fixture.0.join("openssl.cnf");
        for path in [&certificate, &private_key, &openssl_config] {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .unwrap();
        }
        fs::write(
            &openssl_config,
            "[req]\ndistinguished_name=dn\n[dn]\nCN=localhost\n",
        )
        .unwrap();
        let mut generating = CertificateProcess(
            Command::new("openssl")
                .args([
                    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-config",
                ])
                .arg(&openssl_config)
                .args([
                    "-subj",
                    "/CN=localhost",
                    "-addext",
                    "subjectAltName=DNS:localhost,IP:127.0.0.1",
                    "-addext",
                    "basicConstraints=critical,CA:FALSE",
                    "-addext",
                    "keyUsage=critical,digitalSignature,keyEncipherment",
                    "-addext",
                    "extendedKeyUsage=serverAuth",
                    "-keyout",
                ])
                .arg(&private_key)
                .arg("-out")
                .arg(&certificate)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let generation_deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = generating.0.try_wait().unwrap() {
                assert!(status.success(), "localhost certificate generation failed");
                break;
            }
            assert!(
                Instant::now() < generation_deadline,
                "localhost certificate generation exceeded its deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(generating);
        let certificates =
            rustls_pemfile::certs(&mut BufReader::new(File::open(certificate).unwrap()))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        let key =
            rustls_pemfile::private_key(&mut BufReader::new(File::open(private_key).unwrap()))
                .unwrap()
                .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificates[0].clone()).unwrap();
        let tls_server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .unwrap();
        let tls_client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut client_tls = rustls::ClientConnection::new(
            Arc::new(tls_client),
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let mut config = Config::local(vec![1; 32]);
        config.listen.set_port(0);
        config.tls = Some(("127.0.0.1:0".parse().unwrap(), Arc::new(tls_server)));
        let mut server = Server::bind(config).unwrap();
        let mut client = std::net::TcpStream::connect(
            server.tls_listener.as_ref().unwrap().local_addr().unwrap(),
        )
        .unwrap();
        client.set_nonblocking(true).unwrap();
        client.set_nodelay(true).unwrap();
        accept_stream(&mut server);
        let token = *server.connections.keys().next().unwrap();
        socket2::SockRef::from(&server.connections[&token].socket)
            .set_send_buffer_size(65_536)
            .unwrap();
        let handshake_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            while client_tls.wants_write() {
                match client_tls.write_tls(&mut client) {
                    Ok(0) => panic!("TLS client closed during handshake"),
                    Ok(_) => (),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => panic!("TLS client write failed: {error}"),
                }
            }
            server.poll_once(Duration::from_millis(1)).unwrap();
            match client_tls.read_tls(&mut client) {
                Ok(0) => panic!("TLS server closed during handshake"),
                Ok(_) => {
                    client_tls.process_new_packets().unwrap();
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => (),
                Err(error) => panic!("TLS client read failed: {error}"),
            }
            let tls = server.connections[&token].tls.as_ref().unwrap();
            if !client_tls.is_handshaking()
                && !client_tls.wants_write()
                && !tls.is_handshaking()
                && !tls.wants_write()
            {
                break;
            }
            assert!(
                Instant::now() < handshake_deadline,
                "TLS handshake timed out"
            );
        }

        // Stage the exact reachable transition without saturating a kernel
        // socket: a small fixture-only rustls cap makes its writer return zero
        // while ciphertext and a separate application tail are both queued.
        let prefix = vec![0x35; 1024];
        let tail = vec![0x79; 512];
        let conn = server.connections.get_mut(&token).unwrap();
        assert!(!conn.writable_interest, "handshake output already drained");
        let tls = conn.tls.as_mut().unwrap();
        tls.set_buffer_limit(Some(prefix.len()));
        assert_eq!(tls.writer().write(&prefix).unwrap(), prefix.len());
        assert!(tls.wants_write());
        assert_eq!(tls.writer().write(b"not accepted").unwrap(), 0);
        conn.queue(&tail).unwrap();
        conn.update_interest(server.poll.registry(), token, true)
            .unwrap();
        assert!(conn.writable_interest);
        // Consume the actual already-armed edge. Neither another inbound
        // plaintext request nor another application queue call may rescue it.
        let mut events = Events::with_capacity(16);
        let writable_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            server
                .poll
                .poll(&mut events, Some(Duration::from_millis(10)))
                .unwrap();
            if events
                .iter()
                .any(|event| event.token() == token && event.is_writable())
            {
                break;
            }
            assert!(
                Instant::now() < writable_deadline,
                "socket was not writable"
            );
        }
        server.stream(token, &mut [0; MAX_PACKET + HEADROOM]);
        let conn = server
            .connections
            .get(&token)
            .expect("TLS stream stays open");
        assert!(
            !conn.tls.as_ref().unwrap().wants_write(),
            "fixture ciphertext must drain into the writable socket"
        );
        assert!(
            conn.output.is_empty(),
            "TLS ciphertext drained but the application tail was stranded"
        );
        assert_eq!(conn.written, 0);
        assert!(
            !conn.writable_interest,
            "drained stream returns to READ only"
        );
        assert!(
            conn.input.is_empty(),
            "no new client plaintext was supplied"
        );

        let expected = [prefix, tail].concat();
        let mut received = Vec::new();
        let mut buffer = [0; 4096];
        let receive_deadline = Instant::now() + Duration::from_secs(5);
        while received.len() < expected.len() {
            match client_tls.read_tls(&mut client) {
                Ok(0) => panic!("TLS connection closed before the queued bytes arrived"),
                Ok(_) => {
                    client_tls.process_new_packets().unwrap();
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => (),
                Err(error) => panic!("TLS receive failed: {error}"),
            }
            loop {
                match client_tls.reader().read(&mut buffer) {
                    Ok(0) => panic!("TLS plaintext ended before the queued bytes arrived"),
                    Ok(n) => received.extend_from_slice(&buffer[..n]),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => panic!("TLS plaintext read failed: {error}"),
                }
            }
            assert!(
                Instant::now() < receive_deadline,
                "TLS payload drain timed out"
            );
            std::thread::yield_now();
        }
        assert_eq!(received, expected);
    }

    #[test]
    #[cfg(all(feature = "connected-udp", unix))]
    fn relay_overload_preserves_stream_and_resumes_both_framing_paths() {
        for channel in [None, Some(0x4000_u16)] {
            let mut config = Config::local(vec![1; 32]);
            config.listen.set_port(0);
            let mut server = Server::bind(config).unwrap();
            let mut client = std::net::TcpStream::connect(server.local_addr().unwrap()).unwrap();
            client.set_nonblocking(true).unwrap();
            // Leave the receive window at its OS default. The non-reading
            // client and small server send buffer provide real backpressure.
            accept_stream(&mut server);
            let token = *server.connections.keys().next().unwrap();
            let key = Client::Stream(token);
            socket2::SockRef::from(&server.connections[&token].socket)
                .set_send_buffer_size(1024)
                .unwrap();
            let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let peer_address = peer.local_addr().unwrap();
            let relay_socket = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let address = relay_socket.local_addr().unwrap();
            let relay_token = server.relays.reserve(key);
            let expires = Instant::now() + Duration::from_secs(60);
            // Generated authorised state isolates overload from the separately
            // tested authentication path; both actual UDP framing branches run.
            server.allocations.insert(
                key,
                Allocation {
                    socket: relay_socket,
                    client_socket: None,
                    token: relay_token,
                    bound_address: address,
                    advertised_address: address,
                    username: "overload-fixture".into(),
                    transaction: [1; 12],
                    expires,
                    permissions: vec![Permission {
                        ip: peer_address.ip(),
                        expires,
                    }],
                    channels: channel
                        .map(|number| Channel {
                            number,
                            peer: peer_address,
                            expires,
                        })
                        .into_iter()
                        .collect(),
                    bandwidth: Bucket::new(64 * 1024 * 1024, 128 * 1024 * 1024, Instant::now()),
                },
            );

            let block = vec![0x5a; 32_768];
            let mut expected = 0;
            for _ in 0..1024 {
                server.send_client(key, &block);
                expected += block.len();
                let conn = server
                    .connections
                    .get(&token)
                    .expect("bounded fill stays connected");
                if conn.written < conn.output.len() {
                    break;
                }
            }
            let conn = server.connections.get_mut(&token).unwrap();
            let pending = conn.output.len() - conn.written;
            assert!(pending != 0, "socket is genuinely backpressured");
            let fill = MAX_QUEUE - STREAM_CONTROL_RESERVE - pending;
            conn.queue(&vec![0x5a; fill]).unwrap();
            expected += fill;
            let queued = conn.output.clone();
            let written = conn.written;

            let payload = vec![0x7e; 2048];
            peer.send_to(&payload, address).unwrap();
            let mut scratch = vec![0; MAX_PACKET + HEADROOM];
            let wait_for_peer = |server: &Server| {
                let queued_by = Instant::now() + Duration::from_secs(2);
                let mut peek = [0; 2048];
                loop {
                    match server.allocations[&key].socket.peek_from(&mut peek) {
                        Ok((n, from)) => {
                            assert_eq!((n, from), (payload.len(), peer_address));
                            break;
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < queued_by, "peer datagram did not arrive");
                            std::thread::yield_now();
                        }
                        Err(e) => panic!("peer peek failed: {e}"),
                    }
                }
            };
            wait_for_peer(&server);
            server.receive_peer(relay_token, &mut scratch);
            assert!(
                server.connections.contains_key(&token),
                "UDP overload must retain control stream"
            );
            assert!(server.allocations.contains_key(&key));
            let conn = &server.connections[&token];
            assert_eq!(
                (&conn.output, conn.written),
                (&queued, written),
                "drop cannot truncate or partly queue a frame"
            );
            assert_eq!(server.stats.dropped_packets, 1);
            assert_eq!(
                (server.stats.forwarded_packets, server.stats.forwarded_bytes),
                (0, 0)
            );

            // Ordinary control traffic still has space within the same cap.
            server.send_client(key, b"ctrl");
            expected += 4;
            assert!(server.connections.contains_key(&token));
            // Saturation is proven above. Restore send capacity so recovery
            // tests writable progress rather than OS delayed-ACK pacing.
            socket2::SockRef::from(&server.connections[&token].socket)
                .set_send_buffer_size(1_048_576)
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut received = Vec::new();
            while received.len() < expected && Instant::now() < deadline {
                match client.read(&mut scratch) {
                    Ok(0) => panic!("control stream closed while draining"),
                    Ok(n) => received.extend_from_slice(&scratch[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => (),
                    Err(e) => panic!("drain failed: {e}"),
                }
                server.poll_once(Duration::from_millis(1)).unwrap();
            }
            assert_eq!(received.len(), expected);
            assert!(received[..expected - 4].iter().all(|byte| *byte == 0x5a));
            assert_eq!(&received[expected - 4..], b"ctrl");
            assert!(server.connections[&token].output.is_empty());

            peer.send_to(&payload, address).unwrap();
            wait_for_peer(&server);
            server.receive_peer(relay_token, &mut scratch);
            assert_eq!(server.stats.dropped_packets, 1);
            assert_eq!(
                (server.stats.forwarded_packets, server.stats.forwarded_bytes),
                (1, payload.len() as u64)
            );
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut bytes = Vec::new();
            loop {
                match client.read(&mut scratch) {
                    Ok(0) => panic!("resumed stream closed"),
                    Ok(n) => bytes.extend_from_slice(&scratch[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => (),
                    Err(e) => panic!("resumed read failed: {e}"),
                }
                server.poll_once(Duration::from_millis(1)).unwrap();
                if wire::frame_len(&bytes).is_some_and(|len| len == bytes.len()) {
                    break;
                }
                assert!(Instant::now() < deadline, "resumed frame did not drain");
            }
            if let Some(number) = channel {
                assert_eq!(wire::channel(&bytes), Some((number, payload.as_slice())));
            } else {
                let indication = Message::parse(&bytes).unwrap();
                assert_eq!((indication.method, indication.class), (DATA_METHOD, 1));
                assert_eq!(indication.attr(DATA), Some(payload.as_slice()));
            }
            // Control overload still uses the original full-cap close policy.
            server
                .connections
                .get_mut(&token)
                .unwrap()
                .queue(&vec![0; MAX_QUEUE])
                .unwrap();
            server.send_client(key, b"x");
            assert!(!server.connections.contains_key(&token));
            assert!(!server.allocations.contains_key(&key));
            assert_eq!(server.stats.dropped_packets, 1);
        }
    }

    #[test]
    #[cfg(all(feature = "connected-udp", unix))]
    fn stream_backpressure_rearms_and_returns_to_read_interest() {
        let mut config = Config::local(vec![1; 32]);
        config.listen.set_port(0);
        let mut server = Server::bind(config).unwrap();
        let mut client = std::net::TcpStream::connect(server.local_addr().unwrap()).unwrap();
        client.set_nonblocking(true).unwrap();
        let accepting = Instant::now() + Duration::from_secs(2);
        while server.connections.is_empty() {
            server.poll_once(Duration::from_millis(1)).unwrap();
            assert!(Instant::now() < accepting, "TCP client was not accepted");
        }
        let token = *server.connections.keys().next().unwrap();
        socket2::SockRef::from(&server.connections[&token].socket)
            .set_send_buffer_size(1024)
            .unwrap();
        let payload = vec![0x5a; 32_768];
        let mut expected = 0;
        // Fill the actual socket until the nonblocking writer queues data.
        // Stop as soon as it does, keeping the application queue bounded.
        for _ in 0..1024 {
            server.send_client(Client::Stream(token), &payload);
            expected += payload.len();
            let conn = server
                .connections
                .get(&token)
                .expect("queue remains bounded");
            if conn.writable_interest {
                assert!(conn.written < conn.output.len());
                break;
            }
        }
        assert!(server.connections[&token].writable_interest);
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut received = 0;
        let mut buffer = [0; 65_536];
        while received < expected && Instant::now() < deadline {
            match client.read(&mut buffer) {
                Ok(n) => {
                    assert!(n != 0, "connection stays open while draining");
                    assert!(buffer[..n].iter().all(|byte| *byte == 0x5a));
                    received += n;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => (),
                Err(error) => panic!("drain failed: {error}"),
            }
            server.poll_once(Duration::from_millis(1)).unwrap();
        }
        assert_eq!(received, expected);
        let conn = &server.connections[&token];
        assert!(conn.output.is_empty());
        assert!(!conn.writable_interest);

        // A later response still progresses after write interest is removed.
        server.send_client(Client::Stream(token), b"resumed");
        client.set_nonblocking(false).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut resumed = [0; 7];
        client.read_exact(&mut resumed).unwrap();
        assert_eq!(&resumed, b"resumed");
    }

    #[test]
    fn invalid_relay_ranges_are_refused_before_binding() {
        for range in [(0, 0), (0, 65535), (40001, 40000)] {
            let mut config = Config::local(vec![1; 32]);
            config.listen.set_port(0);
            config.relay_port_range = Some(range);
            assert!(Server::bind(config).is_err());
        }
    }

    #[test]
    fn mapped_ports_validate_before_binding() {
        let pair = RelayPortMapping {
            local_port: 41000,
            advertised_port: 51000,
        };
        for case in 0..10 {
            let mut config = Config::local(vec![1; 32]);
            config.listen.set_port(0);
            config.relay_port_mappings = Some(vec![pair]);
            config.advertised_ip = Some("203.0.113.7".parse().unwrap());
            match case {
                0 => config.relay_port_mappings = Some(vec![]),
                1 => config.relay_port_mappings.as_mut().unwrap()[0].local_port = 0,
                2 => config.relay_port_mappings.as_mut().unwrap()[0].advertised_port = 0,
                3 => config
                    .relay_port_mappings
                    .as_mut()
                    .unwrap()
                    .push(RelayPortMapping {
                        local_port: pair.local_port,
                        advertised_port: 51001,
                    }),
                4 => config
                    .relay_port_mappings
                    .as_mut()
                    .unwrap()
                    .push(RelayPortMapping {
                        local_port: 41001,
                        advertised_port: pair.advertised_port,
                    }),
                5 => {
                    config.relay_port_mappings = Some(
                        (0..=MAX_RELAY_PORT_MAPPINGS)
                            .map(|index| RelayPortMapping {
                                local_port: 10000 + index as u16,
                                advertised_port: 20000 + index as u16,
                            })
                            .collect(),
                    );
                }
                6 => config.relay_port_range = Some((41000, 41001)),
                7 => config.local_peer_bridge = true,
                8 => config.listen.set_port(pair.local_port),
                _ => config.advertised_ip = Some("::1".parse().unwrap()),
            }
            assert!(Server::bind(config).is_err(), "case {case}");
        }
        let mut config = Config::local(vec![1; 32]);
        config.listen = "0.0.0.0:41000".parse().unwrap();
        config.relay_port_mappings = Some(vec![pair]);
        config.advertised_ip = Some("203.0.113.7".parse().unwrap());
        assert!(Server::bind(config).is_err());
    }

    #[test]
    fn mapped_port_capacity_accepts_the_unique_maximum_without_prebinding_relays() {
        let mut config = Config::local(vec![1; 32]);
        config.listen.set_port(0);
        config.advertised_ip = Some("203.0.113.7".parse().unwrap());
        config.relay_port_mappings = Some(
            (0..MAX_RELAY_PORT_MAPPINGS)
                .map(|index| RelayPortMapping {
                    local_port: 10000 + index as u16,
                    advertised_port: 20000 + index as u16,
                })
                .collect(),
        );
        let server = Server::bind(config).unwrap();
        assert_eq!(server.allocated_relay_ports().count(), 0);
    }

    #[test]
    fn translated_ports_require_a_distinct_advertised_ip_but_identity_pairs_do_not() {
        for advertised_ip in [None, Some("127.0.0.1".parse().unwrap())] {
            let mut config = Config::local(vec![1; 32]);
            config.listen.set_port(0);
            config.advertised_ip = advertised_ip;
            config.relay_port_mappings = Some(vec![RelayPortMapping {
                local_port: 41000,
                advertised_port: 51000,
            }]);
            let error = Server::bind(config.clone())
                .err()
                .expect("translation refused");
            assert!(error.to_string().contains("translated relay ports"));
            config.relay_port_mappings = Some(vec![
                RelayPortMapping {
                    local_port: 41000,
                    advertised_port: 41000,
                },
                RelayPortMapping {
                    local_port: 41002,
                    advertised_port: 41002,
                },
            ]);
            let server = Server::bind(config).unwrap();
            assert_eq!(server.allocated_relay_ports().count(), 0);
        }
    }

    #[test]
    fn mapped_loopback_endpoints_require_the_explicit_test_opt_in() {
        let mut config = Config::local(vec![1; 32]);
        config.advertised_ip = Some("127.0.0.2".parse().unwrap());
        config.relay_port_mappings = Some(vec![RelayPortMapping {
            local_port: 41000,
            advertised_port: 51000,
        }]);
        let local = HashSet::from([41000]);
        let public = HashSet::from([51000]);
        for endpoint in ["127.0.0.1:41000", "127.0.0.2:51000"] {
            let endpoint = endpoint.parse().unwrap();
            assert!(!Server::allowed_peer(&config, &local, &public, endpoint));
            config.allow_loopback_peers = true;
            assert!(Server::allowed_peer(&config, &local, &public, endpoint));
            config.allow_loopback_peers = false;
        }
        config.allow_loopback_peers = true;
        for endpoint in ["127.0.0.1:51000", "127.0.0.2:41000"] {
            assert!(!Server::allowed_peer(
                &config,
                &local,
                &public,
                endpoint.parse().unwrap()
            ));
        }
    }

    #[test]
    fn mapped_own_addresses_require_matching_live_endpoint_pairs() {
        let mut config = Config::local(vec![1; 32]);
        config.relay_ip = "127.0.0.1".parse().unwrap();
        config.advertised_ip = Some("203.0.113.7".parse().unwrap());
        config.allow_loopback_peers = true;
        config.relay_port_mappings = Some(vec![RelayPortMapping {
            local_port: 41000,
            advertised_port: 51000,
        }]);
        let local = HashSet::from([41000]);
        let public = HashSet::from([51000]);
        for endpoint in ["127.0.0.1:41000", "203.0.113.7:51000"] {
            assert!(Server::allowed_peer(
                &config,
                &local,
                &public,
                endpoint.parse().unwrap()
            ));
            assert!(!Server::allowed_peer(
                &config,
                &HashSet::new(),
                &HashSet::new(),
                endpoint.parse().unwrap()
            ));
        }
        for endpoint in [
            "127.0.0.1:51000",
            "203.0.113.7:41000",
            "127.0.0.1:22",
            "203.0.113.7:22",
        ] {
            assert!(!Server::allowed_peer(
                &config,
                &local,
                &public,
                endpoint.parse().unwrap()
            ));
        }
    }

    #[test]
    #[cfg(feature = "direct-index")]
    fn recycled_slots_ignore_stale_events_and_stay_bounded() {
        let a = Client::Datagram("127.0.0.1:1234".parse().unwrap());
        let b = Client::Datagram("127.0.0.1:1235".parse().unwrap());
        let mut slots = RelaySlots::default();
        let old = slots.reserve(a);
        assert_eq!(slots.get(&Token(old.0 | 2)), Some(&a));
        assert_eq!(slots.remove(&old), Some(a));
        let current = slots.reserve(b);
        assert_ne!(old, current);
        assert_eq!(slots.get(&old), None);
        assert_eq!(slots.remove(&old), None);
        assert_eq!(slots.get(&current), Some(&b));
        slots.remove(&current);
        for _ in 0..10000 {
            let token = slots.reserve(a);
            assert_eq!(slots.remove(&token), Some(a));
        }
        assert_eq!(slots.entries.len(), 1);
        assert!(slots.get(&Token(0)).is_none());
        assert!(slots.get(&Token(1)).is_none());
        assert!(slots.get(&Token(2)).is_none());
        assert!(slots.get(&Token(usize::MAX)).is_none());
    }

    #[test]
    fn local_bridge_domain_excludes_host_services_and_other_networks() {
        let mut config = Config::local(vec![1; 32]);
        config.local_peer_bridge = true;
        config.relay_ip = "127.64.1.1".parse().unwrap();
        config.relay_port_range = Some((49160, 49191));
        config.bridge_peer_ips = [
            "127.64.1.2".parse().unwrap(),
            "127.127.255.255".parse().unwrap(),
        ]
        .into();
        let ports = HashSet::from([49160]);
        for peer in ["127.64.1.2:49160", "127.127.255.255:49191"] {
            assert!(Server::allowed_peer(
                &config,
                &ports,
                &ports,
                peer.parse().unwrap()
            ));
        }
        assert!(Server::allowed_peer(
            &config,
            &ports,
            &ports,
            "127.64.1.1:49160".parse().unwrap()
        ));
        for peer in [
            "127.64.1.1:49161",
            "127.64.1.2:22",
            "127.64.1.2:49159",
            "127.64.1.2:49192",
            "127.64.1.3:49160",
            "127.0.0.1:49160",
            "127.128.0.1:49160",
            "10.0.0.1:49160",
            "203.0.113.2:49160",
            "[::1]:49160",
            "[::ffff:127.64.1.2]:49160",
        ] {
            assert!(
                !Server::allowed_peer(&config, &ports, &ports, peer.parse().unwrap()),
                "{peer}"
            );
        }
    }

    #[test]
    fn local_bridge_requires_concrete_client_binding_and_explicit_peer_bounds() {
        for case in 0..5 {
            let mut config = Config::local(vec![1; 32]);
            config.listen.set_port(0);
            config.local_peer_bridge = true;
            config.relay_ip = "127.64.1.1".parse().unwrap();
            config.relay_port_range = Some((49160, 49191));
            match case {
                0 => config.listen.set_ip("0.0.0.0".parse().unwrap()),
                1 => config.relay_ip = "127.0.0.1".parse().unwrap(),
                2 => config.relay_port_range = None,
                3 => config.allow_loopback_peers = true,
                _ => config.advertised_ip = Some("203.0.113.1".parse().unwrap()),
            }
            assert!(Server::bind(config).is_err());
        }
    }

    #[test]
    fn own_address_is_limited_to_live_relay_ports() {
        let mut config = Config::local(vec![1; 32]);
        config.relay_ip = "203.0.113.1".parse().unwrap();
        let mut ports = HashSet::from([50000]);
        assert!(Server::allowed_peer(
            &config,
            &ports,
            &ports,
            "203.0.113.1:50000".parse().unwrap()
        ));
        assert!(!Server::allowed_peer(
            &config,
            &ports,
            &ports,
            "203.0.113.1:22".parse().unwrap()
        ));
        ports.clear();
        assert!(!Server::allowed_peer(
            &config,
            &ports,
            &ports,
            "203.0.113.1:50000".parse().unwrap()
        ));
        assert!(!Server::allowed_peer(
            &config,
            &ports,
            &ports,
            "10.0.0.1:50000".parse().unwrap()
        ));
        assert!(!Server::allowed_peer(
            &config,
            &ports,
            &ports,
            "[::ffff:127.0.0.1]:22".parse().unwrap()
        ));
    }
}

impl Config {
    pub fn local(secret: Vec<u8>) -> Self {
        Self {
            listen: "127.0.0.1:3478".parse().expect("literal"),
            relay_ip: "127.0.0.1".parse().expect("literal"),
            relay_port_range: None,
            relay_port_mappings: None,
            advertised_ip: None,
            realm: "spry-turn".into(),
            secret,
            allow_loopback_peers: false,
            local_peer_bridge: false,
            bridge_peer_ips: HashSet::new(),
            max_allocations: 1024,
            max_per_user: 8,
            max_connections: 256,
            bytes_per_second: 64 * 1024 * 1024,
            #[cfg(feature = "tls")]
            tls: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
enum Client {
    Datagram(SocketAddr),
    Stream(Token),
}

/// Generation-tagged slots for internally assigned readiness tokens. Client
/// addresses still use a keyed map; no untrusted input is used as a slot index.
#[cfg(feature = "direct-index")]
#[derive(Default)]
struct RelaySlots {
    entries: Vec<(Token, Option<Client>)>,
    free: Vec<usize>,
}

#[cfg(feature = "direct-index")]
impl RelaySlots {
    const BITS: usize = usize::BITS as usize / 2;
    const MASK: usize = (1usize << Self::BITS) - 1;

    fn reserve(&mut self, client: Client) -> Token {
        let index = if let Some(index) = self.free.pop() {
            self.entries[index].0.0 = self.entries[index].0.0.wrapping_add(1usize << Self::BITS);
            index
        } else {
            let index = self.entries.len();
            self.entries.push((Token((index + 1) << 2), None));
            index
        };
        self.entries[index].1 = Some(client);
        self.entries[index].0
    }

    fn index(token: Token) -> Option<usize> {
        if token.0 & 1 != 0 {
            return None;
        }
        ((token.0 & Self::MASK) >> 2).checked_sub(1)
    }

    fn get(&self, token: &Token) -> Option<&Client> {
        let slot = self.entries.get(Self::index(*token)?)?;
        if slot.0 != Token(token.0 & !2) {
            return None;
        }
        slot.1.as_ref()
    }

    fn remove(&mut self, token: &Token) -> Option<Client> {
        let index = Self::index(*token)?;
        let slot = self.entries.get_mut(index)?;
        if slot.0 != Token(token.0 & !2) {
            return None;
        }
        let client = slot.1.take()?;
        self.free.push(index);
        Some(client)
    }
}

struct Permission {
    ip: IpAddr,
    expires: Instant,
}
struct Channel {
    number: u16,
    peer: SocketAddr,
    expires: Instant,
}
struct Allocation {
    socket: UdpSocket,
    #[cfg(feature = "connected-udp")]
    client_socket: Option<UdpSocket>,
    token: Token,
    bound_address: SocketAddr,
    advertised_address: SocketAddr,
    username: String,
    transaction: [u8; 12],
    expires: Instant,
    permissions: Vec<Permission>,
    channels: Vec<Channel>,
    bandwidth: Bucket,
}

enum StreamRead {
    Data,
    Pending,
    Closed,
    Yielded,
}

struct StreamBudget {
    reads: usize,
    bytes: usize,
    frames: usize,
}

impl StreamBudget {
    fn new() -> Self {
        Self {
            reads: STREAM_READS_PER_TURN,
            bytes: STREAM_BYTES_PER_TURN,
            frames: STREAM_FRAMES_PER_TURN,
        }
    }

    fn take_read(&mut self) -> bool {
        if self.reads == 0 || self.bytes == 0 {
            return false;
        }
        self.reads -= 1;
        true
    }
}

struct Connection {
    socket: TcpStream,
    peer: SocketAddr,
    input: Vec<u8>,
    input_offset: usize,
    output: Vec<u8>,
    written: usize,
    writable_interest: bool,
    queued: bool,
    last_active: Instant,
    created: Instant,
    #[cfg(feature = "tls")]
    tls: Option<rustls::ServerConnection>,
}

impl Connection {
    fn update_interest(
        &mut self,
        registry: &mio::Registry,
        token: Token,
        pending: bool,
    ) -> io::Result<()> {
        // Read interest stays enabled. Re-register only when backpressure
        // changes write interest, rather than making a kernel call per packet.
        if self.writable_interest != pending {
            let interest = if pending {
                Interest::READABLE | Interest::WRITABLE
            } else {
                Interest::READABLE
            };
            registry.reregister(&mut self.socket, token, interest)?;
            self.writable_interest = pending;
        }
        Ok(())
    }

    fn queue(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.output.len() - self.written + bytes.len() > MAX_QUEUE {
            return Err(io::Error::other("stream output limit"));
        }
        if self.written != 0 && self.output.len() + bytes.len() > MAX_QUEUE {
            self.output.drain(..self.written);
            self.written = 0;
        }
        self.output.extend_from_slice(bytes);
        self.last_active = Instant::now();
        Ok(())
    }

    fn read(&mut self, scratch: &mut [u8], budget: &mut StreamBudget) -> io::Result<StreamRead> {
        // Leave the consumed prefix in place on a frame-budget yield; compact
        // only when another read needs space, avoiding a copy per frame.
        if self.input_offset == self.input.len() {
            self.input.clear();
        } else if self.input_offset != 0 {
            self.input.drain(..self.input_offset);
        }
        self.input_offset = 0;
        loop {
            if !budget.take_read() {
                return Ok(StreamRead::Yielded);
            }
            let capacity = MAX_QUEUE
                .saturating_sub(self.input.len())
                .min(scratch.len())
                .min(budget.bytes);
            if capacity == 0 {
                return Err(io::Error::other("stream input limit"));
            }
            let scratch = &mut scratch[..capacity];
            #[cfg(feature = "tls")]
            if let Some(tls) = &mut self.tls {
                // A prior TLS read can leave decoded records behind a yield.
                // Drain them before waiting for another socket readiness edge.
                match tls.reader().read(scratch) {
                    Ok(0) => return Ok(StreamRead::Closed),
                    Ok(n) => {
                        self.input.extend_from_slice(&scratch[..n]);
                        budget.bytes -= n;
                        self.last_active = Instant::now();
                        return Ok(StreamRead::Data);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => (),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
                if !budget.take_read() {
                    return Ok(StreamRead::Yielded);
                }
                // Charge encrypted/control work too. A nonzero capacity keeps
                // this bounded reader from turning an exhausted budget into EOF.
                let mut socket = (&mut self.socket).take(capacity as u64);
                match tls.read_tls(&mut socket) {
                    Ok(0) => return Ok(StreamRead::Closed),
                    Ok(n) => {
                        budget.bytes -= n;
                        tls.process_new_packets().map_err(io::Error::other)?;
                        self.last_active = Instant::now();
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        return Ok(StreamRead::Pending);
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
                continue;
            }
            match self.socket.read(scratch) {
                Ok(0) => return Ok(StreamRead::Closed),
                Ok(n) => {
                    self.input.extend_from_slice(&scratch[..n]);
                    budget.bytes -= n;
                    self.last_active = Instant::now();
                    return Ok(StreamRead::Data);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(StreamRead::Pending);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }

    fn flush(&mut self) -> io::Result<bool> {
        #[cfg(feature = "tls")]
        if self.tls.is_some() {
            return self.flush_tls();
        }
        while self.written < self.output.len() {
            match self.socket.write(&self.output[self.written..]) {
                Ok(0) => break,
                Ok(n) => self.written += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        if self.written == self.output.len() {
            self.output.clear();
            self.written = 0;
        }
        Ok(!self.output.is_empty())
    }

    #[cfg(feature = "tls")]
    fn flush_tls(&mut self) -> io::Result<bool> {
        let tls = self.tls.as_mut().expect("TLS checked by flush");
        loop {
            while self.written < self.output.len() {
                match tls.writer().write(&self.output[self.written..]) {
                    Ok(0) => break,
                    Ok(n) => self.written += n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
            if self.written == self.output.len() {
                self.output.clear();
                self.written = 0;
            }
            let mut ciphertext_progress = false;
            while tls.wants_write() {
                match tls.write_tls(&mut self.socket) {
                    Ok(0) => return Ok(true),
                    Ok(_) => ciphertext_progress = true,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(true),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
            if self.output.is_empty() || !ciphertext_progress || tls.is_handshaking() {
                return Ok(!self.output.is_empty());
            }
            // Draining TLS records freed its writer's bounded capacity. Retry
            // the existing application queue before waiting for another edge.
            // No new application bytes enter this call; blocked/no-progress or
            // pre-handshake states above always return to the event loop.
        }
    }
}

/// Embed this server and drive `poll_once`, or use the standalone executable.
/// No room IDs, participant list, discovery, media keys or hosted defaults.
pub struct Server {
    config: Config,
    poll: Poll,
    events: Events,
    listener: UdpSocket,
    tcp: TcpListener,
    #[cfg(feature = "tls")]
    tls_listener: Option<TcpListener>,
    allocations: HashMap<Client, Allocation>,
    #[cfg(not(feature = "direct-index"))]
    relays: HashMap<Token, Client>,
    #[cfg(feature = "direct-index")]
    relays: RelaySlots,
    relay_ports: HashSet<u16>,
    advertised_relay_ports: HashSet<u16>,
    next_relay_mapping: usize,
    next_relay_port: u16,
    connections: HashMap<Token, Connection>,
    pending_streams: VecDeque<Token>,
    next_token: usize,
    nonces: auth::Nonces,
    requests: Bucket,
    sweep_at: Instant,
    input: Vec<u8>,
    stats: Stats,
}

pub fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn credential_lifetime(username: &str, requested: u32, now: SystemTime) -> Duration {
    let remaining = auth::expires(username)
        .and_then(|expiry| UNIX_EPOCH.checked_add(Duration::from_secs(expiry)))
        .and_then(|deadline| deadline.duration_since(now).ok())
        .unwrap_or_default();
    Duration::from_secs(u64::from(requested)).min(remaining)
}

impl Server {
    fn bind_listener(address: SocketAddr) -> io::Result<UdpSocket> {
        #[cfg(all(feature = "connected-udp", unix))]
        {
            let socket = socket2::Socket::new(
                socket2::Domain::for_address(address),
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )?;
            socket.set_reuse_port(true)?;
            socket.set_nonblocking(true)?;
            socket.bind(&address.into())?;
            Ok(UdpSocket::from_std(socket.into()))
        }
        #[cfg(not(all(feature = "connected-udp", unix)))]
        {
            UdpSocket::bind(address)
        }
    }

    #[cfg(feature = "connected-udp")]
    fn connected_client(&self, client: Client, token: Token) -> Option<UdpSocket> {
        #[cfg(unix)]
        {
            let Client::Datagram(peer) = client else {
                return None;
            };
            let address = self.listener.local_addr().ok()?;
            // A concrete IPv4 bind preserves the exact client-facing 5-tuple.
            // Wildcard and IPv6 listeners retain the standard portable path.
            if !address.is_ipv4() || address.ip().is_unspecified() || !peer.is_ipv4() {
                return None;
            }
            let socket = socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )
            .ok()?;
            socket.set_reuse_port(true).ok()?;
            socket.set_nonblocking(true).ok()?;
            socket.bind(&address.into()).ok()?;
            socket.connect(&peer.into()).ok()?;
            let mut socket = UdpSocket::from_std(socket.into());
            self.poll
                .registry()
                .register(&mut socket, Token(token.0 | 2), Interest::READABLE)
                .ok()?;
            Some(socket)
        }
        #[cfg(not(unix))]
        {
            let _ = (client, token);
            None
        }
    }

    #[cfg(feature = "connected-udp")]
    fn receive_client_socket(&mut self, token: Token, input: &mut [u8]) {
        let Some(client) = self.relays.get(&token).copied() else {
            return;
        };
        let Client::Datagram(peer) = client else {
            return;
        };
        loop {
            let Some(socket) = self
                .allocations
                .get_mut(&client)
                .and_then(|a| a.client_socket.as_mut())
            else {
                return;
            };
            let n = match socket.recv(input) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return,
            };
            self.receive(client, peer, &input[..n]);
        }
    }

    pub fn bind(config: Config) -> io::Result<Self> {
        if let Some(mappings) = &config.relay_port_mappings {
            let mut local = HashSet::new();
            let mut advertised = HashSet::new();
            if mappings.is_empty()
                || mappings.len() > MAX_RELAY_PORT_MAPPINGS
                || config.relay_port_range.is_some()
                || config.local_peer_bridge
                || mappings.iter().any(|mapping| {
                    mapping.local_port == 0
                        || mapping.advertised_port == 0
                        || !local.insert(mapping.local_port)
                        || !advertised.insert(mapping.advertised_port)
                        || (mapping.local_port == config.listen.port()
                            && (config.listen.ip().is_unspecified()
                                || config.listen.ip() == config.relay_ip))
                })
            {
                return Err(io::Error::other(
                    "relay port mappings require 1..=1024 unique nonzero local/public ports, no listener collision, range or peer bridge",
                ));
            }
            if mappings
                .iter()
                .any(|mapping| mapping.local_port != mapping.advertised_port)
                && config.advertised_ip.is_none_or(|ip| ip == config.relay_ip)
            {
                return Err(io::Error::other(
                    "translated relay ports require an explicit advertised IP different from the local relay IP",
                ));
            }
        }
        if config
            .relay_port_range
            .is_some_and(|(first, last)| first == 0 || first > last)
        {
            return Err(io::Error::other(
                "relay ports require 1 <= first <= last <= 65535",
            ));
        }
        #[cfg(feature = "direct-index")]
        if config.max_allocations > (RelaySlots::MASK >> 2) - 1 {
            return Err(io::Error::other(
                "allocation limit exceeds readiness slot capacity",
            ));
        }
        if config.secret.len() < 32
            || config.realm.is_empty()
            || config.realm.len() > 128
            || config.relay_ip.is_unspecified()
            || config.max_allocations == 0
            || config.max_per_user == 0
            || config.max_connections == 0
            || config.bytes_per_second == 0
        {
            return Err(io::Error::other(
                "invalid configuration (secret requires at least 32 bytes)",
            ));
        }
        if config
            .advertised_ip
            .is_some_and(|ip| ip.is_ipv4() != config.relay_ip.is_ipv4() || ip.is_unspecified())
        {
            return Err(io::Error::other(
                "advertised address must match relay address family",
            ));
        }
        if config.local_peer_bridge
            && (!matches!(config.listen.ip(), IpAddr::V4(ip) if !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast())
                || !local_bridge_address(config.relay_ip)
                || config.relay_port_range.is_none()
                || config.allow_loopback_peers
                || config.bridge_peer_ips.len() > 8
                || config.bridge_peer_ips.iter().any(|ip| {
                    !local_bridge_address(IpAddr::V4(*ip)) || IpAddr::V4(*ip) == config.relay_ip
                })
                || config.advertised_ip.is_some_and(|ip| ip != config.relay_ip))
        {
            return Err(io::Error::other(
                "peer bridging requires a concrete IPv4 listener, a virtual relay address and bounded peer aliases/ports",
            ));
        }
        #[cfg(feature = "tls")]
        if config.local_peer_bridge
            && config
                .tls
                .as_ref()
                .is_some_and(|(address, _)| !address.ip().is_loopback())
        {
            return Err(io::Error::other(
                "local peer bridging requires loopback TLS",
            ));
        }
        let poll = Poll::new()?;
        let mut listener = Self::bind_listener(config.listen)?;
        poll.registry()
            .register(&mut listener, UDP, Interest::READABLE)?;
        let mut tcp = TcpListener::bind(listener.local_addr()?)?;
        poll.registry()
            .register(&mut tcp, TCP, Interest::READABLE)?;
        #[cfg(feature = "tls")]
        let tls_listener = if let Some((address, _)) = &config.tls {
            let mut listener = TcpListener::bind(*address)?;
            poll.registry()
                .register(&mut listener, TLS, Interest::READABLE)?;
            Some(listener)
        } else {
            None
        };
        let now = Instant::now();
        let next_relay_port = config.relay_port_range.map_or(0, |(first, _)| first);
        Ok(Self {
            config,
            poll,
            events: Events::with_capacity(1024),
            listener,
            tcp,
            #[cfg(feature = "tls")]
            tls_listener,
            allocations: HashMap::new(),
            relays: Default::default(),
            relay_ports: HashSet::new(),
            advertised_relay_ports: HashSet::new(),
            next_relay_mapping: 0,
            next_relay_port,
            connections: HashMap::new(),
            pending_streams: VecDeque::new(),
            next_token: 3,
            nonces: auth::Nonces::new()
                .map_err(|_| io::Error::other("OS randomness unavailable"))?,
            requests: Bucket::new(2000, 4000, now),
            sweep_at: now + SWEEP_INTERVAL,
            input: vec![0; MAX_PACKET + HEADROOM],
            stats: Stats::default(),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }
    pub fn stats(&self) -> Stats {
        self.stats
    }
    pub fn allocation_count(&self) -> usize {
        self.allocations.len()
    }

    /// Update only the explicitly configured bridge's authorised peer aliases.
    pub fn set_bridge_peer_ips(&mut self, peers: HashSet<std::net::Ipv4Addr>) -> io::Result<()> {
        if !self.config.local_peer_bridge
            || peers.len() > 8
            || peers.iter().any(|ip| {
                !local_bridge_address(IpAddr::V4(*ip)) || IpAddr::V4(*ip) == self.config.relay_ip
            })
        {
            return Err(io::Error::other("invalid bridge peer aliases"));
        }
        self.config.bridge_peer_ips = peers;
        // Previously installed permissions cannot outlive an alias withdrawal.
        for allocation in self.allocations.values_mut() {
            allocation.permissions.retain(|permission| {
                self.config.bridge_peer_ips.contains(&match permission.ip {
                    IpAddr::V4(ip) => ip,
                    _ => return false,
                }) || permission.ip == self.config.relay_ip
            });
            allocation.channels.retain(|channel| {
                self.config
                    .bridge_peer_ips
                    .contains(&match channel.peer.ip() {
                        IpAddr::V4(ip) => ip,
                        _ => return false,
                    })
                    || channel.peer.ip() == self.config.relay_ip
            });
        }
        Ok(())
    }

    /// Active relay ports for an embedding adapter's destination checks.
    pub fn allocated_relay_ports(&self) -> impl Iterator<Item = u16> + '_ {
        self.relay_ports.iter().copied()
    }

    fn token(&mut self) -> Token {
        #[cfg(not(feature = "direct-index"))]
        let token = Token(self.next_token);
        #[cfg(feature = "direct-index")]
        let token = Token((self.next_token << 2) | 3);
        self.next_token += 1;
        token
    }

    fn is_relay(&self, token: Token) -> bool {
        #[cfg(feature = "direct-index")]
        {
            token.0 & 3 == 0
        }
        #[cfg(not(feature = "direct-index"))]
        {
            self.relays.contains_key(&token)
        }
    }

    pub fn poll_once(&mut self, timeout: Duration) -> io::Result<()> {
        let mut events = std::mem::replace(&mut self.events, Events::with_capacity(0));
        let wait = if self.pending_streams.is_empty() {
            timeout.min(self.sweep_at.saturating_duration_since(Instant::now()))
        } else {
            Duration::ZERO
        };
        if let Err(e) = self.poll.poll(&mut events, Some(wait)) {
            self.events = events;
            return if e.kind() == io::ErrorKind::Interrupted {
                Ok(())
            } else {
                Err(e)
            };
        }
        let mut input = std::mem::take(&mut self.input);
        for event in &events {
            let token = event.token();
            if token == UDP {
                loop {
                    match self.listener.recv_from(&mut input) {
                        Ok((n, peer)) => self.receive(Client::Datagram(peer), peer, &input[..n]),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
            } else if token == TCP || token == TLS {
                self.accept(token);
            } else if self.is_relay(token) {
                self.receive_peer(token, &mut input);
            } else if cfg!(feature = "connected-udp") && token.0 & 3 == 2 {
                #[cfg(feature = "connected-udp")]
                self.receive_client_socket(token, &mut input);
            } else {
                self.queue_stream(token);
            }
        }
        // A yielded stream waits until the next poll, so each ready client and
        // expiry sweep gets a turn even when one stream stays continuously hot.
        let ready_streams = self.pending_streams.len();
        for _ in 0..ready_streams {
            let Some(token) = self.pending_streams.pop_front() else {
                break;
            };
            if let Some(conn) = self.connections.get_mut(&token) {
                conn.queued = false;
            }
            self.stream(token, &mut input);
        }
        self.input = input;
        self.events = events;
        if Instant::now() >= self.sweep_at {
            self.sweep();
        }
        Ok(())
    }

    fn send_client(&mut self, client: Client, bytes: &[u8]) {
        self.send_client_packet(client, bytes, false);
    }

    /// Returns whether the whole packet was accepted. UDP relay overload drops
    /// the new packet; it must not truncate queued stream frames or allocations.
    fn send_client_packet(&mut self, client: Client, bytes: &[u8], relay_payload: bool) -> bool {
        match client {
            Client::Datagram(peer) => {
                #[cfg(feature = "connected-udp")]
                let result = if let Some(socket) = self
                    .allocations
                    .get(&client)
                    .and_then(|a| a.client_socket.as_ref())
                {
                    socket.send(bytes)
                } else {
                    self.listener.send_to(bytes, peer)
                };
                #[cfg(not(feature = "connected-udp"))]
                let result = self.listener.send_to(bytes, peer);
                if result.is_err() {
                    self.stats.dropped_packets += 1;
                    false
                } else {
                    true
                }
            }
            Client::Stream(token) => {
                let Some(conn) = self.connections.get_mut(&token) else {
                    if relay_payload {
                        self.stats.dropped_packets += 1;
                    }
                    return false;
                };
                let pending = conn.output.len() - conn.written;
                if relay_payload
                    && bytes.len() > (MAX_QUEUE - STREAM_CONTROL_RESERVE).saturating_sub(pending)
                {
                    self.stats.dropped_packets += 1;
                    return false;
                }
                let result = conn.queue(bytes).and_then(|()| conn.flush());
                let accepted = match result {
                    Ok(pending) => {
                        if conn
                            .update_interest(self.poll.registry(), token, pending)
                            .is_err()
                        {
                            self.close(token);
                            false
                        } else {
                            true
                        }
                    }
                    Err(_) => {
                        self.close(token);
                        false
                    }
                };
                if !accepted && relay_payload {
                    self.stats.dropped_packets += 1;
                }
                accepted
            }
        }
    }

    fn accept(&mut self, listener: Token) {
        loop {
            let accepted = if listener == TCP {
                self.tcp.accept()
            } else {
                #[cfg(feature = "tls")]
                {
                    let Some(tls) = &self.tls_listener else {
                        return;
                    };
                    tls.accept()
                }
                #[cfg(not(feature = "tls"))]
                {
                    return;
                }
            };
            let (mut socket, peer) = match accepted {
                Ok(value) => value,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };
            if self.connections.len() >= self.config.max_connections {
                continue;
            }
            let token = self.token();
            if socket.set_nodelay(true).is_err()
                || self
                    .poll
                    .registry()
                    .register(&mut socket, token, Interest::READABLE)
                    .is_err()
            {
                continue;
            }
            let now = Instant::now();
            #[cfg(feature = "tls")]
            let tls = if listener == TLS {
                let Some((_, config)) = &self.config.tls else {
                    continue;
                };
                match rustls::ServerConnection::new(config.clone()) {
                    Ok(mut conn) => {
                        conn.set_buffer_limit(Some(MAX_QUEUE));
                        Some(conn)
                    }
                    Err(_) => continue,
                }
            } else {
                None
            };
            self.connections.insert(
                token,
                Connection {
                    socket,
                    peer,
                    input: Vec::with_capacity(4096),
                    input_offset: 0,
                    output: Vec::with_capacity(4096),
                    written: 0,
                    writable_interest: false,
                    queued: false,
                    last_active: now,
                    created: now,
                    #[cfg(feature = "tls")]
                    tls,
                },
            );
        }
    }

    fn queue_stream(&mut self, token: Token) {
        let Some(conn) = self.connections.get_mut(&token) else {
            return;
        };
        if !conn.queued {
            conn.queued = true;
            self.pending_streams.push_back(token);
        }
    }

    fn stream(&mut self, token: Token, scratch: &mut [u8]) {
        let mut budget = StreamBudget::new();
        let mut yielded = false;
        loop {
            let Some(conn) = self.connections.get_mut(&token) else {
                return;
            };
            let peer = conn.peer;
            let bytes = std::mem::take(&mut conn.input);
            let mut used = conn.input_offset;
            let mut invalid = false;
            while budget.frames != 0 {
                let Some(len) = wire::frame_len(&bytes[used..]) else {
                    break;
                };
                if len == 0 || len > MAX_PACKET {
                    invalid = true;
                    break;
                }
                if bytes.len() - used < len {
                    break;
                }
                self.receive(Client::Stream(token), peer, &bytes[used..used + len]);
                used += len;
                budget.frames -= 1;
                if !self.connections.contains_key(&token) {
                    return;
                }
            }
            if invalid {
                self.close(token);
                return;
            }
            if let Some(conn) = self.connections.get_mut(&token) {
                conn.input = bytes;
                conn.input_offset = used;
                if budget.frames == 0 {
                    yielded = true;
                    break;
                }
                match conn.read(scratch, &mut budget) {
                    Ok(StreamRead::Data) => (),
                    Ok(StreamRead::Pending) => break,
                    Ok(StreamRead::Yielded) => {
                        yielded = true;
                        break;
                    }
                    Ok(StreamRead::Closed) | Err(_) => {
                        self.close(token);
                        return;
                    }
                }
            }
        }
        if let Some(conn) = self.connections.get_mut(&token) {
            match conn.flush() {
                Ok(pending) => {
                    if conn
                        .update_interest(self.poll.registry(), token, pending)
                        .is_err()
                    {
                        self.close(token);
                    }
                }
                Err(_) => self.close(token),
            }
        }
        if yielded {
            self.queue_stream(token);
        }
    }

    fn close(&mut self, token: Token) {
        if let Some(mut conn) = self.connections.remove(&token) {
            if conn.queued {
                self.pending_streams.retain(|queued| *queued != token);
            }
            let _ = self.poll.registry().deregister(&mut conn.socket);
        }
        self.remove_allocation(Client::Stream(token));
    }

    fn remove_allocation(&mut self, client: Client) {
        if let Some(mut allocation) = self.allocations.remove(&client) {
            #[cfg(feature = "connected-udp")]
            if let Some(socket) = &mut allocation.client_socket {
                let _ = self.poll.registry().deregister(socket);
            }
            self.relay_ports.remove(&allocation.bound_address.port());
            self.advertised_relay_ports
                .remove(&allocation.advertised_address.port());
            let _ = self.poll.registry().deregister(&mut allocation.socket);
            self.relays.remove(&allocation.token);
        }
    }

    fn sweep(&mut self) {
        let now = Instant::now();
        let expired: Vec<_> = self
            .allocations
            .iter()
            .filter_map(|(c, a)| (a.expires <= now).then_some(*c))
            .collect();
        for client in expired {
            self.remove_allocation(client);
        }
        for a in self.allocations.values_mut() {
            a.permissions.retain(|p| p.expires > now);
            a.channels.retain(|c| c.expires > now);
        }
        let expired: Vec<_> = self
            .connections
            .iter()
            .filter_map(|(t, c)| {
                let active = self.allocations.contains_key(&Client::Stream(*t));
                ((!active && now.duration_since(c.created) > Duration::from_secs(15))
                    || now.duration_since(c.last_active) > Duration::from_secs(600))
                .then_some(*t)
            })
            .collect();
        for token in expired {
            self.close(token);
        }
        self.sweep_at = now + SWEEP_INTERVAL;
    }
}

impl Server {
    fn error(
        &mut self,
        client: Client,
        peer: SocketAddr,
        message: &Message<'_>,
        code: u16,
        key: Option<&[u8]>,
    ) {
        let mut b = Builder::new(message.method, 3, message.transaction);
        let text = match code {
            400 => "Bad Request",
            401 => "Unauthorised",
            403 => "Forbidden",
            420 => "Unknown Attribute",
            437 => "Allocation Mismatch",
            438 => "Stale Nonce",
            440 => "Address Family Not Supported",
            441 => "Wrong Credentials",
            442 => "Unsupported Transport",
            443 => "Peer Address Family Mismatch",
            486 => "Allocation Quota Reached",
            _ => "Insufficient Capacity",
        };
        let mut value = vec![0, 0, (code / 100) as u8, (code % 100) as u8];
        value.extend_from_slice(text.as_bytes());
        b.attr(ERROR, &value);
        if code == 401 || code == 438 {
            b.attr(REALM, self.config.realm.as_bytes());
            b.attr(
                NONCE,
                self.nonces
                    .issue(unix_time(), peer.ip(), &self.config.realm)
                    .as_bytes(),
            );
        }
        self.send_client(client, &b.finish(key));
    }

    fn authenticate(
        &mut self,
        client: Client,
        peer: SocketAddr,
        m: &Message<'_>,
    ) -> Option<(String, [u8; 16])> {
        let Some(username) = m.attr(USERNAME).and_then(|b| std::str::from_utf8(b).ok()) else {
            self.error(client, peer, m, 401, None);
            return None;
        };
        if m.attr(REALM) != Some(self.config.realm.as_bytes())
            || auth::expires(username).is_none_or(|expiry| expiry <= unix_time())
        {
            self.error(client, peer, m, 401, None);
            return None;
        }
        let password = auth::credential(&self.config.secret, username);
        let key = auth::key(username, &self.config.realm, &password);
        if !m.verify(&key) {
            self.error(client, peer, m, 401, None);
            return None;
        }
        if !m.attr(NONCE).is_some_and(|nonce| {
            self.nonces
                .valid(nonce, unix_time(), peer.ip(), &self.config.realm)
        }) {
            self.error(client, peer, m, 438, Some(&key));
            return None;
        }
        if self
            .allocations
            .get(&client)
            .is_some_and(|a| a.username != username)
        {
            self.error(client, peer, m, 441, Some(&key));
            return None;
        }
        Some((username.to_owned(), key))
    }

    fn receive(&mut self, client: Client, peer: SocketAddr, bytes: &[u8]) {
        if bytes.first().is_some_and(|b| b >> 6 == 1) {
            let Some((number, data)) = wire::channel(bytes) else {
                return;
            };
            let now = Instant::now();
            let Some(a) = self
                .allocations
                .get_mut(&client)
                .filter(|a| a.expires > now)
            else {
                return;
            };
            let Some(channel) = a
                .channels
                .iter()
                .find(|c| c.number == number && c.expires > now)
            else {
                return;
            };
            if !Self::allowed_peer(
                &self.config,
                &self.relay_ports,
                &self.advertised_relay_ports,
                channel.peer,
            ) {
                self.stats.dropped_packets += 1;
                return;
            }
            if !a
                .permissions
                .iter()
                .any(|p| p.ip == channel.peer.ip() && p.expires > now)
                || !a.bandwidth.take(data.len(), now)
            {
                self.stats.dropped_packets += 1;
                return;
            }
            if a.socket.send_to(data, channel.peer).is_ok() {
                self.stats.forwarded_packets += 1;
                self.stats.forwarded_bytes += data.len() as u64;
            } else {
                self.stats.dropped_packets += 1;
            }
            return;
        }
        let Some(m) = Message::parse(bytes) else {
            return;
        };
        if m.class == 1 && m.method == SEND {
            self.send_indication(client, &m);
            return;
        }
        if m.class != 0 || !self.requests.take(1, Instant::now()) {
            return;
        }
        if m.method == BINDING {
            let mut b = Builder::new(BINDING, 2, m.transaction);
            b.address(MAPPED, peer);
            self.send_client(client, &b.finish(None));
            return;
        }
        let Some((username, key)) = self.authenticate(client, peer, &m) else {
            return;
        };
        let mut unknown: Vec<u16> = Vec::new();
        for (typ, _) in m.attributes() {
            if typ < 0x8000
                && !matches!(
                    typ,
                    USERNAME
                        | REALM
                        | NONCE
                        | CHANNEL
                        | LIFETIME
                        | PEER
                        | DATA
                        | FAMILY
                        | TRANSPORT
                )
                && !unknown.contains(&typ)
            {
                unknown.push(typ);
            }
        }
        if !unknown.is_empty() {
            let mut b = Builder::new(m.method, 3, m.transaction);
            let mut error = vec![0, 0, 4, 20];
            error.extend_from_slice(b"Unknown Attribute");
            let unknown: Vec<u8> = unknown.iter().flat_map(|t| t.to_be_bytes()).collect();
            b.attr(ERROR, &error).attr(UNKNOWN, &unknown);
            self.send_client(client, &b.finish(Some(&key)));
            return;
        }
        match m.method {
            ALLOCATE => self.allocate(client, peer, &m, username, key),
            REFRESH | PERMISSION | CHANNEL_BIND => {
                if self
                    .allocations
                    .get(&client)
                    .is_none_or(|a| a.expires <= Instant::now())
                {
                    self.remove_allocation(client);
                    self.error(client, peer, &m, 437, Some(&key));
                    return;
                }
                match m.method {
                    REFRESH => self.refresh(client, peer, &m, key),
                    PERMISSION => self.permission(client, peer, &m, key),
                    _ => self.channel_bind(client, peer, &m, key),
                }
            }
            _ => self.error(client, peer, &m, 400, Some(&key)),
        }
    }

    fn allocate(
        &mut self,
        client: Client,
        peer: SocketAddr,
        m: &Message<'_>,
        username: String,
        key: [u8; 16],
    ) {
        if self
            .allocations
            .get(&client)
            .is_some_and(|a| a.expires <= Instant::now())
        {
            self.remove_allocation(client);
        }
        if let Some(a) = self.allocations.get(&client) {
            if a.transaction == m.transaction {
                self.allocated(client, peer, m, &key);
            } else {
                self.error(client, peer, m, 437, Some(&key));
            }
            return;
        }
        match m.attr(TRANSPORT) {
            Some([17, _, _, _]) => (),
            Some([_, _, _, _]) => {
                self.error(client, peer, m, 442, Some(&key));
                return;
            }
            _ => {
                self.error(client, peer, m, 400, Some(&key));
                return;
            }
        }
        let family = match m.attr(FAMILY) {
            None => 1,
            Some([family @ (1 | 2), _, _, _]) => *family,
            _ => {
                self.error(client, peer, m, 400, Some(&key));
                return;
            }
        };
        if (family == 1) != self.config.relay_ip.is_ipv4() {
            self.error(client, peer, m, 440, Some(&key));
            return;
        }
        if self.allocations.len() >= self.config.max_allocations
            || self
                .allocations
                .values()
                .filter(|a| a.username == username)
                .count()
                >= self.config.max_per_user
        {
            self.error(client, peer, m, 486, Some(&key));
            return;
        }
        let socket = self.bind_relay_socket();
        let Ok(mut socket) = socket else {
            self.error(client, peer, m, 508, Some(&key));
            return;
        };
        #[cfg(not(feature = "direct-index"))]
        let token = self.token();
        #[cfg(feature = "direct-index")]
        let token = self.relays.reserve(client);
        let address = socket.local_addr().and_then(|address| {
            self.poll
                .registry()
                .register(&mut socket, token, Interest::READABLE)?;
            Ok(address)
        });
        let Ok(bound_address) = address else {
            #[cfg(feature = "direct-index")]
            self.relays.remove(&token);
            self.error(client, peer, m, 508, Some(&key));
            return;
        };
        let mut advertised_address = bound_address;
        if let Some(ip) = self.config.advertised_ip {
            advertised_address.set_ip(ip);
        }
        if let Some(mappings) = &self.config.relay_port_mappings {
            // bind_relay_socket selects only validated entries from this map.
            let mapping = mappings
                .iter()
                .find(|mapping| mapping.local_port == bound_address.port())
                .expect("bound mapped port");
            advertised_address.set_port(mapping.advertised_port);
        }
        let now = Instant::now();
        let lifetime = credential_lifetime(
            &username,
            m.number(LIFETIME).unwrap_or(600).clamp(600, 3600),
            SystemTime::now(),
        );
        #[cfg(feature = "connected-udp")]
        let client_socket = self.connected_client(client, token);
        self.allocations.insert(
            client,
            Allocation {
                socket,
                #[cfg(feature = "connected-udp")]
                client_socket,
                token,
                bound_address,
                advertised_address,
                username,
                transaction: m.transaction,
                expires: now + lifetime,
                permissions: Vec::new(),
                channels: Vec::new(),
                bandwidth: Bucket::new(
                    self.config.bytes_per_second,
                    self.config.bytes_per_second,
                    now,
                ),
            },
        );
        self.relay_ports.insert(bound_address.port());
        self.advertised_relay_ports
            .insert(advertised_address.port());
        #[cfg(not(feature = "direct-index"))]
        self.relays.insert(token, client);
        self.allocated(client, peer, m, &key);
    }

    fn bind_relay_socket(&mut self) -> io::Result<UdpSocket> {
        if let Some(mappings) = &self.config.relay_port_mappings {
            for _ in 0..mappings.len() {
                let mapping = mappings[self.next_relay_mapping];
                self.next_relay_mapping = (self.next_relay_mapping + 1) % mappings.len();
                if self.relay_ports.contains(&mapping.local_port) {
                    continue;
                }
                match UdpSocket::bind(SocketAddr::new(self.config.relay_ip, mapping.local_port)) {
                    Ok(socket) => return Ok(socket),
                    Err(error) if error.kind() == io::ErrorKind::AddrInUse => continue,
                    Err(error) => return Err(error),
                }
            }
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "relay port mappings exhausted",
            ));
        }
        let Some((first, last)) = self.config.relay_port_range else {
            return UdpSocket::bind(SocketAddr::new(self.config.relay_ip, 0));
        };
        // Rotate through the bounded range once. Occupied host ports are skipped,
        // but neither capacity exhaustion nor a bind error widens the range.
        for _ in u32::from(first)..=u32::from(last) {
            let port = self.next_relay_port;
            self.next_relay_port = if port == last { first } else { port + 1 };
            if self.relay_ports.contains(&port) {
                continue;
            }
            match UdpSocket::bind(SocketAddr::new(self.config.relay_ip, port)) {
                Ok(socket) => return Ok(socket),
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "relay port range exhausted",
        ))
    }

    fn allocated(&mut self, client: Client, peer: SocketAddr, m: &Message<'_>, key: &[u8]) {
        let Some(a) = self.allocations.get(&client) else {
            return;
        };
        let lifetime = a
            .expires
            .saturating_duration_since(Instant::now())
            .as_secs()
            .saturating_add(1)
            .min(3600) as u32;
        let mut b = Builder::new(ALLOCATE, 2, m.transaction);
        b.address(RELAYED, a.advertised_address)
            .address(MAPPED, peer)
            .number(LIFETIME, lifetime)
            .attr(SOFTWARE, b"spry-turn");
        self.send_client(client, &b.finish(Some(key)));
    }

    fn refresh(&mut self, client: Client, peer: SocketAddr, m: &Message<'_>, key: [u8; 16]) {
        let a = self
            .allocations
            .get_mut(&client)
            .expect("checked allocation");
        if let Some(family) = m.attr(FAMILY) {
            if family.len() != 4 {
                self.error(client, peer, m, 400, Some(&key));
                return;
            }
            if (family[0] == 1) != a.advertised_address.is_ipv4() {
                self.error(client, peer, m, 443, Some(&key));
                return;
            }
        }
        if m.attr(LIFETIME).is_some() && m.number(LIFETIME).is_none() {
            self.error(client, peer, m, 400, Some(&key));
            return;
        }
        let duration = credential_lifetime(
            &a.username,
            m.number(LIFETIME).unwrap_or(600).min(3600),
            SystemTime::now(),
        );
        a.expires = Instant::now() + duration;
        let lifetime = duration
            .as_secs()
            .saturating_add(u64::from(duration.subsec_nanos() != 0)) as u32;
        let mut b = Builder::new(REFRESH, 2, m.transaction);
        b.number(LIFETIME, lifetime);
        self.send_client(client, &b.finish(Some(&key)));
        if lifetime == 0 {
            self.remove_allocation(client);
        }
    }

    fn peer_allowed(&self, address: SocketAddr) -> bool {
        Self::allowed_peer(
            &self.config,
            &self.relay_ports,
            &self.advertised_relay_ports,
            address,
        )
    }

    fn allowed_peer(
        config: &Config,
        ports: &HashSet<u16>,
        advertised_ports: &HashSet<u16>,
        address: SocketAddr,
    ) -> bool {
        if address.port() == 0 {
            return false;
        }
        let ip = address.ip();
        if config.local_peer_bridge {
            if !local_bridge_address(ip) {
                return false;
            }
            if ip == config.relay_ip {
                return ports.contains(&address.port());
            }
            if !matches!(ip, IpAddr::V4(peer) if config.bridge_peer_ips.contains(&peer)) {
                return false;
            }
            return config
                .relay_port_range
                .is_some_and(|(first, last)| (first..=last).contains(&address.port()));
        }
        if ip.is_unspecified() || ip.is_multicast() {
            return false;
        }
        if ip.is_loopback() && !config.allow_loopback_peers {
            return false;
        }
        // Mapped mode must not let the local-test loopback opt-in bypass
        // exact ownership checks on the configured local/public relay IPs.
        if config.relay_port_mappings.is_some()
            && (ip == config.relay_ip || Some(ip) == config.advertised_ip)
        {
            return (ip == config.relay_ip && ports.contains(&address.port()))
                || (ip == config.advertised_ip.unwrap_or(config.relay_ip)
                    && advertised_ports.contains(&address.port()));
        }
        if ip.is_loopback() {
            return config.allow_loopback_peers;
        }
        if ip == config.relay_ip || Some(ip) == config.advertised_ip {
            return (ip == config.relay_ip && ports.contains(&address.port()))
                || (ip == config.advertised_ip.unwrap_or(config.relay_ip)
                    && advertised_ports.contains(&address.port()));
        }
        match ip {
            IpAddr::V4(v) => {
                let [a, b, c, _] = v.octets();
                !(v.is_private()
                    || v.is_link_local()
                    || v.is_broadcast()
                    || v.is_documentation()
                    || a == 0
                    || a >= 224
                    || (a == 100 && (64..=127).contains(&b))
                    || (a == 198 && (b == 18 || b == 19))
                    || (a == 192 && b == 0 && c == 0))
            }
            IpAddr::V6(v) => {
                let first = v.segments()[0];
                v.to_ipv4_mapped().is_none()
                    && first & 0xfe00 != 0xfc00
                    && first & 0xffc0 != 0xfe80
                    && v.segments()[..2] != [0x2001, 0x0db8]
            }
        }
    }

    fn permission(&mut self, client: Client, peer: SocketAddr, m: &Message<'_>, key: [u8; 16]) {
        let mut peers = Vec::new();
        for (typ, value) in m.attributes().filter(|(t, _)| *t == PEER) {
            let _ = typ;
            let Some(address) = decode_address(value, &m.transaction) else {
                self.error(client, peer, m, 400, Some(&key));
                return;
            };
            if address.is_ipv4() != self.config.relay_ip.is_ipv4() {
                self.error(client, peer, m, 443, Some(&key));
                return;
            }
            if !self.peer_allowed(address) {
                self.error(client, peer, m, 403, Some(&key));
                return;
            }
            if !peers.contains(&address.ip()) {
                peers.push(address.ip());
            }
        }
        if peers.is_empty() {
            self.error(client, peer, m, 400, Some(&key));
            return;
        }
        let now = Instant::now();
        let a = self
            .allocations
            .get_mut(&client)
            .expect("checked allocation");
        a.permissions.retain(|p| p.expires > now);
        let new = peers
            .iter()
            .filter(|ip| !a.permissions.iter().any(|p| p.ip == **ip))
            .count();
        if a.permissions.len() + new > MAX_PEERS {
            self.error(client, peer, m, 508, Some(&key));
            return;
        }
        for ip in peers {
            Self::permit(a, ip, now);
        }
        self.send_client(
            client,
            &Builder::new(PERMISSION, 2, m.transaction).finish(Some(&key)),
        );
    }

    fn permit(a: &mut Allocation, ip: IpAddr, now: Instant) {
        if let Some(p) = a.permissions.iter_mut().find(|p| p.ip == ip) {
            p.expires = now + Duration::from_secs(300);
        } else {
            a.permissions.push(Permission {
                ip,
                expires: now + Duration::from_secs(300),
            });
        }
    }

    fn channel_bind(&mut self, client: Client, peer: SocketAddr, m: &Message<'_>, key: [u8; 16]) {
        let Some(value) = m.attr(CHANNEL).filter(|v| v.len() == 4) else {
            self.error(client, peer, m, 400, Some(&key));
            return;
        };
        let number = u16::from_be_bytes([value[0], value[1]]);
        let Some(address) = m.address(PEER) else {
            self.error(client, peer, m, 400, Some(&key));
            return;
        };
        if !(0x4000..=0x4fff).contains(&number) {
            self.error(client, peer, m, 400, Some(&key));
            return;
        }
        if address.is_ipv4() != self.config.relay_ip.is_ipv4() {
            self.error(client, peer, m, 443, Some(&key));
            return;
        }
        if !self.peer_allowed(address) {
            self.error(client, peer, m, 403, Some(&key));
            return;
        }
        let now = Instant::now();
        let a = self
            .allocations
            .get_mut(&client)
            .expect("checked allocation");
        a.permissions.retain(|p| p.expires > now);
        a.channels.retain(|c| c.expires > now);
        if a.channels.iter().any(|c| {
            (c.number == number || c.peer == address) && (c.number != number || c.peer != address)
        }) {
            self.error(client, peer, m, 400, Some(&key));
            return;
        }
        if (!a.channels.iter().any(|c| c.number == number) && a.channels.len() >= MAX_PEERS)
            || (!a.permissions.iter().any(|p| p.ip == address.ip())
                && a.permissions.len() >= MAX_PEERS)
        {
            self.error(client, peer, m, 508, Some(&key));
            return;
        }
        if let Some(c) = a.channels.iter_mut().find(|c| c.number == number) {
            c.expires = now + Duration::from_secs(600);
        } else {
            a.channels.push(Channel {
                number,
                peer: address,
                expires: now + Duration::from_secs(600),
            });
        }
        Self::permit(a, address.ip(), now);
        self.send_client(
            client,
            &Builder::new(CHANNEL_BIND, 2, m.transaction).finish(Some(&key)),
        );
    }

    fn send_indication(&mut self, client: Client, m: &Message<'_>) {
        let (Some(peer), Some(data)) = (m.address(PEER), m.attr(DATA)) else {
            return;
        };
        // Permissions are IP-scoped; apply port-sensitive policy to every send.
        if !self.peer_allowed(peer) {
            self.stats.dropped_packets += 1;
            return;
        }
        let now = Instant::now();
        let Some(a) = self
            .allocations
            .get_mut(&client)
            .filter(|a| a.expires > now)
        else {
            return;
        };
        if !a
            .permissions
            .iter()
            .any(|p| p.ip == peer.ip() && p.expires > now)
            || !a.bandwidth.take(data.len(), now)
        {
            self.stats.dropped_packets += 1;
            return;
        }
        if a.socket.send_to(data, peer).is_ok() {
            self.stats.forwarded_packets += 1;
            self.stats.forwarded_bytes += data.len() as u64;
        } else {
            self.stats.dropped_packets += 1;
        }
    }

    fn receive_peer(&mut self, token: Token, input: &mut [u8]) {
        let Some(client) = self.relays.get(&token).copied() else {
            return;
        };
        loop {
            let now = Instant::now();
            let Some(a) = self
                .allocations
                .get_mut(&client)
                .filter(|a| a.expires > now)
            else {
                return;
            };
            // Receive directly after room for the largest TURN header. Return
            // packets prepend their framing without copying the media payload.
            let (n, peer) = match a.socket.recv_from(&mut input[HEADROOM..]) {
                Ok(value) => value,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return,
            };
            if !a
                .permissions
                .iter()
                .any(|p| p.ip == peer.ip() && p.expires > now)
                || !a.bandwidth.take(n, now)
            {
                self.stats.dropped_packets += 1;
                continue;
            }
            if let Some(c) = a
                .channels
                .iter()
                .find(|c| c.peer == peer && c.expires > now)
            {
                let begin = HEADROOM - 4;
                input[begin..begin + 2].copy_from_slice(&c.number.to_be_bytes());
                input[begin + 2..HEADROOM].copy_from_slice(&(n as u16).to_be_bytes());
                let end = if matches!(client, Client::Stream(_)) {
                    (HEADROOM + n + 3) & !3
                } else {
                    HEADROOM + n
                };
                input[HEADROOM + n..end].fill(0);
                if !self.send_client_packet(client, &input[begin..end], true) {
                    continue;
                }
            } else {
                // Data indications also use the reserved prefix of this buffer.
                if n > 65_440 {
                    self.stats.dropped_packets += 1;
                    continue;
                }
                let mut transaction = [0; 12];
                if getrandom::fill(&mut transaction).is_err() {
                    continue;
                }
                let (address, address_len) = address_value(peer, &transaction);
                let data_start = 20 + 4 + address_len + 4;
                let len = (data_start + n + 3) & !3;
                let begin = HEADROOM - data_start;
                let output = &mut input[begin..begin + len];
                output[..2].copy_from_slice(&message_type(DATA_METHOD, 1).to_be_bytes());
                output[2..4].copy_from_slice(&((len - 20) as u16).to_be_bytes());
                output[4..8].copy_from_slice(&COOKIE.to_be_bytes());
                output[8..20].copy_from_slice(&transaction);
                output[20..22].copy_from_slice(&PEER.to_be_bytes());
                output[22..24].copy_from_slice(&(address_len as u16).to_be_bytes());
                output[24..24 + address_len].copy_from_slice(&address[..address_len]);
                output[data_start - 4..data_start - 2].copy_from_slice(&DATA.to_be_bytes());
                output[data_start - 2..data_start].copy_from_slice(&(n as u16).to_be_bytes());
                output[data_start + n..len].fill(0);
                if !self.send_client_packet(client, &output[..len], true) {
                    continue;
                }
            }
            self.stats.forwarded_packets += 1;
            self.stats.forwarded_bytes += n as u64;
        }
    }
}
