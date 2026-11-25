use super::*;

/// Binds a server on an ephemeral port. `Server::bind` takes a UDP port
/// first and then needs the same number free for TCP, which an unrelated
/// connection can occupy, so a port-0 bind occasionally fails with
/// `AddrInUse` on a busy host. A fresh attempt picks another port; any
/// other error, or a persistent clash, still fails the test.
fn bind_server(config: Config) -> Server {
    const ATTEMPTS: usize = 8;
    for _ in 1..ATTEMPTS {
        match Server::bind(config.clone()) {
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => (),
            result => return result.unwrap(),
        }
    }
    Server::bind(config).unwrap()
}

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

fn batch_output_fixture(count: usize) -> (Server, Vec<std::net::TcpStream>, Vec<Token>) {
    let mut config = Config::local(vec![1; 32]);
    config.listen.set_port(0);
    config.allow_loopback_peers = true;
    let mut server = bind_server(config);
    let mut clients = Vec::new();
    let mut tokens: Vec<Token> = Vec::new();
    for _ in 0..count {
        let client = std::net::TcpStream::connect_timeout(
            &server.local_addr().unwrap(),
            Duration::from_secs(2),
        )
        .unwrap();
        client.set_nonblocking(true).unwrap();
        accept_stream(&mut server);
        let token = *server
            .connections
            .keys()
            .find(|token| !tokens.contains(*token))
            .unwrap();
        tokens.push(token);
        clients.push(client);
    }
    (server, clients, tokens)
}

#[cfg(all(feature = "connected-udp", unix))]
fn batch_output_relay(
    server: &mut Server,
    client: Client,
    peer: SocketAddr,
) -> (Token, SocketAddr) {
    let socket = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let address = socket.local_addr().unwrap();
    #[cfg(feature = "direct-index")]
    let token = server.relays.reserve(client);
    #[cfg(not(feature = "direct-index"))]
    let token = {
        let token = server.token();
        server.relays.insert(token, client);
        token
    };
    let expires = Instant::now() + Duration::from_secs(60);
    // Generated authorised state isolates storage ownership from auth.
    // Direct receive_peer calls do not need a registered relay readiness edge.
    server.allocations.insert(
        client,
        Allocation {
            socket,
            #[cfg(feature = "connected-udp")]
            client_socket: None,
            token,
            bound_address: address,
            advertised_address: address,
            username: "batch-storage-fixture".into(),
            transaction: [1; 12],
            expires,
            permissions: vec![Permission {
                ip: peer.ip(),
                expires,
            }],
            channels: vec![Channel {
                number: 0x4000,
                peer,
                expires,
            }],
            bandwidth: Bucket::new(64 * 1024 * 1024, 128 * 1024 * 1024, Instant::now()),
            requests: Bucket::new(
                ALLOCATION_REQUESTS_PER_SECOND,
                ALLOCATION_REQUEST_BURST,
                Instant::now(),
            ),
        },
    );
    (token, address)
}

#[test]
#[cfg(all(feature = "connected-udp", unix))]
fn batch_output_dispatch_delivers_large_frame_without_retaining_connection_growth() {
    let (mut server, mut clients, tokens) = batch_output_fixture(1);
    let token = tokens[0];
    let key = Client::Stream(token);
    // This regression exercises the drained path. Give the fresh socket
    // room for one 9004-byte frame; it does not manufacture a short write.
    socket2::SockRef::from(&server.connections[&token].socket)
        .set_send_buffer_size(1_048_576)
        .unwrap();
    let original_capacity = server.connections[&token].output.capacity();
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer_address = peer.local_addr().unwrap();
    let (relay_token, address) = batch_output_relay(&mut server, key, peer_address);
    let payload: Vec<u8> = (0..9000).map(|i| (i % 251) as u8).collect();
    assert_eq!(peer.send_to(&payload, address).unwrap(), payload.len());
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut peek = [0; 1];
    loop {
        match server.allocations[&key].socket.peek_from(&mut peek) {
            Ok((_, from)) => {
                assert_eq!(from, peer_address);
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "peer datagram did not arrive");
                std::thread::yield_now();
            }
            Err(error) => panic!("peer peek failed: {error}"),
        }
    }
    let mut scratch = vec![0; MAX_PACKET + HEADROOM];
    server.receive_peer(relay_token, &mut scratch);
    assert!(
        server.connections[&token].output.is_empty(),
        "the fresh socket must drain this single-frame fixture"
    );
    assert_eq!(
        server.connections[&token].output.capacity(),
        original_capacity,
        "a drained dispatch must not retain its batch growth on the connection"
    );
    let mut delivered = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(2);
    while delivered.len() < payload.len() + 4 && Instant::now() < deadline {
        match clients[0].read(&mut scratch) {
            Ok(0) => panic!("connection closed before the frame was delivered"),
            Ok(n) => delivered.extend_from_slice(&scratch[..n]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::yield_now();
            }
            Err(error) => panic!("client read failed: {error}"),
        }
    }
    assert_eq!(delivered.len(), payload.len() + 4);
    assert_eq!(
        wire::channel(&delivered),
        Some((0x4000, payload.as_slice()))
    );
    assert_eq!(server.stats.forwarded_packets, 1);
    assert_eq!(server.stats.forwarded_bytes, payload.len() as u64);
    assert_eq!(server.stats.dropped_packets, 0);
}

#[test]
fn batch_output_singleton_is_immediate_and_second_return_starts_batch() {
    let (mut server, mut clients, tokens) = batch_output_fixture(1);
    let token = tokens[0];
    let key = Client::Stream(token);
    server.tcp_return_output = Vec::with_capacity(TCP_RETURN_BATCH_BYTES);
    let shared_pointer = server.tcp_return_output.as_ptr();
    let own_pointer = server.connections[&token].output.as_ptr();
    let mut dispatch = PeerReturnDispatch::new();
    assert!(server.send_peer_return(key, b"first", 1, &mut dispatch));
    assert!(!dispatch.batch_started);
    assert!(!dispatch.lent_output);
    assert_eq!(server.tcp_return_output.as_ptr(), shared_pointer);
    assert_eq!(server.connections[&token].output.as_ptr(), own_pointer);
    clients[0].set_nonblocking(false).unwrap();
    clients[0]
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut received = [0; 5];
    clients[0].read_exact(&mut received).unwrap();
    assert_eq!(&received, b"first");
    assert_eq!(server.stats.forwarded_packets, 1);
    assert!(server.send_peer_return(key, b"next", 2, &mut dispatch));
    assert!(dispatch.batch_started);
    assert!(dispatch.lent_output);
    assert_eq!(dispatch.batch.frames, 1);
    assert_eq!(server.stats.forwarded_packets, 1);
    assert!(server.flush_peer_batch(key, &mut dispatch.batch));
    assert!(server.swap_empty_peer_output(key));
    clients[0].read_exact(&mut received[..4]).unwrap();
    assert_eq!(&received[..4], b"next");
    assert_eq!(server.stats.forwarded_packets, 2);
    assert_eq!(server.stats.forwarded_bytes, 3);
    assert_eq!(server.connections[&token].output.as_ptr(), own_pointer);
}

#[test]
fn batch_output_first_large_fatal_write_releases_loan_and_counts_once() {
    let (mut server, _clients, tokens) = batch_output_fixture(1);
    let token = tokens[0];
    let key = Client::Stream(token);
    let own_pointer = server.connections[&token].output.as_ptr();
    server.connections[&token]
        .socket
        .shutdown(std::net::Shutdown::Write)
        .unwrap();
    let mut dispatch = PeerReturnDispatch::new();
    assert!(!server.send_peer_return(key, &vec![0; 9004], 9000, &mut dispatch));
    assert!(!server.connections.contains_key(&token));
    assert_eq!(server.tcp_return_output.as_ptr(), own_pointer);
    assert!(server.tcp_return_output.is_empty());
    assert_eq!(server.stats.forwarded_packets, 0);
    assert_eq!(server.stats.dropped_packets, 1);
    assert_eq!(server.transport.stream_errors, 1);
    assert!(server.flush_peer_batch(key, &mut dispatch.batch));
    assert_eq!(server.stats.dropped_packets, 1);
}

#[test]
#[cfg(all(feature = "connected-udp", unix))]
fn batch_output_first_large_pending_write_keeps_loan_when_next_batch_fails() {
    let (mut server, clients, tokens) = batch_output_fixture(1);
    let token = tokens[0];
    let key = Client::Stream(token);
    socket2::SockRef::from(&server.connections[&token].socket)
        .set_send_buffer_size(4096)
        .unwrap();
    socket2::SockRef::from(&clients[0])
        .set_recv_buffer_size(4096)
        .unwrap();
    let block = [0x5a; 4096];
    let mut blocked = false;
    for _ in 0..8192 {
        match server
            .connections
            .get_mut(&token)
            .unwrap()
            .socket
            .write(&block)
        {
            Ok(_) => (),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                blocked = true;
                break;
            }
            Err(error) => panic!("socket fill failed: {error}"),
        }
    }
    assert!(blocked, "bounded socket fill must reach backpressure");
    server.tcp_return_output = Vec::with_capacity(TCP_RETURN_BATCH_BYTES);
    let shared_pointer = server.tcp_return_output.as_ptr();
    let own_pointer = server.connections[&token].output.as_ptr();
    let mut dispatch = PeerReturnDispatch::new();
    assert!(server.send_peer_return(key, &vec![0x42; 9004], 9000, &mut dispatch));
    let conn = &server.connections[&token];
    assert!(conn.output.len() > conn.written);
    assert_eq!(conn.output.as_ptr(), shared_pointer);
    assert_eq!(server.tcp_return_output.as_ptr(), own_pointer);
    assert_eq!(server.stats.forwarded_packets, 1);
    assert!(server.send_peer_return(key, b"next", 2, &mut dispatch));
    assert!(!dispatch.lent_output, "pending ownership is never swapped");
    server.connections[&token]
        .socket
        .shutdown(std::net::Shutdown::Write)
        .unwrap();
    assert!(!server.flush_peer_batch(key, &mut dispatch.batch));
    assert_eq!(server.stats.forwarded_packets, 1);
    assert_eq!(server.stats.forwarded_bytes, 9000);
    assert_eq!(server.stats.dropped_packets, 1);
    assert!(server.tcp_return_output.is_empty());
}

#[test]
fn batch_output_empty_storage_reuses_capacity_across_two_connections() {
    let (mut server, _clients, tokens) = batch_output_fixture(2);
    server.tcp_return_output = Vec::with_capacity(TCP_RETURN_BATCH_BYTES);
    let shared_pointer = server.tcp_return_output.as_ptr();
    let shared_capacity = server.tcp_return_output.capacity();
    for (index, token) in tokens.into_iter().enumerate() {
        let key = Client::Stream(token);
        let original_pointer = server.connections[&token].output.as_ptr();
        let original_capacity = server.connections[&token].output.capacity();
        assert!(server.swap_empty_peer_output(key));
        assert_eq!(server.connections[&token].output.as_ptr(), shared_pointer);
        assert!(server.connections[&token].output.is_empty());
        assert_eq!(server.tcp_return_output.as_ptr(), original_pointer);
        let conn = server.connections.get_mut(&token).unwrap();
        let bytes = vec![index as u8 + 1; 9004];
        conn.queue(&bytes).unwrap();
        assert_eq!(conn.output, bytes);
        // Synthetic successful writer completion, not socket I/O.
        conn.output.clear();
        conn.written = 0;
        assert!(server.swap_empty_peer_output(key));
        assert_eq!(server.connections[&token].output.as_ptr(), original_pointer);
        assert_eq!(
            server.connections[&token].output.capacity(),
            original_capacity
        );
        assert_eq!(server.tcp_return_output.as_ptr(), shared_pointer);
        assert_eq!(server.tcp_return_output.capacity(), shared_capacity);
        assert!(server.tcp_return_output.is_empty());
    }
}

#[test]
fn batch_output_pending_or_partial_bytes_never_change_owner() {
    let (mut server, _clients, tokens) = batch_output_fixture(1);
    let token = tokens[0];
    let key = Client::Stream(token);
    server.tcp_return_output = Vec::with_capacity(TCP_RETURN_BATCH_BYTES);
    let shared_pointer = server.tcp_return_output.as_ptr();
    let bytes: Vec<u8> = (0..128).collect();
    server
        .connections
        .get_mut(&token)
        .unwrap()
        .queue(&bytes)
        .unwrap();
    let original_pointer = server.connections[&token].output.as_ptr();
    // Synthetic writer offsets include a fully consumed but uncleared Vec.
    for written in [0, 17, bytes.len()] {
        server.connections.get_mut(&token).unwrap().written = written;
        assert!(!server.swap_empty_peer_output(key));
        let conn = &server.connections[&token];
        assert_eq!(conn.output, bytes);
        assert_eq!(conn.written, written);
        assert_eq!(conn.output.as_ptr(), original_pointer);
        assert_eq!(server.tcp_return_output.as_ptr(), shared_pointer);
    }
    let conn = server.connections.get_mut(&token).unwrap();
    conn.output.clear();
    conn.written = 0;
    assert!(server.swap_empty_peer_output(key));
    let conn = server.connections.get_mut(&token).unwrap();
    conn.queue(&bytes).unwrap();
    conn.written = 17;
    assert!(
        !server.swap_empty_peer_output(key),
        "a pending loan stays with its writer"
    );
    let conn = &server.connections[&token];
    assert_eq!(&conn.output[conn.written..], &bytes[17..]);
    assert_eq!(conn.output.as_ptr(), shared_pointer);
    assert_eq!(server.tcp_return_output.as_ptr(), original_pointer);
    assert!(server.tcp_return_output.is_empty());
}

#[test]
fn batch_output_close_while_lent_leaves_empty_storage_available() {
    let (mut server, _clients, tokens) = batch_output_fixture(2);
    let key = Client::Stream(tokens[0]);
    server.tcp_return_output = Vec::with_capacity(TCP_RETURN_BATCH_BYTES);
    let original_pointer = server.connections[&tokens[0]].output.as_ptr();
    assert!(server.swap_empty_peer_output(key));
    server
        .connections
        .get_mut(&tokens[0])
        .unwrap()
        .queue(b"accepted tail")
        .unwrap();
    server.close(tokens[0]);
    assert!(!server.swap_empty_peer_output(key));
    assert!(!server.connections.contains_key(&tokens[0]));
    assert!(server.tcp_return_output.is_empty());
    assert_eq!(server.tcp_return_output.as_ptr(), original_pointer);
    assert!(server.swap_empty_peer_output(Client::Stream(tokens[1])));
    assert!(server.connections[&tokens[1]].output.is_empty());
    assert_eq!(
        server.connections[&tokens[1]].output.as_ptr(),
        original_pointer
    );
}

#[test]
fn batch_output_flushes_at_frame_and_byte_limits_and_on_dispatch_end() {
    let (mut server, mut clients, tokens) = batch_output_fixture(1);
    let token = tokens[0];
    let key = Client::Stream(token);
    let mut batch = server.peer_return_batch(key);
    let small = [0x41; 8];
    for _ in 0..TCP_RETURN_BATCH_FRAMES - 1 {
        assert!(server.send_peer_packet(key, &small, 4, &mut batch));
    }
    let mut buffer = [0; TCP_RETURN_BATCH_BYTES + 4];
    assert_eq!(
        clients[0].read(&mut buffer).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(server.send_peer_packet(key, &small, 4, &mut batch));
    assert_eq!(batch.frames, 0, "frame limit flushes immediately");
    clients[0].set_nonblocking(false).unwrap();
    clients[0]
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    clients[0]
        .read_exact(&mut buffer[..small.len() * TCP_RETURN_BATCH_FRAMES])
        .unwrap();
    assert!(
        buffer[..small.len() * TCP_RETURN_BATCH_FRAMES]
            .iter()
            .all(|b| *b == 0x41)
    );
    let half = vec![0x52; TCP_RETURN_BATCH_BYTES / 2];
    assert!(server.send_peer_packet(key, &half, half.len() - 4, &mut batch));
    assert!(server.send_peer_packet(key, &half, half.len() - 4, &mut batch));
    assert_eq!(batch.frames, 0, "byte limit flushes before the frame limit");
    clients[0]
        .read_exact(&mut buffer[..TCP_RETURN_BATCH_BYTES])
        .unwrap();
    assert!(buffer[..TCP_RETURN_BATCH_BYTES].iter().all(|b| *b == 0x52));
    assert!(server.send_peer_packet(key, b"tail", 0, &mut batch));
    server.flush_peer_batch(key, &mut batch);
    clients[0].read_exact(&mut buffer[..4]).unwrap();
    assert_eq!(&buffer[..4], b"tail");
    assert!(server.connections[&token].output.is_empty());
}

#[test]
fn batch_output_final_fatal_flush_counts_all_unaccepted_payloads() {
    let (mut server, _clients, tokens) = batch_output_fixture(1);
    let token = tokens[0];
    let key = Client::Stream(token);
    let mut batch = server.peer_return_batch(key);
    // A local write shutdown makes the next write fail deterministically,
    // without relying on delivery of a remote FIN/RST readiness event.
    server.connections[&token]
        .socket
        .shutdown(std::net::Shutdown::Write)
        .unwrap();
    assert!(server.send_peer_packet(key, b"framed-payload", 9, &mut batch));
    assert_eq!(server.stats.forwarded_packets, 0);
    assert!(!server.flush_peer_batch(key, &mut batch));
    assert_eq!(server.stats.forwarded_packets, 0);
    assert_eq!(server.stats.forwarded_bytes, 0);
    assert_eq!(server.transport.stream_bytes, 0);
    assert_eq!(server.stats.dropped_packets, 1);
    assert_eq!(server.transport.stream_errors, 1);
    assert!(!server.connections.contains_key(&token));
    assert!(server.flush_peer_batch(key, &mut batch));
    assert_eq!(server.stats.dropped_packets, 1);
}

#[test]
fn batch_output_threshold_failure_does_not_recount_accepted_batch() {
    let (mut server, _clients, tokens) = batch_output_fixture(1);
    let token = tokens[0];
    let key = Client::Stream(token);
    let mut batch = server.peer_return_batch(key);
    assert!(server.send_peer_packet(key, b"first", 1, &mut batch));
    assert!(server.flush_peer_batch(key, &mut batch));
    assert_eq!(server.stats.forwarded_packets, 1);
    server.connections[&token]
        .socket
        .shutdown(std::net::Shutdown::Write)
        .unwrap();
    for _ in 0..TCP_RETURN_BATCH_FRAMES - 1 {
        assert!(server.send_peer_packet(key, b"next", 2, &mut batch));
    }
    assert!(!server.send_peer_packet(key, b"last", 3, &mut batch));
    assert_eq!(server.stats.forwarded_packets, 1);
    assert_eq!(server.stats.forwarded_bytes, 1);
    assert_eq!(server.transport.stream_bytes, 1);
    assert_eq!(server.stats.dropped_packets, TCP_RETURN_BATCH_FRAMES as u64);
    assert_eq!(server.transport.stream_errors, 1);
    assert!(server.flush_peer_batch(key, &mut batch));
    assert_eq!(server.stats.dropped_packets, TCP_RETURN_BATCH_FRAMES as u64);
}

#[test]
#[cfg(all(feature = "connected-udp", unix))]
fn batch_output_backpressured_acceptance_is_not_recounted_after_failure() {
    let (mut server, clients, tokens) = batch_output_fixture(1);
    let token = tokens[0];
    let key = Client::Stream(token);
    socket2::SockRef::from(&server.connections[&token].socket)
        .set_send_buffer_size(4096)
        .unwrap();
    socket2::SockRef::from(&clients[0])
        .set_recv_buffer_size(4096)
        .unwrap();
    let block = [0x5a; TCP_RETURN_BATCH_BYTES];
    for _ in 0..2048 {
        server.send_client(key, &block);
        let conn = &server.connections[&token];
        if conn.output.len() > conn.written {
            break;
        }
    }
    assert!(server.connections[&token].output.len() > server.connections[&token].written);
    let mut batch = server.peer_return_batch(key);
    assert!(server.send_peer_packet(key, b"queued", 2, &mut batch));
    assert!(server.flush_peer_batch(key, &mut batch));
    assert_eq!(server.stats.forwarded_packets, 1);
    assert_eq!(server.stats.forwarded_bytes, 2);
    // An accepted pending batch remains forwarded when a later batch fails.
    server.connections[&token]
        .socket
        .shutdown(std::net::Shutdown::Write)
        .unwrap();
    assert!(server.send_peer_packet(key, b"failed", 3, &mut batch));
    assert!(!server.flush_peer_batch(key, &mut batch));
    assert_eq!(server.stats.forwarded_packets, 1);
    assert_eq!(server.stats.forwarded_bytes, 2);
    assert_eq!(server.transport.stream_bytes, 2);
    assert_eq!(server.stats.dropped_packets, 1);
}

#[test]
fn batch_output_queue_retry_fatal_flush_counts_batch_and_new_frame_once() {
    let (mut server, _clients, tokens) = batch_output_fixture(1);
    let token = tokens[0];
    let key = Client::Stream(token);
    let mut batch = server.peer_return_batch(key);
    // Model an already accepted full pending queue, leaving room for one
    // short batch frame. Its historical acceptance must stay untouched.
    server
        .connections
        .get_mut(&token)
        .unwrap()
        .queue(&vec![0; MAX_QUEUE - STREAM_CONTROL_RESERVE - 4])
        .unwrap();
    server.forwarded(key, 100);
    assert!(server.send_peer_packet(key, b"next", 2, &mut batch));
    server.connections[&token]
        .socket
        .shutdown(std::net::Shutdown::Write)
        .unwrap();
    assert!(!server.send_peer_packet(key, b"last", 3, &mut batch));
    assert_eq!(server.stats.forwarded_packets, 1);
    assert_eq!(server.stats.forwarded_bytes, 100);
    assert_eq!(server.transport.stream_bytes, 100);
    assert_eq!(server.stats.dropped_packets, 2);
    assert_eq!(server.transport.stream_errors, 1);
    assert!(server.flush_peer_batch(key, &mut batch));
    assert_eq!(server.stats.dropped_packets, 2);
}

#[test]
fn batch_output_excludes_udp_and_tls() {
    let (mut server, _clients, tokens) = batch_output_fixture(1);
    let key = Client::Stream(tokens[0]);
    assert!(server.peer_return_batch(key).enabled);
    assert!(
        !server
            .peer_return_batch(Client::Datagram("127.0.0.1:1".parse().unwrap()))
            .enabled
    );
    #[cfg(feature = "tls")]
    {
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
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(NoCertificate));
        server.connections.get_mut(&tokens[0]).unwrap().tls =
            Some(rustls::ServerConnection::new(Arc::new(config)).unwrap());
        assert!(!server.peer_return_batch(key).enabled);
    }
    server.close(tokens[0]);
    assert!(!server.peer_return_batch(key).enabled);
}

#[test]
#[cfg(all(feature = "connected-udp", unix))]
fn stream_processes_valid_batch_larger_than_input_limit() {
    let mut config = Config::local(vec![1; 32]);
    config.listen.set_port(0);
    let mut server = bind_server(config);
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
    let mut server = bind_server(config);
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
    assert_eq!(server.relay_metrics().stream_errors, 1);

    healthy.write_all(&requests[3]).unwrap();
    drive_until(&mut server, |server| {
        server.connections[&healthy_token].last_active > server.connections[&healthy_token].created
    });
    binding_response(&mut healthy, [4; 12]);
    drop(healthy);
    drive_until(&mut server, |server| server.connections.is_empty());
    assert_eq!(
        server.relay_metrics().stream_errors,
        1,
        "ordinary EOF is not a failure"
    );
    assert_eq!(
        server.relay_metrics().stream_forwarded_bytes,
        0,
        "STUN replies are not relayed payload"
    );
}

#[test]
fn stream_capacity_refusals_are_counted_without_displacing_the_live_socket() {
    let mut config = Config::local(vec![1; 32]);
    config.listen.set_port(0);
    config.max_connections = 1;
    let mut server = bind_server(config);
    let live = std::net::TcpStream::connect(server.local_addr().unwrap()).unwrap();
    accept_stream(&mut server);
    let refused = std::net::TcpStream::connect(server.local_addr().unwrap()).unwrap();
    drive_until(&mut server, |server| {
        server.relay_metrics().refused_streams == 1
    });
    assert_eq!(server.relay_metrics().stream_connections, 1);
    assert_eq!(server.relay_metrics().stream_errors, 0);
    drop((live, refused));
    drive_until(&mut server, |server| server.connections.is_empty());
    assert_eq!(server.relay_metrics().stream_errors, 0);
}

#[test]
fn stream_processes_complete_frames_before_eof() {
    let mut config = Config::local(vec![1; 32]);
    config.listen.set_port(0);
    let mut server = bind_server(config);
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
    let mut server = bind_server(config);
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
    let mut server = bind_server(config);
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
    let mut server = bind_server(config);
    let mut hot = std::net::TcpStream::connect(server.local_addr().unwrap()).unwrap();
    hot.set_nodelay(true).unwrap();
    accept_stream(&mut server);
    let hot_token = *server.connections.keys().next().unwrap();

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

    // Queue the backlog only after every connection is accepted. Accepting
    // drives the server, and each turn spent there would consume part of the
    // backlog before the single turn measured below.
    let indication = Builder::new(BINDING, 1, [1; 12]).finish(None);
    let backlog = indication.repeat(STREAM_FRAMES_PER_TURN * 16);
    hot.write_all(&backlog).unwrap();
    wait_for_queued(&server, hot_token, backlog.len());
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
    let mut server = bind_server(config);
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
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    use std::{
        fs::{self, OpenOptions},
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
    let certificates = CertificateDer::pem_file_iter(certificate)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_file(private_key).unwrap();
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
    let mut server = bind_server(config);
    let mut client =
        std::net::TcpStream::connect(server.tls_listener.as_ref().unwrap().local_addr().unwrap())
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

/// Two datagram clients with one allocation each, as the fixture for the
/// aggregate cap. Returns the server, each client's socket, each peer's
/// socket and each allocation's relay token and address.
#[cfg(all(feature = "connected-udp", unix))]
#[allow(clippy::type_complexity)]
fn two_allocations(
    aggregate: Option<u64>,
) -> (
    Server,
    Vec<std::net::UdpSocket>,
    Vec<std::net::UdpSocket>,
    Vec<(Token, SocketAddr)>,
) {
    let mut config = Config::local(vec![1; 32]);
    config.listen.set_port(0);
    config.aggregate_bytes_per_second = aggregate;
    let mut server = bind_server(config);
    let (mut clients, mut peers, mut relays) = (Vec::new(), Vec::new(), Vec::new());
    for index in 0..2 {
        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let key = Client::Datagram(client.local_addr().unwrap());
        let relay_socket = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = relay_socket.local_addr().unwrap();
        let token = server.relays.reserve(key);
        let expires = Instant::now() + Duration::from_secs(60);
        server.allocations.insert(
            key,
            Allocation {
                socket: relay_socket,
                client_socket: None,
                token,
                bound_address: address,
                advertised_address: address,
                username: format!("aggregate-fixture-{index}"),
                transaction: [1; 12],
                expires,
                permissions: vec![Permission {
                    ip: peer.local_addr().unwrap().ip(),
                    expires,
                }],
                channels: Vec::new(),
                bandwidth: Bucket::new(64 * 1024 * 1024, 128 * 1024 * 1024, Instant::now()),
                requests: Bucket::new(
                    ALLOCATION_REQUESTS_PER_SECOND,
                    ALLOCATION_REQUEST_BURST,
                    Instant::now(),
                ),
            },
        );
        relays.push((token, address));
        clients.push(client);
        peers.push(peer);
    }
    (server, clients, peers, relays)
}

#[test]
fn new_allocations_reclaim_expired_capacity_before_the_periodic_sweep() {
    for resource in ["node", "user", "port"] {
        let reserved = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = reserved.local_addr().unwrap().port();
        let mut config = Config::local(vec![1; 32]);
        config.listen.set_port(0);
        if resource == "node" {
            config.max_allocations = 1;
        } else if resource == "user" {
            config.max_per_user = 1;
        } else {
            config.relay_port_range = Some((port, port));
        }
        let mut server = bind_server(config);
        drop(reserved);
        let first = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let replacement = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        replacement
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let username = format!("{}:capacity-fixture", unix_time() + 300);
        let key = auth::key(
            &username,
            &server.config.realm,
            &auth::credential(&server.config.secret, &username),
        );
        let nonce = server.nonces.issue(
            unix_time(),
            first.local_addr().unwrap().ip(),
            &server.config.realm,
        );
        let mut request = Builder::new(ALLOCATE, 0, [7; 12]);
        request.attr(USERNAME, username.as_bytes());
        request.attr(REALM, b"spry-turn");
        request.attr(NONCE, nonce.as_bytes());
        request.attr(TRANSPORT, &[17, 0, 0, 0]);
        let request = request.finish(Some(&key));
        let address = first.local_addr().unwrap();
        server.receive(Client::Datagram(address), address, &request);
        assert_eq!(server.allocation_count(), 1);
        server
            .allocations
            .get_mut(&Client::Datagram(address))
            .unwrap()
            .expires = Instant::now();
        // A new NAT path can arrive between expiry and the next timer
        // sweep. Its authenticated Allocate must not count expired leases.
        let address = replacement.local_addr().unwrap();
        server.receive(Client::Datagram(address), address, &request);
        let mut bytes = [0; 2048];
        let length = replacement.recv(&mut bytes).unwrap();
        let answer = Message::parse(&bytes[..length]).unwrap();
        assert!(answer.verify(&key));
        assert_eq!(answer.class, 2, "expired {resource} capacity was refused");
        assert_eq!(server.allocation_count(), 1);
        assert!(server.allocations.contains_key(&Client::Datagram(address)));
        if resource == "port" {
            assert_eq!(server.allocated_relay_ports().collect::<Vec<_>>(), [port]);
        }
    }
}

#[test]
fn authenticated_capacity_refusals_have_distinct_aggregate_counters() {
    for resource in ["node", "user", "port"] {
        let reserved = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = reserved.local_addr().unwrap().port();
        let mut config = Config::local(vec![1; 32]);
        config.listen.set_port(0);
        if resource == "node" {
            config.max_allocations = 1;
        } else if resource == "user" {
            config.max_per_user = 1;
        } else {
            config.relay_port_range = Some((port, port));
        }
        let mut server = bind_server(config);
        drop(reserved);
        let first = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let second = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        for client in [&first, &second] {
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
        }
        let username = format!("{}:quota-fixture", unix_time() + 300);
        let key = auth::key(
            &username,
            &server.config.realm,
            &auth::credential(&server.config.secret, &username),
        );
        let nonce = server.nonces.issue(
            unix_time(),
            first.local_addr().unwrap().ip(),
            &server.config.realm,
        );
        let mut request = Builder::new(ALLOCATE, 0, [7; 12]);
        request.attr(USERNAME, username.as_bytes());
        request.attr(REALM, b"spry-turn");
        request.attr(NONCE, nonce.as_bytes());
        request.attr(TRANSPORT, &[17, 0, 0, 0]);
        let request = request.finish(Some(&key));
        // Retransmissions from the allocated tuple succeed, even at the
        // limit. Unauthenticated requests must not inflate the counters.
        for (client, bytes, expected, error_code) in [
            (&first, request.clone(), 2, None),
            (&first, request.clone(), 2, None),
            (
                &second,
                Builder::new(ALLOCATE, 0, [8; 12]).finish(None),
                3,
                Some(401),
            ),
            (
                &second,
                request,
                3,
                Some(if resource == "port" { 508 } else { 486 }),
            ),
        ] {
            let address = client.local_addr().unwrap();
            server.receive(Client::Datagram(address), address, &bytes);
            let mut answer = [0; 2048];
            let length = client.recv(&mut answer).unwrap();
            let answer = Message::parse(&answer[..length]).unwrap();
            assert_eq!(answer.class, expected);
            if let Some(expected_code) = error_code {
                let error = answer.attr(ERROR).unwrap();
                let code = u16::from(error[2]) * 100 + u16::from(error[3]);
                assert_eq!(code, expected_code);
                if code != 401 {
                    assert!(answer.verify(&key));
                }
            }
        }
        let metrics = server.relay_metrics();
        assert_eq!(
            metrics.allocation_quota_refusals,
            u64::from(resource == "node")
        );
        assert_eq!(metrics.user_quota_refusals, u64::from(resource == "user"));
        assert_eq!(metrics.relay_bind_failures, u64::from(resource == "port"));
        assert_eq!(metrics.refused_streams, 0);
        assert_eq!(server.allocation_count(), 1);
    }
}

#[test]
fn invalid_allocation_lifetime_caps_are_refused_before_binding() {
    for lifetime in [0, 3601] {
        let mut config = Config::local(vec![1; 32]);
        config.listen.set_port(0);
        config.max_allocation_lifetime = lifetime;
        assert!(Server::bind(config).is_err());
    }
}

#[test]
fn zero_lifetime_refresh_tears_down_before_ack_and_preserves_endpoint() {
    for wildcard in [false, true] {
        let mut config = Config::local(vec![1; 32]);
        config.listen = if wildcard { "0.0.0.0:0" } else { "127.0.0.1:0" }
            .parse()
            .unwrap();
        config.advertised_ip = Some("203.0.113.7".parse().unwrap());
        config.max_allocations = 1;
        config.max_allocation_lifetime = 60;
        let mut server = bind_server(config);
        let endpoint = SocketAddr::new(
            "127.0.0.1".parse().unwrap(),
            server.local_addr().unwrap().port(),
        );
        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        client.set_nonblocking(true).unwrap();
        let address = client.local_addr().unwrap();
        let identity = Client::Datagram(address);
        let username = format!("{}:deallocation-fixture", unix_time() + 300);
        let key = auth::key(
            &username,
            &server.config.realm,
            &auth::credential(&server.config.secret, &username),
        );
        let nonce = server
            .nonces
            .issue(unix_time(), address.ip(), &server.config.realm);
        let request = |method, lifetime| {
            let mut value = Builder::new(method, 0, [7; 12]);
            value.attr(USERNAME, username.as_bytes());
            value.attr(REALM, b"spry-turn");
            value.attr(NONCE, nonce.as_bytes());
            value.attr(TRANSPORT, &[17, 0, 0, 0]);
            value.number(LIFETIME, lifetime);
            value.finish(Some(&key))
        };
        let answer = |server: &mut Server, phase, method, class, expected_lifetime, error_code| {
            let mut bytes = [0; 2048];
            let deadline = Instant::now() + Duration::from_secs(2);
            let (length, source) = loop {
                match client.recv_from(&mut bytes) {
                    Ok(answer) => break answer,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "{phase}, wildcard={wildcard}: reply did not arrive"
                        );
                        // A poll can first report another readiness edge,
                        // including the removed socket. Drive the event
                        // loop until the reply arrives; never resend.
                        server.poll_once(Duration::from_millis(10)).unwrap();
                    }
                    Err(error) => panic!("receive failed: {error}"),
                }
            };
            assert_eq!(
                source, endpoint,
                "the advertised peer IP is not the listener"
            );
            let response = Message::parse(&bytes[..length]).unwrap();
            assert_eq!(
                (response.method, response.class),
                (method, class),
                "{phase}, wildcard={wildcard}: unexpected TURN error {:?}",
                response
                    .attr(ERROR)
                    .map(|error| u16::from(error[2]) * 100 + u16::from(error[3]))
            );
            assert_eq!(response.transaction, [7; 12]);
            assert!(response.verify(&key));
            assert_eq!(response.number(LIFETIME), expected_lifetime);
            if let Some(expected) = error_code {
                let error = response.attr(ERROR).unwrap();
                assert_eq!(u16::from(error[2]) * 100 + u16::from(error[3]), expected);
            }
        };
        server.receive(identity, address, &request(ALLOCATE, 60));
        answer(&mut server, "initial", ALLOCATE, 2, Some(60), None);
        // Let the kernel choose the first allocation's port without a
        // reserve/drop/rebind gap, then require its reuse after teardown.
        let relay_port = server.allocations[&identity].bound_address.port();
        server.config.relay_port_range = Some((relay_port, relay_port));
        server.next_relay_port = relay_port;
        #[cfg(all(feature = "connected-udp", unix))]
        assert_eq!(
            server.allocations[&identity].client_socket.is_some(),
            !wildcard
        );
        // send_client's test-only assertion checks that teardown already
        // happened at the send boundary, deterministically rejecting the
        // previous response-before-close ordering without a timing race.
        server.receive(identity, address, &request(REFRESH, 0));
        answer(&mut server, "deallocation", REFRESH, 2, Some(0), None);
        assert_eq!(server.allocation_count(), 0);
        assert!(server.relay_ports.is_empty());
        assert!(server.own_public_to_local.is_empty());
        assert!(server.own_local_to_public.is_empty());
        client.send_to(&request(REFRESH, 60), endpoint).unwrap();
        answer(&mut server, "post-ack", REFRESH, 3, None, Some(437));
        client.send_to(&request(ALLOCATE, 60), endpoint).unwrap();
        answer(&mut server, "replacement", ALLOCATE, 2, Some(60), None);
        assert_eq!(
            server.allocations[&identity].bound_address.port(),
            relay_port
        );
    }
}

#[test]
fn short_allocation_leases_refresh_and_free_an_orphaned_stream_port() {
    let reserved = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = reserved.local_addr().unwrap().port();
    let mut config = Config::local(vec![1; 32]);
    config.listen.set_port(0);
    config.relay_port_range = Some((port, port));
    config.max_allocation_lifetime = 30;
    let mut server = bind_server(config);
    let mut client = std::net::TcpStream::connect(server.local_addr().unwrap()).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    accept_stream(&mut server);
    let token = *server.connections.keys().next().unwrap();
    let address = client.local_addr().unwrap();
    drop(reserved);
    let username = format!("{}:lease-fixture", unix_time() + 300);
    let key = auth::key(
        &username,
        &server.config.realm,
        &auth::credential(&server.config.secret, &username),
    );
    let nonce = server
        .nonces
        .issue(unix_time(), address.ip(), &server.config.realm);
    let request = |method, lifetime| {
        let mut value = Builder::new(method, 0, [7; 12]);
        value.attr(USERNAME, username.as_bytes());
        value.attr(REALM, b"spry-turn");
        value.attr(NONCE, nonce.as_bytes());
        value.attr(TRANSPORT, &[17, 0, 0, 0]);
        value.number(LIFETIME, lifetime);
        value.finish(Some(&key))
    };
    let answer = |client: &mut std::net::TcpStream, method| {
        let mut header = [0; 20];
        client.read_exact(&mut header).unwrap();
        let mut bytes = header.to_vec();
        bytes.resize(
            20 + usize::from(u16::from_be_bytes([header[2], header[3]])),
            0,
        );
        client.read_exact(&mut bytes[20..]).unwrap();
        let value = Message::parse(&bytes).unwrap();
        assert_eq!((value.method, value.class), (method, 2));
        assert!(value.verify(&key));
        value.number(LIFETIME).unwrap()
    };
    server.receive(Client::Stream(token), address, &request(ALLOCATE, 3600));
    assert_eq!(answer(&mut client, ALLOCATE), 30);
    let allocation = server.allocations.get_mut(&Client::Stream(token)).unwrap();
    allocation.expires = Instant::now() + Duration::from_secs(1);
    server.receive(Client::Stream(token), address, &request(REFRESH, 3600));
    assert_eq!(answer(&mut client, REFRESH), 30);
    assert!(
        server.allocations[&Client::Stream(token)].expires
            > Instant::now() + Duration::from_secs(29)
    );
    // Model an abandoned transport after its thirty-second lease. Sweep
    // must release its one reserved port even though the client stays open.
    server
        .allocations
        .get_mut(&Client::Stream(token))
        .unwrap()
        .expires = Instant::now();
    server.connections.get_mut(&token).unwrap().created = Instant::now() - Duration::from_secs(31);
    server.sweep();
    assert_eq!(server.allocation_count(), 0);
    assert!(!server.connections.contains_key(&token));
    assert!(server.relay_ports.is_empty());
    assert_eq!(client.read(&mut [0]).unwrap(), 0);
    let mut replacement = std::net::TcpStream::connect(server.local_addr().unwrap()).unwrap();
    replacement
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    accept_stream(&mut server);
    let token = *server.connections.keys().next().unwrap();
    let address = replacement.local_addr().unwrap();
    server.receive(Client::Stream(token), address, &request(ALLOCATE, 3600));
    assert_eq!(answer(&mut replacement, ALLOCATE), 30);
    assert_eq!(
        server.allocations[&Client::Stream(token)]
            .bound_address
            .port(),
        port
    );
    server.receive(Client::Stream(token), address, &request(REFRESH, 0));
    assert_eq!(answer(&mut replacement, REFRESH), 0);
    assert_eq!(server.allocation_count(), 0);
}

#[test]
fn revoked_cached_login_cannot_allocate_or_refresh_again() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let allowed = Arc::new(AtomicBool::new(true));
    let gate = allowed.clone();
    let mut config = Config::local(vec![1; 32]);
    config.listen.set_port(0);
    config.allow_loopback_peers = true;
    config.credential_authorizer = Some(Arc::new(move |_| gate.load(Ordering::Acquire)));
    let mut server = bind_server(config);
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer = socket.local_addr().unwrap();
    let username = format!("{}:revocation-fixture", unix_time() + 300);
    let password = auth::credential(&server.config.secret, &username);
    let key = auth::key(&username, &server.config.realm, &password);
    let nonce = server
        .nonces
        .issue(unix_time(), peer.ip(), &server.config.realm);
    let request = |method, transaction| {
        let mut request = Builder::new(method, 0, [transaction; 12]);
        request.attr(USERNAME, username.as_bytes());
        request.attr(REALM, b"spry-turn");
        request.attr(NONCE, nonce.as_bytes());
        request.attr(TRANSPORT, &[17, 0, 0, 0]);
        request.finish(Some(&key))
    };
    server.receive(Client::Datagram(peer), peer, &request(ALLOCATE, 1));
    assert_eq!(server.allocation_count(), 1);
    allowed.store(false, Ordering::Release);
    server.poll_once(Duration::ZERO).unwrap();
    assert_eq!(server.allocation_count(), 0);
    for method in [ALLOCATE, REFRESH] {
        server.receive(Client::Datagram(peer), peer, &request(method, 2));
        assert_eq!(
            server.allocation_count(),
            0,
            "cached credential restored access"
        );
    }
}

#[test]
fn revocation_closes_the_stream_and_a_new_stream_cannot_reuse_its_login() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let allowed = Arc::new(AtomicBool::new(true));
    let gate = allowed.clone();
    let mut config = Config::local(vec![1; 32]);
    config.listen.set_port(0);
    config.allow_loopback_peers = true;
    config.credential_authorizer = Some(Arc::new(move |_| gate.load(Ordering::Acquire)));
    let mut server = bind_server(config);
    let address = server.local_addr().unwrap();
    let mut client = std::net::TcpStream::connect(address).unwrap();
    accept_stream(&mut server);
    let username = format!("{}:stream-revocation-fixture", unix_time() + 300);
    let password = auth::credential(&server.config.secret, &username);
    let key = auth::key(&username, &server.config.realm, &password);
    let nonce = server.nonces.issue(
        unix_time(),
        client.local_addr().unwrap().ip(),
        &server.config.realm,
    );
    let mut request = Builder::new(ALLOCATE, 0, [7; 12]);
    request.attr(USERNAME, username.as_bytes());
    request.attr(REALM, b"spry-turn");
    request.attr(NONCE, nonce.as_bytes());
    request.attr(TRANSPORT, &[17, 0, 0, 0]);
    let request = request.finish(Some(&key));
    client.write_all(&request).unwrap();
    drive_until(&mut server, |server| server.allocation_count() == 1);
    allowed.store(false, Ordering::Release);
    server.poll_once(Duration::ZERO).unwrap();
    assert_eq!(server.allocation_count(), 0);
    assert!(server.connections.is_empty());
    let mut retry = std::net::TcpStream::connect(address).unwrap();
    retry
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    accept_stream(&mut server);
    retry.write_all(&request).unwrap();
    drive_until(&mut server, |server| {
        server
            .connections
            .values()
            .any(|c| c.last_active > c.created)
    });
    let mut header = [0; 20];
    retry.read_exact(&mut header).unwrap();
    let mut response = header.to_vec();
    response.resize(20 + u16::from_be_bytes([header[2], header[3]]) as usize, 0);
    retry.read_exact(&mut response[20..]).unwrap();
    let response = Message::parse(&response).unwrap();
    assert_eq!((response.method, response.class), (ALLOCATE, 3));
    assert_eq!(server.allocation_count(), 0);
}

#[test]
#[cfg(all(feature = "connected-udp", unix))]
fn a_live_credential_policy_removes_only_the_revoked_allocation() {
    let (mut server, _clients, _peers, _) = two_allocations(None);
    server.config.credential_authorizer =
        Some(Arc::new(|username| username == "aggregate-fixture-1"));
    server.poll_once(Duration::ZERO).unwrap();
    assert_eq!(server.allocation_count(), 1);
    assert_eq!(
        server.allocations.values().next().unwrap().username,
        "aggregate-fixture-1"
    );
}

#[test]
#[cfg(all(feature = "connected-udp", unix))]
fn aggregate_cap_is_spent_by_all_allocations_together() {
    for (aggregate, forwarded, dropped) in [(Some(3000), 3000, 1), (None, 4000, 0)] {
        let (mut server, _clients, peers, relays) = two_allocations(aggregate);
        let payload = [0x42; 1000];
        // Two packets for each allocation: four thousand bytes in all,
        // far inside every allocation's own allowance.
        for (peer, (_, address)) in peers.iter().zip(&relays) {
            peer.send_to(&payload, address).unwrap();
            peer.send_to(&payload, address).unwrap();
        }
        std::thread::sleep(Duration::from_millis(50));
        let mut scratch = vec![0; MAX_PACKET + HEADROOM];
        for (token, _) in &relays {
            server.receive_peer(*token, &mut scratch);
        }
        assert_eq!(
            (server.stats.forwarded_bytes, server.stats.dropped_packets),
            (forwarded, dropped),
            "aggregate {aggregate:?}"
        );
        let metrics = server.relay_metrics();
        assert_eq!(metrics.udp_allocations, 2);
        assert_eq!(metrics.stream_allocations, 0);
        assert_eq!(metrics.udp_forwarded_bytes, forwarded);
        assert_eq!(metrics.stream_forwarded_bytes, 0);
        assert_eq!(metrics.dropped_packets, dropped);
        if aggregate.is_some() {
            // The second allocation was the one cut short, though it had
            // used nothing itself: the cap belongs to the total.
            assert_eq!(server.stats.forwarded_packets, 3);
        }
    }
}

#[test]
fn a_refusal_by_the_aggregate_returns_the_allocations_own_tokens() {
    let now = Instant::now();
    let mut allocation = Bucket::new(1000, 1000, now);
    let mut aggregate = Some(Bucket::new(500, 500, now));
    assert!(!Server::within_budget(
        &mut allocation,
        &mut aggregate,
        600,
        now
    ));
    // The allocation still holds its whole second, and the aggregate
    // was not charged for the packet it refused.
    assert!(Server::within_budget(&mut allocation, &mut None, 1000, now));
    assert!(Server::within_budget(
        &mut Bucket::new(1000, 1000, now),
        &mut aggregate,
        500,
        now
    ));
    // Without an aggregate only the allocation's own limit applies.
    assert!(!Server::within_budget(
        &mut Bucket::new(1000, 1000, now),
        &mut None,
        1001,
        now
    ));
}

#[test]
fn a_zero_aggregate_is_refused_at_bind() {
    let mut config = Config::local(vec![1; 32]);
    config.listen.set_port(0);
    config.aggregate_bytes_per_second = Some(0);
    assert!(Server::bind(config).is_err());
}

#[test]
fn only_addresses_beyond_the_hosts_own_networks_count_as_remote() {
    let mut config = Config::local(vec![1; 32]);
    config.relay_ip = "198.51.100.20".parse().unwrap();
    config.advertised_ip = Some("203.0.113.7".parse().unwrap());
    for local in [
        "127.0.0.1",
        "0.0.0.0",
        "10.1.2.3",
        "172.16.0.9",
        "192.168.1.5",
        "169.254.7.7",
        "224.0.0.1",
        "255.255.255.255",
        "::1",
        "::",
        "fd00::1",
        "fe80::1",
        "ff02::1",
        "::ffff:192.168.1.5",
        "::ffff:127.0.0.1",
        // The host itself, through its router or on its own interface.
        "203.0.113.7",
        "198.51.100.20",
        "::ffff:203.0.113.7",
    ] {
        assert!(
            !remote_client(local.parse().unwrap(), &config),
            "{local} is local"
        );
    }
    for remote in ["198.51.100.99", "100.64.0.1", "8.8.8.8", "2001:db8::1"] {
        assert!(
            remote_client(remote.parse().unwrap(), &config),
            "{remote} is remote"
        );
    }
}

#[test]
#[cfg(all(feature = "connected-udp", unix))]
fn relay_overload_preserves_stream_and_resumes_both_framing_paths() {
    // Below macOS's 9216-byte UDP datagram limit. Socket capacity can
    // change while the test runs, so observe an actual drop in a bounded
    // non-reading burst rather than assuming its first frame must drop.
    const OVERLOAD_PAYLOAD: usize = 8192;
    for channel in [None, Some(0x4000_u16)] {
        let mut config = Config::local(vec![1; 32]);
        config.listen.set_port(0);
        let mut server = bind_server(config);
        // Small buffers reach real backpressure promptly, but neither
        // their requested size nor an earlier WouldBlock fixes how many
        // bytes a later retry flush can accept on every supported OS.
        let client = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();
        client.set_recv_buffer_size(2048).unwrap();
        client
            .connect(&server.local_addr().unwrap().into())
            .unwrap();
        let mut client = std::net::TcpStream::from(client);
        client.set_nonblocking(true).unwrap();
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
                requests: Bucket::new(
                    ALLOCATION_REQUESTS_PER_SECOND,
                    ALLOCATION_REQUEST_BURST,
                    Instant::now(),
                ),
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
        let prefix_len = expected;
        let payload = vec![0x7e; OVERLOAD_PAYLOAD];
        let mut scratch = vec![0; MAX_PACKET + HEADROOM];
        let wait_for_peer = |server: &Server| {
            let queued_by = Instant::now() + Duration::from_secs(2);
            let mut peek = vec![0; OVERLOAD_PAYLOAD];
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
        let saturate_by = Instant::now() + Duration::from_secs(5);
        let mut admitted = 0_u64;
        let mut observed_drop = false;
        for attempt in 0..256 {
            assert!(
                Instant::now() < saturate_by,
                "saturation deadline at {attempt}"
            );
            let conn = &server.connections[&token];
            let queued = conn.output.clone();
            let written = conn.written;
            let forwarded = server.stats.forwarded_packets;
            let dropped = server.stats.dropped_packets;
            peer.send_to(&payload, address).unwrap();
            wait_for_peer(&server);
            server.receive_peer(relay_token, &mut scratch);
            assert!(
                server.connections.contains_key(&token),
                "UDP overload must retain control stream"
            );
            assert!(server.allocations.contains_key(&key));
            match (
                server.stats.forwarded_packets - forwarded,
                server.stats.dropped_packets - dropped,
            ) {
                (1, 0) => admitted += 1,
                (0, 1) => {
                    let conn = &server.connections[&token];
                    assert!(
                        conn.output == queued && conn.written >= written,
                        "drop cannot truncate or partly queue a new frame"
                    );
                    observed_drop = true;
                    break;
                }
                outcome => panic!("frame must be wholly admitted or dropped: {outcome:?}"),
            }
        }
        assert!(
            observed_drop,
            "bounded non-reading burst did not reach overload"
        );
        assert_eq!(server.stats.dropped_packets, 1);
        assert_eq!(
            (server.stats.forwarded_packets, server.stats.forwarded_bytes),
            (admitted, admitted * payload.len() as u64)
        );
        // Every admitted frame must survive, even if an earlier retry
        // flush legitimately freed enough capacity to accept it.
        let frame_len = if channel.is_some() {
            4 + payload.len()
        } else {
            let (_, address_len) = address_value(peer_address, &[0; 12]);
            (20 + 4 + address_len + 4 + payload.len() + 3) & !3
        };
        expected += admitted as usize * frame_len;

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
        assert!(received[..prefix_len].iter().all(|byte| *byte == 0x5a));
        let mut frames = &received[prefix_len..expected - 4];
        for _ in 0..admitted {
            let len = wire::frame_len(frames).expect("complete admitted frame");
            assert_eq!(len, frame_len);
            let frame = &frames[..len];
            if let Some(number) = channel {
                assert_eq!(wire::channel(frame), Some((number, payload.as_slice())));
            } else {
                let indication = Message::parse(frame).unwrap();
                assert_eq!((indication.method, indication.class), (DATA_METHOD, 1));
                assert_eq!(indication.attr(DATA), Some(payload.as_slice()));
            }
            frames = &frames[len..];
        }
        assert!(frames.is_empty(), "no truncated or extra admitted frames");
        assert_eq!(&received[expected - 4..], b"ctrl");
        assert!(server.connections[&token].output.is_empty());

        peer.send_to(&payload, address).unwrap();
        wait_for_peer(&server);
        server.receive_peer(relay_token, &mut scratch);
        assert_eq!(server.stats.dropped_packets, 1);
        assert_eq!(
            (server.stats.forwarded_packets, server.stats.forwarded_bytes),
            (admitted + 1, (admitted + 1) * payload.len() as u64)
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

#[cfg(all(feature = "connected-udp", unix))]
fn recovered_relay_packet(channel: Option<u16>) {
    let mut config = Config::local(vec![1; 32]);
    config.listen.set_port(0);
    let mut server = bind_server(config);
    let mut client = std::net::TcpStream::connect(server.local_addr().unwrap()).unwrap();
    client.set_nonblocking(true).unwrap();
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
    server.allocations.insert(
        key,
        Allocation {
            socket: relay_socket,
            client_socket: None,
            token: relay_token,
            bound_address: address,
            advertised_address: address,
            username: "recovered-stream-fixture".into(),
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
            requests: Bucket::new(
                ALLOCATION_REQUESTS_PER_SECOND,
                ALLOCATION_REQUEST_BURST,
                Instant::now(),
            ),
        },
    );

    // First reach genuine nonblocking socket backpressure, then fill
    // only the existing bounded application queue, as a relay burst can.
    let block = vec![0x5a; 32_768];
    let mut expected_prefix = 0;
    for _ in 0..1024 {
        server.send_client(key, &block);
        expected_prefix += block.len();
        let conn = &server.connections[&token];
        if conn.written < conn.output.len() {
            break;
        }
    }
    let conn = server.connections.get_mut(&token).unwrap();
    let pending = conn.output.len() - conn.written;
    assert!(pending != 0, "socket is genuinely backpressured");
    let fill = MAX_QUEUE - STREAM_CONTROL_RESERVE - pending;
    conn.queue(&vec![0x5a; fill]).unwrap();
    expected_prefix += fill;
    let queued = (conn.output.clone(), conn.written);
    let kernel_prefix = expected_prefix - (MAX_QUEUE - STREAM_CONTROL_RESERVE);

    // Recover kernel writability without servicing the server's stream
    // handler: the next ready event may instead be this relay socket.
    socket2::SockRef::from(&conn.socket)
        .set_send_buffer_size(1_048_576)
        .unwrap();
    let mut scratch = vec![0; MAX_PACKET + HEADROOM];
    let mut received = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while received.len() < kernel_prefix && Instant::now() < deadline {
        match client.read(&mut scratch) {
            Ok(0) => panic!("stream closed before writable recovery"),
            Ok(n) => received.extend_from_slice(&scratch[..n]),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::yield_now(),
            Err(e) => panic!("recovery read failed: {e}"),
        }
    }
    assert_eq!(received.len(), kernel_prefix);
    let mut events = Events::with_capacity(16);
    let mut writable = false;
    while !writable && Instant::now() < deadline {
        server
            .poll
            .poll(&mut events, Some(Duration::from_millis(1)))
            .unwrap();
        writable = events
            .iter()
            .any(|event| event.token() == token && event.is_writable());
    }
    assert!(writable, "destination socket recovered write capacity");
    let conn = &server.connections[&token];
    assert_eq!((&conn.output, conn.written), (&queued.0, queued.1));
    assert!(conn.writable_interest);

    let payload = vec![0x7e; 2048];
    peer.send_to(&payload, address).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match server.allocations[&key].socket.peek_from(&mut scratch) {
            Ok((n, from)) => {
                assert_eq!((n, from), (payload.len(), peer_address));
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "authorised relay packet did not arrive"
                );
                std::thread::yield_now();
            }
            Err(e) => panic!("relay peek failed: {e}"),
        }
    }
    server.receive_peer(relay_token, &mut scratch);
    assert_eq!(
        server.stats.dropped_packets, 0,
        "a recovered writable stream must retry queued output before dropping the new relay packet"
    );
    assert_eq!(
        (server.stats.forwarded_packets, server.stats.forwarded_bytes),
        (1, payload.len() as u64)
    );
    assert!(server.allocations.contains_key(&key));
    let metrics = server.relay_metrics();
    assert_eq!(
        (
            metrics.udp_allocations,
            metrics.stream_allocations,
            metrics.stream_connections
        ),
        (0, 1, 1)
    );
    assert_eq!(
        (metrics.udp_forwarded_bytes, metrics.stream_forwarded_bytes),
        (0, payload.len() as u64)
    );
    assert_eq!(metrics.stream_errors, 0);
    let conn = &server.connections[&token];
    assert!(conn.output.is_empty());
    assert!(
        !conn.writable_interest,
        "drained output returns to read interest"
    );

    // No new server poll/flush or inbound control data may rescue this
    // delivery. Both the old prefix and the new whole frame must arrive.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match client.read(&mut scratch) {
            Ok(0) => panic!("stream closed while reading the admitted frame"),
            Ok(n) => received.extend_from_slice(&scratch[..n]),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::yield_now(),
            Err(e) => panic!("frame read failed: {e}"),
        }
        if received.len() >= expected_prefix
            && wire::frame_len(&received[expected_prefix..])
                .is_some_and(|len| len == received.len() - expected_prefix)
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "admitted relay frame did not drain"
        );
    }
    assert!(received[..expected_prefix].iter().all(|byte| *byte == 0x5a));
    let frame = &received[expected_prefix..];
    if let Some(number) = channel {
        assert_eq!(wire::channel(frame), Some((number, payload.as_slice())));
    } else {
        let indication = Message::parse(frame).unwrap();
        assert_eq!((indication.method, indication.class), (DATA_METHOD, 1));
        assert_eq!(indication.attr(DATA), Some(payload.as_slice()));
    }
}

#[test]
#[cfg(all(feature = "connected-udp", unix))]
fn relay_indication_retries_recovered_stream_before_overload_drop() {
    recovered_relay_packet(None);
}

#[test]
#[cfg(all(feature = "connected-udp", unix))]
fn relay_channel_retries_recovered_stream_before_overload_drop() {
    recovered_relay_packet(Some(0x4000));
}

#[test]
#[cfg(all(feature = "connected-udp", unix))]
fn stream_backpressure_rearms_and_returns_to_read_interest() {
    let mut config = Config::local(vec![1; 32]);
    config.listen.set_port(0);
    let mut server = bind_server(config);
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
    let server = bind_server(config);
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
        let server = bind_server(config);
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
fn own_public_addresses_stay_on_the_host_both_ways() {
    let mut config = Config::local(vec![1; 32]);
    config.relay_ip = "192.168.1.20".parse().unwrap();
    config.advertised_ip = Some("203.0.113.7".parse().unwrap());
    let public_to_local = HashMap::from([(51000, 41000)]);
    let local_to_public = HashMap::from([(41000, 51000)]);
    let target = |config: &Config, peer: &str| {
        Server::own_local_target(config, &public_to_local, peer.parse().unwrap())
    };
    assert_eq!(
        target(&config, "203.0.113.7:51000"),
        "192.168.1.20:41000".parse().unwrap()
    );
    // Other public ports, other hosts and the local address pass through.
    for peer in [
        "203.0.113.7:51001",
        "198.51.100.1:51000",
        "192.168.1.20:41000",
    ] {
        assert_eq!(target(&config, peer), peer.parse().unwrap());
    }
    let now = Instant::now();
    let public = vec![Permission {
        ip: "203.0.113.7".parse().unwrap(),
        expires: now + Duration::from_secs(60),
    }];
    let source = |permissions: &[Permission], from: &str| {
        Server::own_public_source(
            &config,
            &local_to_public,
            permissions,
            now,
            from.parse().unwrap(),
        )
    };
    assert_eq!(
        source(&public, "192.168.1.20:41000"),
        "203.0.113.7:51000".parse().unwrap()
    );
    // Without a permission for the public IP, or from a port that is not
    // a live allocation, the real source is kept.
    assert_eq!(
        source(&[], "192.168.1.20:41000"),
        "192.168.1.20:41000".parse().unwrap()
    );
    assert_eq!(
        source(&public, "192.168.1.20:41001"),
        "192.168.1.20:41001".parse().unwrap()
    );
    assert_eq!(
        source(&public, "198.51.100.1:41000"),
        "198.51.100.1:41000".parse().unwrap()
    );
    // With no distinct advertised address there is nothing to translate.
    let mut plain = config.clone();
    plain.advertised_ip = None;
    assert_eq!(
        target(&plain, "203.0.113.7:51000"),
        "203.0.113.7:51000".parse().unwrap()
    );
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

/// One instance relays one address family. This drives a native IPv6
/// instance end to end over real loopback sockets: the family rules on
/// Allocate, IPv6 XOR address encoding, and data in both directions.
#[test]
fn ipv6_instance_allocates_and_relays_both_directions() {
    let mut config = Config::local(vec![1; 32]);
    config.listen = "[::1]:0".parse().unwrap();
    config.relay_ip = "::1".parse().unwrap();
    config.allow_loopback_peers = true;
    let client = match std::net::UdpSocket::bind("[::1]:0") {
        Ok(socket) => socket,
        // A host without IPv6 loopback cannot run this; say so and stop.
        Err(error) if error.kind() == io::ErrorKind::AddrNotAvailable => {
            eprintln!("skipped: no IPv6 loopback on this host");
            return;
        }
        Err(error) => panic!("IPv6 client socket: {error}"),
    };
    let mut server = bind_server(config);
    let endpoint = server.local_addr().unwrap();
    assert!(endpoint.is_ipv6());
    client.set_nonblocking(true).unwrap();
    let address = client.local_addr().unwrap();
    let peer = std::net::UdpSocket::bind("[::1]:0").unwrap();
    peer.set_nonblocking(true).unwrap();
    let peer_address = peer.local_addr().unwrap();

    let username = format!("{}:ipv6-fixture", unix_time() + 300);
    let key = auth::key(
        &username,
        &server.config.realm,
        &auth::credential(&server.config.secret, &username),
    );
    let nonce = server
        .nonces
        .issue(unix_time(), address.ip(), &server.config.realm);
    let signed = |method, transaction, family: Option<u8>, to: Option<SocketAddr>| {
        let mut value = Builder::new(method, 0, transaction);
        value.attr(USERNAME, username.as_bytes());
        value.attr(REALM, server.config.realm.as_bytes());
        value.attr(NONCE, nonce.as_bytes());
        if method == ALLOCATE {
            value.attr(TRANSPORT, &[17, 0, 0, 0]);
        }
        if let Some(family) = family {
            value.attr(FAMILY, &[family, 0, 0, 0]);
        }
        if let Some(to) = to {
            value.address(PEER, to);
        }
        value.finish(Some(&key))
    };
    let allocate_v4 = signed(ALLOCATE, [1; 12], None, None);
    let allocate_v6 = signed(ALLOCATE, [2; 12], Some(2), None);
    let permit = signed(PERMISSION, [3; 12], None, Some(peer_address));
    // Drive the event loop until `socket` has a datagram; never resend.
    fn receive(
        server: &mut Server,
        socket: &std::net::UdpSocket,
        what: &str,
    ) -> (Vec<u8>, SocketAddr) {
        let mut bytes = [0; 2048];
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match socket.recv_from(&mut bytes) {
                Ok((length, source)) => return (bytes[..length].to_vec(), source),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "{what} did not arrive");
                    server.poll_once(Duration::from_millis(10)).unwrap();
                }
                Err(error) => panic!("{what}: {error}"),
            }
        }
    }
    let error_code = |message: &Message| {
        message
            .attr(ERROR)
            .map(|error| u16::from(error[2]) * 100 + u16::from(error[3]))
    };

    // The default family is IPv4, which this instance does not relay.
    client.send_to(&allocate_v4, endpoint).unwrap();
    let (bytes, _) = receive(&mut server, &client, "family refusal");
    let refused = Message::parse(&bytes).unwrap();
    assert_eq!((refused.method, refused.class), (ALLOCATE, 3));
    assert_eq!(error_code(&refused), Some(440));

    client.send_to(&allocate_v6, endpoint).unwrap();
    let (bytes, source) = receive(&mut server, &client, "allocation");
    assert_eq!(source, endpoint);
    let allocated = Message::parse(&bytes).unwrap();
    assert_eq!(
        (allocated.method, allocated.class),
        (ALLOCATE, 2),
        "unexpected TURN error {:?}",
        error_code(&allocated)
    );
    assert!(allocated.verify(&key));
    assert_eq!(allocated.address(MAPPED), Some(address));
    let relayed = allocated.address(RELAYED).unwrap();
    assert_eq!(relayed.ip(), endpoint.ip());
    assert_ne!(relayed.port(), 0);

    client.send_to(&permit, endpoint).unwrap();
    let (bytes, _) = receive(&mut server, &client, "permission");
    let permitted = Message::parse(&bytes).unwrap();
    assert_eq!(
        (permitted.method, permitted.class),
        (PERMISSION, 2),
        "unexpected TURN error {:?}",
        error_code(&permitted)
    );

    // Client to peer: a Send indication leaves from the relayed address.
    let mut send = Builder::new(SEND, 1, [4; 12]);
    send.address(PEER, peer_address);
    send.attr(DATA, b"to the peer over IPv6");
    client.send_to(&send.finish(None), endpoint).unwrap();
    let (bytes, source) = receive(&mut server, &peer, "relayed payload");
    assert_eq!(bytes, b"to the peer over IPv6");
    assert_eq!(source, relayed);

    // Peer to client: a Data indication names the IPv6 peer.
    peer.send_to(b"back to the client", relayed).unwrap();
    let (bytes, source) = receive(&mut server, &client, "data indication");
    assert_eq!(source, endpoint);
    let data = Message::parse(&bytes).unwrap();
    assert_eq!((data.method, data.class), (DATA_METHOD, 1));
    assert_eq!(data.address(PEER), Some(peer_address));
    assert_eq!(data.attr(DATA), Some(&b"back to the client"[..]));
}

#[test]
fn ipv6_peers_are_global_unicast_without_embedded_or_translated_ipv4() {
    let mut config = Config::local(vec![1; 32]);
    config.relay_ip = "2a00:1450:4009::1".parse().unwrap();
    let none = HashSet::new();
    let allowed = |peer: &str| {
        let address = SocketAddr::new(peer.parse().unwrap(), 3478);
        Server::allowed_peer(&config, &none, &none, address)
    };
    for peer in [
        "2606:4700::1111",
        "2a00:1450:4009::2",
        "2001:200::1",
        "2001:4860::8888",
        "3fef:ffff::1",
        "3000::1",
    ] {
        assert!(allowed(peer), "{peer} is ordinary global unicast");
    }
    for (peer, why) in [
        ("::ffff:10.0.0.1", "IPv4-mapped"),
        ("::10.0.0.1", "IPv4-compatible"),
        ("64:ff9b::10.0.0.1", "NAT64 to a private address"),
        ("64:ff9b::127.0.0.1", "NAT64 to loopback"),
        ("64:ff9b::169.254.169.254", "NAT64 to link-local"),
        ("64:ff9b::8.8.8.8", "NAT64 to any IPv4"),
        ("64:ff9b:1::10.0.0.1", "local-use NAT64"),
        ("2002:a00:1::1", "6to4 embedding 10.0.0.1"),
        ("2001:0:4136:e378:8000:63bf:3fff:fdd2", "Teredo"),
        ("2001:1ff:ffff::1", "end of the IETF special block"),
        ("2001:db8::1", "documentation"),
        ("3fff::1", "documentation, RFC 9637"),
        (
            "3fff:fff:ffff::1",
            "end of the RFC 9637 documentation range",
        ),
        ("4000::1", "outside global unicast"),
        ("fd00::1", "unique local"),
        ("fe80::1", "link-local"),
        ("fec0::1", "site-local"),
        ("100::1", "discard-only"),
        ("::1", "loopback"),
        ("::", "unspecified"),
        ("ff02::1", "multicast"),
    ] {
        assert!(!allowed(peer), "{peer} ({why}) must be refused");
    }
}

/// An unauthenticated flood may spend the budget every source shares, but
/// not the control requests of a client that already holds an allocation.
#[test]
fn an_allocated_client_keeps_control_requests_when_the_shared_budget_is_spent() {
    let mut config = Config::local(vec![1; 32]);
    config.listen.set_port(0);
    let mut server = bind_server(config);
    let endpoint = server.local_addr().unwrap();
    let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    client.set_nonblocking(true).unwrap();
    let address = client.local_addr().unwrap();
    let username = format!("{}:budget-fixture", unix_time() + 300);
    let key = auth::key(
        &username,
        &server.config.realm,
        &auth::credential(&server.config.secret, &username),
    );
    let nonce = server
        .nonces
        .issue(unix_time(), address.ip(), &server.config.realm);
    let signed = |method, transaction: u8| {
        let mut value = Builder::new(method, 0, [transaction; 12]);
        value.attr(USERNAME, username.as_bytes());
        value.attr(REALM, server.config.realm.as_bytes());
        value.attr(NONCE, nonce.as_bytes());
        if method == ALLOCATE {
            value.attr(TRANSPORT, &[17, 0, 0, 0]);
        }
        value.finish(Some(&key))
    };
    let allocate = signed(ALLOCATE, 1);
    let refresh = signed(REFRESH, 2);
    fn reply(server: &mut Server, socket: &std::net::UdpSocket, wait: u64) -> Option<(u16, u8)> {
        let mut bytes = [0; 2048];
        let deadline = Instant::now() + Duration::from_millis(wait);
        loop {
            match socket.recv_from(&mut bytes) {
                Ok((length, _)) => {
                    let message = Message::parse(&bytes[..length]).unwrap();
                    return Some((message.method, message.class));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return None;
                    }
                    server.poll_once(Duration::from_millis(5)).unwrap();
                }
                Err(error) => panic!("receive failed: {error}"),
            }
        }
    }
    client.send_to(&allocate, endpoint).unwrap();
    assert_eq!(reply(&mut server, &client, 2_000), Some((ALLOCATE, 2)));

    // Another source spends the whole shared budget.
    let stranger: SocketAddr = "198.51.100.9:40000".parse().unwrap();
    let binding = Builder::new(BINDING, 0, [3; 12]).finish(None);
    for _ in 0..8_000 {
        server.receive(Client::Datagram(stranger), stranger, &binding);
    }
    // Hold it empty: a real flood keeps taking what refills, and the test
    // must not depend on outrunning that refill.
    server.requests = Bucket::new(0, 0, Instant::now());

    // A newcomer shares that budget and gets nothing.
    let newcomer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    newcomer.set_nonblocking(true).unwrap();
    newcomer.send_to(&binding, endpoint).unwrap();
    assert_eq!(reply(&mut server, &newcomer, 100), None);

    // The allocated client is still answered, for the whole of its burst.
    // Its own budget is frozen too, so the count is exact.
    let allocation = server.allocations.values_mut().next().unwrap();
    allocation.requests = Bucket::new(0, ALLOCATION_REQUEST_BURST, Instant::now());
    for _ in 0..ALLOCATION_REQUEST_BURST {
        client.send_to(&refresh, endpoint).unwrap();
        assert_eq!(reply(&mut server, &client, 2_000), Some((REFRESH, 2)));
    }
    // That budget is bounded: once spent it falls back to the shared one,
    // which is empty.
    client.send_to(&refresh, endpoint).unwrap();
    assert_eq!(reply(&mut server, &client, 100), None);
}

fn source_cap_server(max_connections: usize) -> Server {
    let mut config = Config::local(vec![1; 32]);
    config.listen.set_port(0);
    config.max_connections = max_connections;
    bind_server(config)
}

/// Opens `count` real connections to the relay and waits until it holds them.
fn open_streams(server: &mut Server, count: usize) -> Vec<std::net::TcpStream> {
    let mut clients = Vec::new();
    for _ in 0..count {
        clients.push(std::net::TcpStream::connect(server.local_addr().unwrap()).unwrap());
        accept_stream(server);
    }
    clients
}

/// Presents every connection the relay holds as coming from `ip`, so a test
/// can model a second source without a second local address.
fn relabel_sources(server: &mut Server, ip: IpAddr) {
    for conn in server.connections.values_mut() {
        conn.peer = SocketAddr::new(ip, conn.peer.port());
    }
}

fn allocation_fixture(server: &Server) -> Allocation {
    let socket = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let address = socket.local_addr().unwrap();
    let now = Instant::now();
    Allocation {
        socket,
        #[cfg(feature = "connected-udp")]
        client_socket: None,
        token: Token(usize::MAX),
        bound_address: address,
        advertised_address: address,
        username: "source-cap-fixture".into(),
        transaction: [1; 12],
        expires: now + Duration::from_secs(60),
        permissions: Vec::new(),
        channels: Vec::new(),
        bandwidth: Bucket::new(server.config.bytes_per_second, 1, now),
        requests: Bucket::new(
            ALLOCATION_REQUESTS_PER_SECOND,
            ALLOCATION_REQUEST_BURST,
            now,
        ),
    }
}

#[test]
fn one_source_is_limited_to_half_the_connection_table_without_allocations() {
    let mut server = source_cap_server(64);
    let mut clients = open_streams(&mut server, 32);
    let refused = std::net::TcpStream::connect(server.local_addr().unwrap()).unwrap();
    drive_until(&mut server, |server| {
        server.relay_metrics().refused_streams == 1
    });
    assert_eq!(server.connections.len(), 32, "the 33rd was not admitted");
    let mut refused = refused;
    refused
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    assert_eq!(refused.read(&mut [0u8; 1]).unwrap(), 0);
    // Closing one connection releases its share.
    drop(clients.pop());
    drive_until(&mut server, |server| server.connections.len() == 31);
    clients.push(std::net::TcpStream::connect(server.local_addr().unwrap()).unwrap());
    accept_stream(&mut server);
    assert_eq!(server.connections.len(), 32);
    assert_eq!(server.relay_metrics().refused_streams, 1);
}

#[test]
fn a_second_source_connects_while_the_first_is_at_its_cap() {
    let mut server = source_cap_server(64);
    let _first = open_streams(&mut server, 32);
    relabel_sources(&mut server, "192.0.2.10".parse().unwrap());
    assert!(server.source_at_unauthenticated_cap("192.0.2.10".parse().unwrap()));
    assert!(!server.source_at_unauthenticated_cap("192.0.2.11".parse().unwrap()));
    let second = open_streams(&mut server, 1);
    assert_eq!(server.connections.len(), 33);
    assert_eq!(server.relay_metrics().refused_streams, 0);
    drop(second);
}

#[test]
fn ipv6_sources_share_a_cap_by_prefix_and_mapped_addresses_count_as_ipv4() {
    let mut server = source_cap_server(4);
    let _clients = open_streams(&mut server, 2);
    let tokens: Vec<_> = server.connections.keys().copied().collect();
    for (token, ip) in tokens
        .iter()
        .zip(["2001:db8:1:2::1", "2001:db8:1:2:ffff::9"])
    {
        let conn = server.connections.get_mut(token).unwrap();
        conn.peer = SocketAddr::new(ip.parse().unwrap(), 4000);
    }
    assert!(server.source_at_unauthenticated_cap("2001:db8:1:2:1::1".parse().unwrap()));
    assert!(!server.source_at_unauthenticated_cap("2001:db8:1:3::1".parse().unwrap()));
    assert!(!server.source_at_unauthenticated_cap("192.0.2.1".parse().unwrap()));
    relabel_sources(&mut server, "192.0.2.1".parse().unwrap());
    assert!(server.source_at_unauthenticated_cap("::ffff:192.0.2.1".parse().unwrap()));
}

#[test]
fn a_connection_with_an_allocation_stops_counting_and_counts_again_without_one() {
    let mut server = source_cap_server(64);
    let _clients = open_streams(&mut server, 32);
    let source: IpAddr = "127.0.0.1".parse().unwrap();
    assert!(server.source_at_unauthenticated_cap(source));
    let token = *server.connections.keys().next().unwrap();
    server
        .allocations
        .insert(Client::Stream(token), allocation_fixture(&server));
    assert!(!server.source_at_unauthenticated_cap(source));
    server.remove_allocation(Client::Stream(token));
    assert!(server.source_at_unauthenticated_cap(source));
}

#[test]
fn the_source_cap_is_half_the_table_and_never_below_one() {
    for (max, cap) in [
        (1, 1),
        (2, 1),
        (3, 1),
        (16, 8),
        (32, 16),
        (64, 32),
        (512, 256),
    ] {
        assert_eq!(unauthenticated_cap(max), cap, "max_connections {max}");
    }
    let mut server = source_cap_server(1);
    let _only = open_streams(&mut server, 1);
    assert!(server.source_at_unauthenticated_cap("127.0.0.1".parse().unwrap()));
}
