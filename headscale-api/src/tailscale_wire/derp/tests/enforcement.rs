//! Actual encrypted DERP logins and production raw/WebSocket loops. The local
//! callbacks model current membership/policy; they do not execute a chain or
//! inspect the encrypted packet carried between the endpoint keys.
use super::*;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize};

type Key = [u8; KEY_LEN];
type Members = Arc<Mutex<HashSet<Key>>>;

#[derive(Clone, Copy, Debug)]
enum Transport {
    Raw,
    WebSocket,
}

const TRANSPORTS: [Transport; 2] = [Transport::Raw, Transport::WebSocket];
const WAIT: Duration = Duration::from_secs(10);

fn key(seed: u8) -> DerpNodeKeyPair {
    DerpNodeKeyPair::from_private_key([seed; KEY_LEN]).unwrap()
}

fn members(keys: &[Key]) -> Members {
    Arc::new(Mutex::new(keys.iter().copied().collect()))
}

fn runtime(
    members: Members,
    peers: impl Fn(&Key, &Key) -> bool + Send + Sync + 'static,
) -> Arc<NativeDerpRuntime> {
    Arc::new(
        NativeDerpRuntime::new(key(9), NativeDerpRelay::new())
            .with_client_verifier(move |public| members.lock().unwrap().contains(public))
            .with_peer_verifier(peers),
    )
}

async fn wait_sent(sent: &Arc<Mutex<Vec<Message>>>, count: usize) {
    tokio::time::timeout(WAIT, async {
        while sent.lock().unwrap().len() < count {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("DERP WebSocket frame deadline");
}

enum Client {
    Raw(RawDerpClient),
    WebSocket(WebsocketDerpClient),
}

struct Connected {
    client: Client,
    next: usize,
}

impl Connected {
    async fn open(
        transport: Transport,
        runtime: Arc<NativeDerpRuntime>,
        key: &DerpNodeKeyPair,
    ) -> Self {
        let client = match transport {
            Transport::Raw => Client::Raw(
                tokio::time::timeout(WAIT, start_raw_derp_client(runtime, key))
                    .await
                    .expect("DERP raw login deadline"),
            ),
            Transport::WebSocket => {
                let public = runtime.public_key();
                let info = encode_client_info_frame(key, &public, &ClientInfo::regular()).unwrap();
                let (tx, rx) = mpsc::channel(16);
                let sent = Arc::new(Mutex::new(Vec::new()));
                let server_sent = sent.clone();
                let server = tokio::spawn(async move {
                    drive_native_derp_websocket_parts(
                        runtime,
                        CollectWebsocketSink { sent: server_sent },
                        MpscMessageStream { rx },
                    )
                    .await
                });
                tx.send(Ok(Message::Binary(info))).await.unwrap();
                wait_sent(&sent, 2).await;
                assert!(matches!(
                    decode_websocket_sent_frame(&sent, 0, "server key"),
                    Frame::ServerKey { key, .. } if key == public
                ));
                assert_eq!(
                    open_server_info(
                        key,
                        &public,
                        &decode_websocket_sent_frame(&sent, 1, "server info")
                    )
                    .unwrap(),
                    ServerInfo::current()
                );
                Client::WebSocket(WebsocketDerpClient { tx, sent, server })
            }
        };
        Self { client, next: 2 }
    }

    async fn bytes(&mut self, bytes: Vec<u8>) {
        match &mut self.client {
            Client::Raw(client) => {
                client.writer.write_all(&bytes).await.unwrap();
                client.writer.flush().await.unwrap();
            }
            Client::WebSocket(client) => {
                client.tx.send(Ok(Message::Binary(bytes))).await.unwrap();
            }
        }
    }

    async fn send(&mut self, frame: Frame) {
        self.bytes(encode_frame(&frame).unwrap()).await;
    }

    async fn next(&mut self) -> Frame {
        match &mut self.client {
            Client::Raw(client) => tokio::time::timeout(
                WAIT,
                read_next_frame(&mut client.reader, &mut client.decoder),
            )
            .await
            .expect("DERP raw frame deadline")
            .unwrap(),
            Client::WebSocket(client) => {
                wait_sent(&client.sent, self.next + 1).await;
                let frame = decode_websocket_sent_frame(&client.sent, self.next, "relay frame");
                self.next += 1;
                frame
            }
        }
    }

    async fn barrier(&mut self) {
        self.send(Frame::Ping(*b"barrier!")).await;
        // Disconnect/duplicate notices are control traffic. Any unexpected
        // data packet must fail this positive control rather than be skipped.
        for _ in 0..8 {
            match self.next().await {
                Frame::PeerGone { .. } | Frame::Health(_) => (),
                frame => {
                    assert_eq!(frame, Frame::Pong(*b"barrier!"));
                    return;
                }
            }
        }
        panic!("too many control frames before DERP barrier");
    }

    async fn close(self) {
        let server = match self.client {
            Client::Raw(client) => {
                drop(client.reader);
                drop(client.writer);
                client.server
            }
            Client::WebSocket(client) => {
                client.tx.send(Ok(Message::Close(None))).await.unwrap();
                client.server
            }
        };
        tokio::time::timeout(WAIT, server)
            .await
            .expect("DERP close deadline")
            .unwrap()
            .unwrap();
    }

    async fn refused_without_packet(self, expected: &str) {
        self.refusal(expected, true).await;
    }

    async fn refused(self, expected: &str) {
        self.refusal(expected, false).await;
    }

    async fn refusal(self, expected: &str, no_packets: bool) {
        match self.client {
            Client::Raw(mut client) => {
                let error = tokio::time::timeout(WAIT, client.server)
                    .await
                    .expect("DERP refusal deadline")
                    .unwrap()
                    .unwrap_err();
                assert!(error.to_string().contains(expected), "{error}");
                // The server is joined and its writer closed. Drain any
                // already-buffered frames through EOF to catch leaked data.
                tokio::time::timeout(WAIT, async {
                    while let Ok(frame) =
                        read_next_frame(&mut client.reader, &mut client.decoder).await
                    {
                        if no_packets {
                            assert!(!matches!(frame, Frame::RecvPacket { .. }));
                        }
                    }
                })
                .await
                .expect("DERP refused stream did not end");
            }
            Client::WebSocket(client) => {
                let error = tokio::time::timeout(WAIT, client.server)
                    .await
                    .expect("DERP refusal deadline")
                    .unwrap()
                    .unwrap_err();
                assert!(error.to_string().contains(expected), "{error}");
                let messages = client.sent.lock().unwrap();
                for message in messages.iter() {
                    let (frame, _) = headscale_core::derp::protocol::decode_frame(
                        binary_frame(message),
                        MAX_INFO_LEN,
                    )
                    .unwrap();
                    if no_packets {
                        assert!(!matches!(frame, Frame::RecvPacket { .. }));
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn directional_policy_is_enforced_for_every_transport_pair_and_bound_to_real_keys() {
    for source_transport in TRANSPORTS {
        for destination_transport in TRANSPORTS {
            let source_key = key(7);
            let destination_key = key(8);
            let source_public = source_key.public_key();
            let destination_public = destination_key.public_key();
            let allowed = Arc::new(AtomicBool::new(true));
            let observed = Arc::new(Mutex::new(Vec::new()));
            let runtime = runtime(members(&[source_public, destination_public]), {
                let allowed = allowed.clone();
                let observed = observed.clone();
                move |source, destination| {
                    observed.lock().unwrap().push((*source, *destination));
                    allowed.load(Ordering::SeqCst)
                }
            });
            assert!(runtime.peer_verification_enabled());
            assert!(runtime.debug_snapshot().peer_verification_enabled);
            let mut source = Connected::open(source_transport, runtime.clone(), &source_key).await;
            let mut destination =
                Connected::open(destination_transport, runtime.clone(), &destination_key).await;
            source
                .send(Frame::SendPacket {
                    destination: destination_public,
                    packet: b"opaque encrypted payload".to_vec(),
                })
                .await;
            assert_eq!(
                destination.next().await,
                Frame::RecvPacket {
                    source: source_public,
                    packet: b"opaque encrypted payload".to_vec(),
                }
            );
            destination
                .send(Frame::SendPacket {
                    destination: source_public,
                    packet: b"return payload".to_vec(),
                })
                .await;
            assert_eq!(
                source.next().await,
                Frame::RecvPacket {
                    source: destination_public,
                    packet: b"return payload".to_vec(),
                }
            );
            assert_eq!(
                *observed.lock().unwrap(),
                [
                    (source_public, destination_public),
                    (source_public, destination_public),
                    (destination_public, source_public),
                    (destination_public, source_public),
                ]
            );
            allowed.store(false, Ordering::SeqCst);
            source
                .send(Frame::SendPacket {
                    destination: destination_public,
                    packet: b"must not be carried".to_vec(),
                })
                .await;
            source.refused("peer route").await;
            destination.barrier().await;
            destination.close().await;
            assert_eq!(runtime.relay.session_count().await, 0);
        }
    }
}

#[tokio::test]
async fn peer_policy_is_rechecked_after_intake_before_any_queued_packet_is_written() {
    for source_transport in TRANSPORTS {
        for destination_transport in TRANSPORTS {
            let source_key = key(7);
            let destination_key = key(8);
            let calls = Arc::new(AtomicUsize::new(0));
            let runtime = runtime(
                members(&[source_key.public_key(), destination_key.public_key()]),
                {
                    let calls = calls.clone();
                    move |_, _| calls.fetch_add(1, Ordering::SeqCst) == 0
                },
            );
            let mut source = Connected::open(source_transport, runtime.clone(), &source_key).await;
            let destination =
                Connected::open(destination_transport, runtime.clone(), &destination_key).await;
            source
                .send(Frame::SendPacket {
                    destination: destination_key.public_key(),
                    packet: b"allowed at intake only".to_vec(),
                })
                .await;
            destination.refused_without_packet("peer route").await;
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            source.barrier().await;
            source.close().await;
            assert_eq!(runtime.relay.session_count().await, 0);
        }
    }
}

#[tokio::test]
async fn allowing_one_peer_direction_does_not_authorize_the_reverse_direction() {
    for source_transport in TRANSPORTS {
        for destination_transport in TRANSPORTS {
            let source_key = key(7);
            let destination_key = key(8);
            let source_public = source_key.public_key();
            let destination_public = destination_key.public_key();
            let runtime = runtime(
                members(&[source_public, destination_public]),
                move |source, destination| {
                    *source == source_public && *destination == destination_public
                },
            );
            let mut source = Connected::open(source_transport, runtime.clone(), &source_key).await;
            let mut destination =
                Connected::open(destination_transport, runtime.clone(), &destination_key).await;
            source
                .send(Frame::SendPacket {
                    destination: destination_public,
                    packet: b"allowed direction".to_vec(),
                })
                .await;
            assert_eq!(
                destination.next().await,
                Frame::RecvPacket {
                    source: source_public,
                    packet: b"allowed direction".to_vec()
                }
            );
            // A valid destination key cannot reverse the authorized pair.
            destination
                .send(Frame::SendPacket {
                    destination: source_public,
                    packet: b"forbidden reverse".to_vec(),
                })
                .await;
            destination.refused("peer route").await;
            source.barrier().await;
            source.close().await;
            assert_eq!(runtime.relay.session_count().await, 0);
        }
    }
}

#[tokio::test]
async fn configured_verifiers_preserve_authorized_duplicate_sessions() {
    let source_key = key(7);
    let destination_key = key(8);
    let runtime = runtime(
        members(&[source_key.public_key(), destination_key.public_key()]),
        |_, _| true,
    );
    let mut source = Connected::open(Transport::Raw, runtime.clone(), &source_key).await;
    let mut duplicate = Connected::open(Transport::WebSocket, runtime.clone(), &source_key).await;
    let mut destination = Connected::open(Transport::Raw, runtime.clone(), &destination_key).await;
    let health = Frame::Health(DUPLICATE_CONNECTION_HEALTH.to_string());
    assert_eq!(source.next().await, health);
    assert_eq!(duplicate.next().await, health);
    duplicate.close().await;
    assert_eq!(source.next().await, Frame::Health(String::new()));
    source
        .send(Frame::SendPacket {
            destination: destination_key.public_key(),
            packet: b"remaining authorized duplicate".to_vec(),
        })
        .await;
    assert_eq!(
        destination.next().await,
        Frame::RecvPacket {
            source: source_key.public_key(),
            packet: b"remaining authorized duplicate".to_vec()
        }
    );
    source.close().await;
    destination.barrier().await;
    destination.close().await;
    assert_eq!(runtime.relay.session_count().await, 0);
}

#[tokio::test]
async fn removed_live_clients_cannot_send_packets_or_control_frames() {
    for transport in TRANSPORTS {
        for packet in [false, true] {
            let source_key = key(7);
            let destination_key = key(8);
            let membership = members(&[source_key.public_key(), destination_key.public_key()]);
            let runtime = runtime(membership.clone(), |_, _| true);
            let mut source = Connected::open(transport, runtime.clone(), &source_key).await;
            let mut destination =
                Connected::open(transport, runtime.clone(), &destination_key).await;
            membership.lock().unwrap().remove(&source_key.public_key());
            source
                .send(if packet {
                    Frame::SendPacket {
                        destination: destination_key.public_key(),
                        packet: b"revoked source".to_vec(),
                    }
                } else {
                    Frame::Ping(*b"revoked!")
                })
                .await;
            source
                .refused_without_packet("client was not admitted")
                .await;
            destination.barrier().await;
            destination.close().await;
            assert_eq!(runtime.relay.session_count().await, 0);
        }
    }
}

#[tokio::test]
async fn queued_packets_recheck_both_already_connected_endpoints() {
    for source_transport in TRANSPORTS {
        for destination_transport in TRANSPORTS {
            for remove_source in [false, true] {
                let source_key = key(7);
                let destination_key = key(8);
                let membership = members(&[source_key.public_key(), destination_key.public_key()]);
                let removed = if remove_source {
                    source_key.public_key()
                } else {
                    destination_key.public_key()
                };
                let calls = Arc::new(AtomicUsize::new(0));
                let runtime = runtime(membership.clone(), {
                    let membership = membership.clone();
                    let calls = calls.clone();
                    move |_, _| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        // The actual authenticated intake has checked both
                        // endpoints. Revoke before it queues the packet.
                        membership.lock().unwrap().remove(&removed);
                        true
                    }
                });
                let mut source =
                    Connected::open(source_transport, runtime.clone(), &source_key).await;
                let destination =
                    Connected::open(destination_transport, runtime.clone(), &destination_key).await;
                source
                    .send(Frame::SendPacket {
                        destination: destination_key.public_key(),
                        packet: b"revoked after intake".to_vec(),
                    })
                    .await;
                destination
                    .refused_without_packet("client was not admitted")
                    .await;
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                source.close().await;
                assert_eq!(runtime.relay.session_count().await, 0);
            }
        }
    }
}

#[tokio::test]
async fn every_coalesced_decoded_frame_rechecks_current_membership() {
    for transport in TRANSPORTS {
        let source_key = key(7);
        let source_public = source_key.public_key();
        let destination_key = key(8);
        let armed = Arc::new(AtomicBool::new(false));
        let checks = Arc::new(AtomicUsize::new(0));
        let runtime = Arc::new(
            NativeDerpRuntime::new(key(9), NativeDerpRelay::new())
                .with_client_verifier({
                    let armed = armed.clone();
                    let checks = checks.clone();
                    move |client| {
                        *client != source_public
                            || !armed.load(Ordering::SeqCst)
                            || checks.fetch_add(1, Ordering::SeqCst) == 0
                    }
                })
                .with_peer_verifier(|_, _| true),
        );
        let mut source = Connected::open(transport, runtime.clone(), &source_key).await;
        let mut destination = Connected::open(transport, runtime.clone(), &destination_key).await;
        source.barrier().await;
        armed.store(true, Ordering::SeqCst);
        let mut bytes = encode_frame(&Frame::Ping(*b"first!!!")).unwrap();
        bytes.extend_from_slice(
            &encode_frame(&Frame::SendPacket {
                destination: destination_key.public_key(),
                packet: b"second frame is revoked".to_vec(),
            })
            .unwrap(),
        );
        source.bytes(bytes).await;
        source
            .refused_without_packet("client was not admitted")
            .await;
        assert_eq!(checks.load(Ordering::SeqCst), 2);
        destination.barrier().await;
        destination.close().await;
        assert_eq!(runtime.relay.session_count().await, 0);
    }
}

#[tokio::test]
async fn authenticated_client_cannot_spoof_mesh_source_watch_or_close_another_peer() {
    for transport in TRANSPORTS {
        for operation in 0..3 {
            let attacker_key = key(6);
            let victim_key = key(7);
            let destination_key = key(8);
            let runtime = runtime(
                members(&[
                    attacker_key.public_key(),
                    victim_key.public_key(),
                    destination_key.public_key(),
                ]),
                |_, _| true,
            );
            let mut attacker = Connected::open(transport, runtime.clone(), &attacker_key).await;
            let mut victim = Connected::open(transport, runtime.clone(), &victim_key).await;
            let mut destination =
                Connected::open(transport, runtime.clone(), &destination_key).await;
            attacker
                .send(match operation {
                    0 => Frame::ForwardPacket {
                        source: victim_key.public_key(),
                        destination: destination_key.public_key(),
                        packet: b"forged victim source".to_vec(),
                    },
                    1 => Frame::ClosePeer {
                        peer: victim_key.public_key(),
                    },
                    _ => Frame::WatchConns,
                })
                .await;
            attacker.refused_without_packet("mesh control").await;
            victim.barrier().await;
            destination.barrier().await;
            victim.close().await;
            destination.close().await;
            assert_eq!(runtime.relay.session_count().await, 0);
        }
    }
}

#[test]
fn server_only_frames_are_rejected_and_unknown_extensions_remain_inert() {
    let runtime = NativeDerpRuntime::new(key(9), NativeDerpRelay::new());
    let client = key(7).public_key();
    let frames = [
        Frame::ServerKey {
            key: client,
            extra: vec![],
        },
        Frame::ClientInfo {
            public_key: client,
            encrypted_info: vec![],
        },
        Frame::ServerInfo {
            encrypted_info: vec![],
        },
        Frame::RecvPacket {
            source: client,
            packet: vec![],
        },
        Frame::PeerGone {
            peer: client,
            reason: PeerGoneReason::Disconnected,
        },
        Frame::PeerPresent {
            peer: client,
            endpoint: None,
            flags: None,
            extra: vec![],
        },
        Frame::Health(String::new()),
        Frame::Restarting {
            reconnect_in_ms: 1,
            try_for_ms: 1,
        },
    ];
    for frame in frames {
        assert!(
            runtime.incoming_frame(&client, &frame).is_err(),
            "{frame:?}"
        );
    }
    assert!(
        runtime
            .incoming_frame(
                &client,
                &Frame::Unknown {
                    frame_type: 255,
                    payload: vec![1]
                }
            )
            .is_ok()
    );
    assert!(runtime.admit_peer(&client, &key(8).public_key()));
    assert!(!runtime.peer_verification_enabled());
}
