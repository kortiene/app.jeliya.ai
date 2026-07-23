//! Conformance corpus for the control wire. Every frame and message type has a
//! round-trip test; the load-bearing ones also have a committed golden-hex
//! fixture (so a re-encode that changes the bytes fails here, not silently on
//! the wire); and the strict-parse guarantees have explicit negative fixtures.
//! The browser controller re-implements this wire and is expected to reproduce
//! the same golden bytes.

use super::*;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ---- Golden fixtures ---------------------------------------------------

#[test]
fn client_hello_golden() {
    let hello = ClientHello {
        versions: vec![1],
        session_kind: SessionKind::Pairing,
        pairing_nonce: [0x11; 16],
    };
    // "JCTL" | count=1 | version=1 | kind=1(pairing) | nonce(16×0x11)
    let expected = "4a43544c0100010111111111111111111111111111111111";
    assert_eq!(hex(&hello.encode_body().unwrap()), expected);
    assert_eq!(ClientHello::decode_body(&unhex(expected)).unwrap(), hello);
}

#[test]
fn server_hello_golden() {
    let hello = ServerHello {
        version: 1,
        min_version: 1,
    };
    let expected = "4a43544c00010001";
    assert_eq!(hex(&hello.encode_body()), expected);
    assert_eq!(ServerHello::decode_body(&unhex(expected)).unwrap(), hello);
}

#[test]
fn request_golden() {
    let params = MethodCall::MessageSend {
        room_id: "r1".into(),
        body: "hi".into(),
        client_msg_id: "c1".into(),
    }
    .encode()
    .unwrap();
    // params: string "r1" | string "hi" | string "c1"
    assert_eq!(hex(&params), "000272310002686900026331");
    let req = Msg::Request {
        nonce: 1,
        method: method::MESSAGE_SEND,
        params,
    };
    // type 0x10 | nonce=1 (u64) | method=0x0003 | blob(len=0x000c | params)
    let expected = "1000000000000000010003000c000272310002686900026331";
    assert_eq!(hex(&req.encode().unwrap()), expected);
    assert_eq!(Msg::decode(&unhex(expected)).unwrap(), req);
}

#[test]
fn frame_wraps_length_and_type() {
    let body = vec![0xAA, 0xBB, 0xCC];
    let frame = Frame::new(FrameType::Transport, body.clone());
    // length=3 (u32) | type=0x10 | body
    assert_eq!(hex(&frame.encode().unwrap()), "0000000310aabbcc");
    let (decoded, consumed) = Frame::decode_prefix(&frame.encode().unwrap()).unwrap();
    assert_eq!(decoded, frame);
    assert_eq!(consumed, 8);
}

// ---- Round-trips -------------------------------------------------------

#[test]
fn every_message_round_trips() {
    let cases = vec![
        Msg::SessionAccept {
            methods: method::ALL.to_vec(),
            expires_at_ms: 1_700_000_000_000,
        },
        Msg::SessionReject {
            reason: reject::REVOKED,
        },
        Msg::PairConfirm,
        Msg::PairResult {
            installed: true,
            scopes: scope::ALL.to_vec(),
            rooms: vec!["room-a".into(), "room-b".into()],
            expires_at_ms: 42,
        },
        Msg::PairResult {
            installed: false,
            scopes: vec![],
            rooms: vec![],
            expires_at_ms: 0,
        },
        Msg::Request {
            nonce: u64::MAX,
            method: method::ROOM_TIMELINE,
            params: vec![1, 2, 3],
        },
        Msg::Response {
            nonce: 7,
            ok: true,
            body: b"{\"ok\":1}".to_vec(),
        },
    ];
    for case in cases {
        let bytes = case.encode().unwrap();
        assert_eq!(Msg::decode(&bytes).unwrap(), case, "round-trip {case:?}");
    }
}

#[test]
fn method_calls_round_trip() {
    let cases = vec![
        MethodCall::RoomTimeline {
            room_id: "r".into(),
            limit: None,
            after: None,
        },
        MethodCall::RoomTimeline {
            room_id: "r".into(),
            limit: Some(50),
            after: Some("evt-9".into()),
        },
        MethodCall::RoomMembers {
            room_id: "r".into(),
        },
        MethodCall::MessageSend {
            room_id: "r".into(),
            body: "hello".into(),
            client_msg_id: "cmid".into(),
        },
    ];
    for case in cases {
        let id = match &case {
            MethodCall::RoomTimeline { .. } => method::ROOM_TIMELINE,
            MethodCall::RoomMembers { .. } => method::ROOM_MEMBERS,
            MethodCall::MessageSend { .. } => method::MESSAGE_SEND,
        };
        let bytes = case.encode().unwrap();
        assert_eq!(MethodCall::decode(id, &bytes).unwrap(), case);
    }
}

#[test]
fn error_response_round_trips() {
    let msg = Msg::error_response(9, error::DENIED_SCOPE, "scope not granted").unwrap();
    let bytes = msg.encode().unwrap();
    let decoded = Msg::decode(&bytes).unwrap();
    match decoded {
        Msg::Response { nonce, ok, body } => {
            assert_eq!(nonce, 9);
            assert!(!ok);
            let (code, message) = Msg::decode_error_body(&body).unwrap();
            assert_eq!(code, error::DENIED_SCOPE);
            assert_eq!(message, "scope not granted");
        }
        other => panic!("expected Response, got {other:?}"),
    }
}

// ---- Negative fixtures (strict parse fails closed) ---------------------

#[test]
fn oversized_frame_length_is_rejected_before_alloc() {
    let mut buf = Writer::new();
    buf.put_u32((MAX_FRAME_LEN + 1) as u32);
    buf.put_u8(FrameType::Transport.tag());
    assert_eq!(
        Frame::decode_prefix(&buf.into_vec()),
        Err(ProtoError::FrameTooLarge)
    );
}

#[test]
fn unknown_frame_type_is_rejected() {
    let bytes = unhex("0000000199"); // len=1, type=0x99, (body missing but type checked first)
    assert_eq!(
        Frame::decode_prefix(&bytes),
        Err(ProtoError::BadEnum("frame_type"))
    );
}

#[test]
fn bad_magic_is_rejected() {
    let bytes = unhex("deadbeef00010001");
    assert_eq!(ServerHello::decode_body(&bytes), Err(ProtoError::BadMagic));
}

#[test]
fn zero_version_count_is_rejected() {
    // "JCTL" | count=0 ...
    let bytes = unhex("4a43544c00");
    assert_eq!(
        ClientHello::decode_body(&bytes),
        Err(ProtoError::BadCount("versions"))
    );
}

#[test]
fn too_many_versions_is_rejected_on_encode() {
    let hello = ClientHello {
        versions: vec![1; MAX_VERSIONS + 1],
        session_kind: SessionKind::Control,
        pairing_nonce: ZERO_NONCE,
    };
    assert_eq!(hello.encode_body(), Err(ProtoError::BadCount("versions")));
}

#[test]
fn control_session_with_nonzero_nonce_is_rejected() {
    let hello = ClientHello {
        versions: vec![1],
        session_kind: SessionKind::Control,
        pairing_nonce: [1; 16],
    };
    assert_eq!(
        hello.encode_body(),
        Err(ProtoError::BadEnum("pairing_nonce"))
    );
    // and on decode: "JCTL"|count1|ver1|kind2|nonce(1×16)
    let bytes = unhex("4a43544c0100010201010101010101010101010101010101");
    assert_eq!(
        ClientHello::decode_body(&bytes),
        Err(ProtoError::BadEnum("pairing_nonce"))
    );
}

#[test]
fn non_utf8_string_is_rejected() {
    // Msg::Response with a blob is fine (bytes), but a Request room string must
    // be UTF-8. Build message.send params with an invalid UTF-8 room id.
    let mut w = Writer::new();
    w.put_u16(1); // string length 1
    w.put_u8(0xFF); // not valid UTF-8
    assert_eq!(
        MethodCall::decode(method::MESSAGE_SEND, &w.into_vec()),
        Err(ProtoError::BadUtf8)
    );
}

#[test]
fn trailing_bytes_are_rejected() {
    let mut bytes = Msg::PairConfirm.encode().unwrap();
    bytes.push(0x00);
    assert_eq!(Msg::decode(&bytes), Err(ProtoError::TrailingBytes));
}

#[test]
fn unknown_msg_type_is_rejected() {
    assert_eq!(Msg::decode(&[0x7F]), Err(ProtoError::BadEnum("msg_type")));
}

#[test]
fn timeline_limit_is_clamped_but_none_is_left_for_the_daemon_default() {
    let clamped = MethodCall::RoomTimeline {
        room_id: "r".into(),
        limit: Some(u32::MAX),
        after: None,
    }
    .clamped();
    match clamped {
        MethodCall::RoomTimeline { limit, .. } => assert_eq!(limit, Some(MAX_TIMELINE_LIMIT)),
        other => panic!("expected RoomTimeline, got {other:?}"),
    }
    // A None limit stays None (the daemon applies its own small default).
    let untouched = MethodCall::RoomTimeline {
        room_id: "r".into(),
        limit: None,
        after: None,
    }
    .clamped();
    match untouched {
        MethodCall::RoomTimeline { limit, .. } => assert_eq!(limit, None),
        other => panic!("expected RoomTimeline, got {other:?}"),
    }
}

#[test]
fn unknown_method_scope_lookup_fails_closed() {
    assert_eq!(scope_for_method(0xFFFF), Err(ProtoError::BadEnum("method")));
    assert_eq!(
        scope_for_method(method::ROOM_TIMELINE).unwrap(),
        scope::ROOM_READ
    );
    assert_eq!(
        scope_for_method(method::MESSAGE_SEND).unwrap(),
        scope::MESSAGE_SEND
    );
}

#[test]
fn short_input_is_rejected() {
    assert_eq!(
        ServerHello::decode_body(&unhex("4a43544c00")),
        Err(ProtoError::ShortInput)
    );
}

#[test]
fn separately_approved_methods_have_no_v1_id() {
    // Nothing outside the three-method registry decodes as a method call.
    for id in [0x0004u16, 0x0010, 0x00FF, 0x1000] {
        assert!(MethodCall::decode(id, &[]).is_err());
        assert!(scope_for_method(id).is_err());
    }
    assert_eq!(method::ALL.len(), 3);
}
