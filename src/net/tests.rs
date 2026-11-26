//! `net::mod` 的单元测试：协议边界、配置与鉴权事件的端到端接线。

use super::*;
use serde_json::Value;
use std::io::BufRead;

#[test]
fn ct_eq_is_length_safe_and_exact() {
    assert!(ct_eq(b"abcdef", b"abcdef"));
    assert!(!ct_eq(b"abcdef", b"abcdeF"));
    assert!(!ct_eq(b"abcdef", b"abcde"));
    assert!(!ct_eq(b"", b"a"));
}

#[test]
fn base_urls_are_narrowed_to_http_host_port() {
    assert_eq!(
        normalize_base("http://127.0.0.1:7878/").unwrap(),
        "http://127.0.0.1:7878"
    );
    assert!(matches!(
        normalize_base("https://127.0.0.1:7878"),
        Err(NetError::NotHttp(_))
    ));
    assert!(matches!(
        normalize_base("http://127.0.0.1"),
        Err(NetError::MissingPort(_))
    ));
    assert!(matches!(
        normalize_base("http://127.0.0.1:7878/x"),
        Err(NetError::NotHttp(_))
    ));
}

#[test]
fn query_and_percent_decoding_roundtrip() {
    let (path, query) = request::split_target("/v1/pull?ref=main&prefix=a%2Fb");
    assert_eq!(path, "/v1/pull");
    assert_eq!(query.get("ref").map(String::as_str), Some("main"));
    assert_eq!(query.get("prefix").map(String::as_str), Some("a/b"));
    assert_eq!(request::percent_decode("a+b%2Fc"), "a b/c");
    assert_eq!(percent_encode("a/b c"), "a/b%20c");
}

#[test]
fn config_requires_a_real_token() {
    let short = Config::new(".", "127.0.0.1:0", "x").validated();
    assert!(matches!(short, Err(NetError::BadToken(_))));
    let ok = Config::new(".", "127.0.0.1:0", "0123456789abcdef").validated();
    assert!(ok.is_ok());
}

#[test]
fn config_rejects_duplicate_token_bindings() {
    let token = "0123456789abcdef".to_string();
    let mut config = Config::new(".", "127.0.0.1:0", token.clone());
    config.tokens = vec![
        TokenBinding {
            token: token.clone(),
            actor: Some("alice".to_string()),
        },
        TokenBinding {
            token,
            actor: Some("bob".to_string()),
        },
    ];
    assert!(matches!(config.validated(), Err(NetError::BadToken(_))));

    let mut config = Config::new(".", "127.0.0.1:0", "0123456789abcdef");
    config.tokens = vec![TokenBinding {
        token: "fedcba9876543210".to_string(),
        actor: Some("bob".to_string()),
    }];
    assert!(config.validated().is_ok());
}

#[test]
fn per_token_bindings_pick_their_own_actor() {
    let root = std::env::temp_dir().join(format!(
        "trit-vcs-net-actors-{}-{}",
        std::process::id(),
        auth::request_id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let mut config = Config::new(root.join("central"), "127.0.0.1:0", "0123456789abcdef");
    config.actor = Some("qoder:fallback".to_string());
    config.tokens = vec![
        TokenBinding {
            token: "0123456789abcdef".to_string(),
            actor: Some("alice".to_string()),
        },
        TokenBinding {
            token: "fedcba9876543210".to_string(),
            actor: Some("bob".to_string()),
        },
        TokenBinding {
            token: "0011223344556677".to_string(),
            actor: None,
        },
    ];
    let server = Server::start(config).unwrap();
    for token in ["0123456789abcdef", "fedcba9876543210", "0011223344556677"] {
        let response = raw_get_path_with_token(server.addr(), token, "/v1/health");
        assert!(response.starts_with("HTTP/1.1 200"), "{token}: {response}");
    }
    let denied = raw_get_path_with_token(server.addr(), "ffffffffffffffff", "/v1/health");
    assert!(denied.starts_with("HTTP/1.1 401"), "{denied}");
    let central = crate::repo::Repo::open(root.join("central")).unwrap();
    let actors: Vec<&str> = central
        .journal()
        .events()
        .iter()
        .filter(|event| {
            event.kind == "auth"
                && event.payload.get("decision").and_then(Value::as_str) == Some("allowed")
        })
        .filter_map(|event| event.payload.get("actor").and_then(Value::as_str))
        .collect();
    assert!(actors.contains(&"alice"), "{actors:?}");
    assert!(actors.contains(&"bob"), "{actors:?}");
    assert!(actors.contains(&"qoder:fallback"), "{actors:?}");
    server.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn config_rejects_empty_oversized_or_control_actor() {
    for actor in [String::new(), "x".repeat(129), "qoder:\nci".to_string()] {
        let mut config = Config::new(".", "127.0.0.1:0", "0123456789abcdef");
        config.actor = Some(actor);
        assert!(matches!(config.validated(), Err(NetError::BadActor(_))));
    }
    let mut config = Config::new(".", "127.0.0.1:0", "0123456789abcdef");
    config.actor = Some("qoder:ci".to_string());
    assert!(config.validated().is_ok());
}

#[test]
fn client_rejects_malformed_op_id_before_connecting() {
    let root = std::env::temp_dir().join(format!(
        "trit-vcs-net-bad-op-{}-{}",
        std::process::id(),
        auth::request_id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let repo = crate::repo::Repo::init(&root).unwrap();
    let client = Client::new("http://127.0.0.1:1", "0123456789abcdef").unwrap();
    let id = crate::hash::Hash::of(b"op").to_hex();
    for bad in [format!("\r\n{id}\r\n"), "broken".to_string()] {
        assert!(matches!(
            client.publish(
                "main",
                &crate::hash::Hash::of(b"tip"),
                &crate::wire::Body::default(),
                repo.store(),
                &bad,
            ),
            Err(NetError::BadOpId)
        ));
        assert!(matches!(
            client.pull("main", None, repo.store(), Limits::default(), &bad),
            Err(NetError::BadOpId)
        ));
    }
    let _ = std::fs::remove_dir_all(&root);
}

fn response_request_id(response: &str) -> String {
    response
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("x-trit-request-id")
                .then(|| value.trim().to_string())
        })
        .expect("响应必须带 X-Trit-Request-Id")
}

fn raw_get(addr: SocketAddr, token: &str) -> String {
    raw_get_path(addr, token, "/v1/health")
}

fn raw_get_path(addr: SocketAddr, token: &str, target: &str) -> String {
    raw_get_path_with_token(addr, token, target)
}

fn raw_get_path_with_token(addr: SocketAddr, token: &str, target: &str) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    let head = format!(
        "GET {target} HTTP/1.1\r\nhost: {addr}\r\nauthorization: Bearer {token}\r\n\
         x-trit-actor: attacker\r\nconnection: close\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut response = String::new();
    std::io::Read::read_to_string(&mut stream, &mut response).unwrap();
    response
}

#[test]
fn allowed_auth_binds_server_actor_and_response_request_id() {
    let root = std::env::temp_dir().join(format!(
        "trit-vcs-net-auth-ok-{}-{}",
        std::process::id(),
        auth::request_id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let mut config = Config::new(root.join("central"), "127.0.0.1:0", "0123456789abcdef");
    config.actor = Some("qoder:ci".to_string());
    let server = Server::start(config).unwrap();
    let first = raw_get(server.addr(), "0123456789abcdef");
    let second = raw_get(server.addr(), "0123456789abcdef");
    let first_id = response_request_id(&first);
    let second_id = response_request_id(&second);
    assert_ne!(first_id, second_id, "每个请求必须有独立 request id");

    let central = crate::repo::Repo::open(root.join("central")).unwrap();
    let allowed: Vec<_> = central
        .journal()
        .events()
        .iter()
        .filter(|event| event.kind == "auth" && event.payload["decision"] == "allowed")
        .collect();
    assert_eq!(allowed.len(), 2);
    assert_eq!(allowed[0].payload["actor"], "qoder:ci");
    assert_eq!(allowed[0].payload["source"], "127.0.0.1");
    assert_eq!(allowed[0].payload["request_id"], first_id);
    assert_eq!(allowed[1].payload["request_id"], second_id);
    assert_eq!(
        allowed[0].payload["state_before"], allowed[0].payload["state_after"],
        "鉴权放行本身不改仓库状态"
    );
    server.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn denied_auth_returns_the_same_request_id_without_trusting_client_actor() {
    let root = std::env::temp_dir().join(format!(
        "trit-vcs-net-auth-denied-{}-{}",
        std::process::id(),
        auth::request_id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let mut config = Config::new(root.join("central"), "127.0.0.1:0", "0123456789abcdef");
    config.actor = Some("qoder:ci".to_string());
    let server = Server::start(config).unwrap();
    let response = raw_get(server.addr(), "wrong-token-0000");
    assert!(response.starts_with("HTTP/1.1 401"), "{response}");
    let request_id = response_request_id(&response);

    let central = crate::repo::Repo::open(root.join("central")).unwrap();
    let denied = central
        .journal()
        .events()
        .iter()
        .find(|event| event.kind == "auth" && event.payload["decision"] == "denied")
        .expect("鉴权拒绝必须落账");
    assert_eq!(denied.payload["request_id"], request_id);
    assert!(denied.payload["actor"].is_null());
    assert_eq!(denied.payload["source"], "127.0.0.1");
    assert_eq!(denied.payload["status"], 401);
    server.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

fn raw_op_request(addr: SocketAddr, method: &str, target: &str, op_id: &str) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    let length = if method == "POST" {
        "content-length: 1\r\n"
    } else {
        ""
    };
    let op_header = if method == "POST" {
        format!("x-trit-op-id: {op_id}\r\n")
    } else {
        String::new()
    };
    let target = if method == "POST" {
        target.to_string()
    } else {
        format!("{target}&op_id={}", percent_encode(op_id))
    };
    let head = format!(
        "{method} {target} HTTP/1.1\r\nhost: {addr}\r\nauthorization: Bearer 0123456789abcdef\r\n{op_header}{length}connection: close\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).unwrap();
    if method == "POST" {
        stream.write_all(b"x").unwrap();
    }
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut response = String::new();
    std::io::Read::read_to_string(&mut stream, &mut response).unwrap();
    response
}

#[test]
fn malformed_op_id_is_rejected_and_audited_on_both_sync_routes() {
    let root = std::env::temp_dir().join(format!("trit-vcs-bad-op-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let server = Server::start(Config::new(
        root.join("central"),
        "127.0.0.1:0",
        "0123456789abcdef",
    ))
    .unwrap();
    let publish = raw_op_request(server.addr(), "POST", "/v1/publish?ref=main", "broken");
    let pull = raw_op_request(server.addr(), "GET", "/v1/pull?ref=main", "broken");
    let wrapped = format!("\r\n{}\r\n", crate::hash::Hash::of(b"op").to_hex());
    let injected = raw_op_request(server.addr(), "GET", "/v1/pull?ref=main", &wrapped);
    assert!(publish.starts_with("HTTP/1.1 400"), "{publish}");
    assert!(pull.starts_with("HTTP/1.1 400"), "{pull}");
    assert!(injected.starts_with("HTTP/1.1 400"), "{injected}");
    assert!(publish.contains("op_id"));
    assert!(pull.contains("op_id"));
    assert!(injected.contains("op_id"));

    let central = crate::repo::Repo::open(root.join("central")).unwrap();
    let denies: Vec<_> = central
        .journal()
        .events()
        .iter()
        .filter(|event| event.kind == "deny" && event.payload["reason"] == "bad_op_id")
        .collect();
    assert_eq!(denies.len(), 3);
    assert_eq!(denies[0].payload["action"], "publish");
    assert_eq!(denies[1].payload["action"], "pull");
    assert_eq!(denies[2].payload["action"], "pull");
    assert!(
        denies
            .iter()
            .all(|deny| deny.payload["detail"]["source"] == "127.0.0.1"),
        "{denies:?}"
    );
    server.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

fn fake_response(extra: &str, body: &str) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n{extra}connection: close\r\n\r\n{body}",
        body.len()
    );
    let join = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut length = 0u64;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':')
                && name.eq_ignore_ascii_case("content-length")
            {
                length = value.trim().parse().unwrap();
            }
        }
        std::io::copy(&mut reader.by_ref().take(length), &mut std::io::sink()).unwrap();
        stream.write_all(response.as_bytes()).unwrap();
        stream.flush().unwrap();
        // 先半关写端让客户端读到 EOF；再读到客户端关闭，避免 Windows 上服务端先全关发 RST。
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        let _ = std::io::copy(&mut reader, &mut std::io::sink());
    });
    (format!("http://{addr}"), join)
}

#[test]
fn clients_reject_missing_or_mismatched_correlation_headers() {
    let root = std::env::temp_dir().join(format!(
        "trit-vcs-client-correlation-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let repo = crate::repo::Repo::init(&root).unwrap();
    let op_id = crate::hash::Hash::of(b"op").to_hex();
    let request_id = crate::hash::Hash::of(b"request").to_hex();
    let other = crate::hash::Hash::of(b"other").to_hex();

    for extra in [
        format!("x-trit-request-id: {request_id}\r\n"),
        format!("x-trit-request-id: broken\r\nx-trit-op-id: {op_id}\r\n"),
        format!("x-trit-request-id: {request_id}\r\nx-trit-op-id: {other}\r\n"),
    ] {
        let (remote, join) = fake_response(&extra, "{}");
        let client = Client::new(&remote, "0123456789abcdef").unwrap();
        let publish = client.publish(
            "main",
            &crate::hash::Hash::of(b"tip"),
            &wire::Body::default(),
            repo.store(),
            &op_id,
        );
        join.join().unwrap();
        assert!(
            matches!(publish, Err(NetError::BadResponse)),
            "publish={publish:?}"
        );
    }
    for extra in [
        format!("x-trit-op-id: {op_id}\r\n"),
        format!("x-trit-request-id: {request_id}\r\n"),
        format!("x-trit-request-id: {request_id}\r\nx-trit-op-id: {other}\r\n"),
    ] {
        let (remote, join) = fake_response(&extra, "");
        let client = Client::new(&remote, "0123456789abcdef").unwrap();
        assert!(matches!(
            client.pull("main", None, repo.store(), Limits::default(), &op_id),
            Err(NetError::BadResponse)
        ));
        join.join().unwrap();
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn view_endpoint_is_json_and_bad_ref_is_denied() {
    let root = std::env::temp_dir().join(format!(
        "trit-vcs-net-view-{}-{}",
        std::process::id(),
        auth::request_id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let mut config = Config::new(root.join("central"), "127.0.0.1:0", "0123456789abcdef");
    config.actor = Some("qoder:ci".to_string());
    let server = Server::start(config).unwrap();
    let good = raw_get_path(server.addr(), "0123456789abcdef", "/v1/view?ref=main");
    assert!(good.starts_with("HTTP/1.1 200"), "{good}");
    assert!(good.contains("trit-view-v1"), "{good}");
    assert_eq!(response_request_id(&good).len(), 64);

    let bad = raw_get_path(server.addr(), "0123456789abcdef", "/v1/view?ref=bad%2Fname");
    assert!(bad.starts_with("HTTP/1.1 400"), "{bad}");
    let central = crate::repo::Repo::open(root.join("central")).unwrap();
    let deny = central
        .journal()
        .events()
        .iter()
        .find(|event| {
            event.kind == "deny"
                && event.payload["action"] == "view"
                && event.payload["reason"] == "bad_ref"
        })
        .expect("坏 ref 的 view 必须落 deny");
    assert_eq!(deny.payload["detail"]["status"], 400);
    assert_eq!(deny.payload["state_before"], deny.payload["state_after"]);
    server.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}
