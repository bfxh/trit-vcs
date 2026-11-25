//! `net::mod` 的单元测试：协议边界、配置与鉴权事件的端到端接线。

use super::*;

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
    let mut stream = TcpStream::connect(addr).unwrap();
    let head = format!(
        "GET /v1/health HTTP/1.1\r\nhost: {addr}\r\nauthorization: Bearer {token}\r\n\
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
    assert_eq!(denied.payload["status"], 401);
    server.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}
