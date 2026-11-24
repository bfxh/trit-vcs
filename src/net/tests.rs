//! `net::mod` 的单元测试：只测协议边界与配置，不另起 HTTP 服务。

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
    let (path, query) = split_target("/v1/pull?ref=main&prefix=a%2Fb");
    assert_eq!(path, "/v1/pull");
    assert_eq!(query.get("ref").map(String::as_str), Some("main"));
    assert_eq!(query.get("prefix").map(String::as_str), Some("a/b"));
    assert_eq!(percent_encode("a/b c"), "a/b%20c");
}

#[test]
fn config_requires_a_real_token() {
    let short = Config::new(".", "127.0.0.1:0", "x").validated();
    assert!(matches!(short, Err(NetError::BadToken(_))));
    let ok = Config::new(".", "127.0.0.1:0", "0123456789abcdef").validated();
    assert!(ok.is_ok());
}
