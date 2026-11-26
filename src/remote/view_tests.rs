//! 跨机视图 pin 的集成测试：首次信任、前进、回滚与同高换根。

use std::collections::BTreeMap;

use super::tests::{TOKEN, assert_audit_clean, commit_all, start_on, temp};
use super::*;
use crate::net::{Config, Server};
use crate::signing::KeyFile;

fn start(root: &std::path::Path) -> crate::net::Server {
    start_on(root, "127.0.0.1:0")
}

fn start_signed(root: &std::path::Path, key: &std::path::Path, addr: &str) -> crate::net::Server {
    let mut config = Config::new(root.join("central"), addr, TOKEN);
    config.actor = Some("qoder:ci".to_string());
    config.read_timeout = std::time::Duration::from_secs(20);
    config.max_body = 64 * 1024 * 1024;
    config.view_key_path = Some(key.to_path_buf());
    Server::start(config).unwrap()
}

#[test]
fn publish_pins_view_and_later_sync_advances_it() {
    let root = temp("pin-advance");
    let mut src = Repo::init(root.join("src")).unwrap();
    let files = BTreeMap::from([("a.txt".to_string(), b"a\n".to_vec())]);
    commit_all(&mut src, &files, 1_000);
    let server = start(&root);
    let remote = format!("http://{}", server.addr());
    let first = publish_to(&remote, TOKEN, &mut src, "main", None).unwrap();
    assert_eq!(first.pin_status, Some(PinStatus::First));
    let first_view = first.view.expect("首次发布必须记视图");
    assert!(first_view.height > 0);
    let pin = view::latest_pin(&src, &remote, "main")
        .unwrap()
        .expect("首次发布后应有 pin");
    assert_eq!(pin.height, first_view.height);
    assert_eq!(pin.root, first_view.root);

    let files = BTreeMap::from([
        ("a.txt".to_string(), b"a2\n".to_vec()),
        ("b.txt".to_string(), b"b\n".to_vec()),
    ]);
    commit_all(&mut src, &files, 2_000);
    let second = publish_to(&remote, TOKEN, &mut src, "main", None).unwrap();
    assert_eq!(second.pin_status, Some(PinStatus::Advanced));
    let second_view = second.view.expect("第二次发布必须记视图");
    assert!(second_view.height > first_view.height);
    let pin = view::latest_pin(&src, &remote, "main").unwrap().unwrap();
    assert_eq!(pin.height, second_view.height);
    assert_audit_clean(&src);
    server.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn server_rollback_is_detected_before_pull_materializes() {
    let root = temp("pin-rollback");
    let mut src = Repo::init(root.join("src")).unwrap();
    let files = BTreeMap::from([("a.txt".to_string(), b"a\n".to_vec())]);
    commit_all(&mut src, &files, 1_000);
    let server = start(&root);
    let remote = format!("http://{}", server.addr());
    let port = server.addr().port();
    let published = publish_to(&remote, TOKEN, &mut src, "main", None).unwrap();
    let pinned = published.view.expect("首次发布必须记视图");
    server.shutdown();

    // 中央仓被换成更短的历史：只留第一条 init 事件。
    let journal = root.join("central").join(".tritvcs").join("journal.jsonl");
    let text = std::fs::read_to_string(&journal).unwrap();
    let first_line = text.lines().next().unwrap().to_string();
    std::fs::write(&journal, format!("{first_line}\n")).unwrap();

    let server = start_on(&root, &format!("127.0.0.1:{port}"));
    let remote = format!("http://{}", server.addr());
    let err = pull_from(&remote, TOKEN, &mut src, "main", None, true).unwrap_err();
    assert!(
        matches!(err, RemoteError::View(ViewError::Rollback { .. })),
        "{err}"
    );
    // 预检失败在下载/物化前就挡住：HEAD 与 journal 都没动。
    assert_eq!(src.head().unwrap(), published.commit);
    assert!(!src.journal().events().iter().any(|event| {
        event.kind == "pull"
            && event.payload.get("side").and_then(|side| side.as_str()) == Some("client")
    }));
    let denies = src
        .journal()
        .events()
        .iter()
        .filter(|event| event.kind == "deny" && event.payload["reason"] == "remote_rollback")
        .count();
    assert_eq!(denies, 1, "回滚拒绝必须落账");
    assert!(pinned.height > 1);
    server.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn server_equivocation_at_same_height_is_detected() {
    let root = temp("pin-equivocation");
    let mut src = Repo::init(root.join("src")).unwrap();
    let files = BTreeMap::from([("a.txt".to_string(), b"a\n".to_vec())]);
    commit_all(&mut src, &files, 1_000);
    let server = start(&root);
    let remote = format!("http://{}", server.addr());
    let port = server.addr().port();
    let published = publish_to(&remote, TOKEN, &mut src, "main", None).unwrap();
    let pinned = published.view.expect("首次发布必须记视图");
    server.shutdown();

    // 另一条历史：高度相同、内容不同 ⇒ 根不同。ref main 不存在也不影响先判视图。
    let fresh = root.join("central-fresh");
    let _ = std::fs::remove_dir_all(&fresh);
    let mut fake = Repo::init(&fresh).unwrap();
    let init_height = fake.journal().events().len();
    for i in init_height..pinned.height {
        fake.record_deny(
            "fake",
            "equivocation",
            "测试用",
            serde_json::json!({"i": i}),
        );
    }
    assert_eq!(fake.journal().events().len(), pinned.height);
    let central = root.join("central");
    std::fs::remove_dir_all(&central).unwrap();
    std::fs::rename(&fresh, &central).unwrap();

    let server = start_on(&root, &format!("127.0.0.1:{port}"));
    let remote = format!("http://{}", server.addr());
    let err = publish_to(&remote, TOKEN, &mut src, "main", None).unwrap_err();
    assert!(
        matches!(err, RemoteError::View(ViewError::Equivocation(_))),
        "{err}"
    );
    let denies = src
        .journal()
        .events()
        .iter()
        .filter(|event| event.kind == "deny" && event.payload["reason"] == "remote_equivocation")
        .count();
    assert_eq!(denies, 1, "同高换根拒绝必须落账");
    server.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn no_pin_mode_records_remote_without_view() {
    let root = temp("pin-off");
    let mut src = Repo::init(root.join("src")).unwrap();
    let files = BTreeMap::from([("a.txt".to_string(), b"a\n".to_vec())]);
    commit_all(&mut src, &files, 1_000);
    let server = start(&root);
    let remote = format!("http://{}", server.addr());
    let stats = publish_to_with(&remote, TOKEN, &mut src, "main", None, false).unwrap();
    assert!(stats.view.is_none());
    assert!(stats.pin_status.is_none());
    assert!(view::latest_pin(&src, &remote, "main").unwrap().is_none());
    assert_audit_clean(&src);
    server.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn signed_view_pins_signer_and_rejects_key_swap() {
    let root = temp("pin-signer");
    let mut src = Repo::init(root.join("src")).unwrap();
    let files = BTreeMap::from([("a.txt".to_string(), b"a\n".to_vec())]);
    commit_all(&mut src, &files, 1_000);
    let key1 = KeyFile::generate().unwrap();
    let key1_path = root.join("key1.json");
    key1.save_new(&key1_path).unwrap();
    let key2 = KeyFile::generate().unwrap();
    let key2_path = root.join("key2.json");
    key2.save_new(&key2_path).unwrap();
    let server = start_signed(&root, &key1_path, "127.0.0.1:0");
    let remote = format!("http://{}", server.addr());
    let port = server.addr().port();
    let published = publish_to(&remote, TOKEN, &mut src, "main", None).unwrap();
    assert_eq!(published.view_signer.as_deref(), Some(key1.key_id.as_str()));
    let pinned = view::latest_pin(&src, &remote, "main")
        .unwrap()
        .expect("签名视图必须落 pin");
    assert_eq!(pinned.signer.as_deref(), Some(key1.key_id.as_str()));
    assert_eq!(pinned.signer_key.as_deref(), Some(key1.public.as_str()));
    server.shutdown();

    // 同一中央仓换签名钥：旧 pin 要求同一把钥，不能静默接受。
    let server = start_signed(&root, &key2_path, &format!("127.0.0.1:{port}"));
    let remote = format!("http://{}", server.addr());
    let err = pull_from(&remote, TOKEN, &mut src, "main", None, true).unwrap_err();
    assert!(
        matches!(err, RemoteError::View(ViewError::SignerChanged { .. })),
        "{err}"
    );
    assert_eq!(src.head().unwrap(), published.commit);
    assert!(!src.journal().events().iter().any(|event| {
        event.kind == "pull"
            && event.payload.get("side").and_then(|side| side.as_str()) == Some("client")
    }));
    assert!(src.journal().events().iter().any(|event| {
        event.kind == "deny" && event.payload["reason"] == "remote_signer_changed"
    }));
    server.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn signed_pin_rejects_unsigned_server() {
    let root = temp("pin-unsigned");
    let mut src = Repo::init(root.join("src")).unwrap();
    let files = BTreeMap::from([("a.txt".to_string(), b"a\n".to_vec())]);
    commit_all(&mut src, &files, 1_000);
    let key = KeyFile::generate().unwrap();
    let key_path = root.join("key.json");
    key.save_new(&key_path).unwrap();
    let server = start_signed(&root, &key_path, "127.0.0.1:0");
    let remote = format!("http://{}", server.addr());
    let port = server.addr().port();
    let published = publish_to(&remote, TOKEN, &mut src, "main", None).unwrap();
    server.shutdown();

    // 同一个中央仓改回无签名服务端：pin 记得旧签名者，不允许静默降级。
    let server = start_on(&root, &format!("127.0.0.1:{port}"));
    let remote = format!("http://{}", server.addr());
    let err = pull_from(&remote, TOKEN, &mut src, "main", None, true).unwrap_err();
    assert!(
        matches!(err, RemoteError::View(ViewError::Unsigned { .. })),
        "{err}"
    );
    assert_eq!(src.head().unwrap(), published.commit);
    assert!(src.journal().events().iter().any(|event| {
        event.kind == "deny" && event.payload["reason"] == "remote_view_unsigned"
    }));
    server.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}
