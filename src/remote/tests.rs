use std::collections::BTreeMap;
use std::io::{BufRead, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use super::*;
use crate::gate::ClaimSpec;
use crate::net::{Config, Server};
use crate::repo::CommitRequest;

const TOKEN: &str = "0123456789abcdef";

fn temp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("trit-vcs-remote-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn commit_all(repo: &mut Repo, files: &BTreeMap<String, Vec<u8>>, now: u64) -> Hash {
    repo.stage(files, now).unwrap();
    repo.commit(CommitRequest {
        message: format!("c{now}"),
        session: "qoder:remote".to_string(),
        claims: vec![ClaimSpec {
            id: format!("c{now}"),
            owner: "qoder:remote".to_string(),
            paths: files.keys().cloned().collect(),
            acquired_at: 1,
            expires_at: u64::MAX / 2,
        }],
        now_secs: now,
        ..Default::default()
    })
    .unwrap()
    .id
}

fn start(root: &std::path::Path) -> Server {
    start_on(root, "127.0.0.1:0")
}

fn start_on(root: &std::path::Path, addr: &str) -> Server {
    let mut config = Config::new(root.join("central"), addr, TOKEN);
    config.actor = Some("qoder:ci".to_string());
    config.read_timeout = Duration::from_secs(20);
    config.max_body = 64 * 1024 * 1024;
    Server::start(config).unwrap()
}

fn assert_sync(
    repo: &Repo,
    action: &str,
    side: &str,
    op_id: &str,
    request_id: Option<&str>,
    actor: Option<&str>,
) {
    let event = repo
        .journal()
        .events()
        .iter()
        .find(|event| {
            event.kind == action
                && event.payload["schema"] == sync::SCHEMA
                && event.payload["side"] == side
        })
        .unwrap_or_else(|| panic!("缺 {action}/{side} 成功事件"));
    assert_eq!(event.payload["action"], action);
    assert_eq!(event.payload["op_id"], op_id);
    assert_eq!(
        event.payload["transport"],
        if request_id.is_some() {
            "http"
        } else {
            "local"
        }
    );
    assert_eq!(event.payload["request_id"].as_str(), request_id);
    assert_eq!(event.payload["actor"].as_str(), actor);
    assert_eq!(event.payload["name"], "main");
    let stage = match (action, side, request_id.is_some()) {
        ("publish", "source", _) => "recorded",
        ("publish", "central", _) => "applied",
        ("pull", "client", _) => "applied",
        ("pull", "central", false) => "prepared",
        ("pull", "central", true) => "response_sent",
        _ => panic!("不支持的同步组合"),
    };
    assert_eq!(event.payload["stage"], stage);
    assert!(crate::hash::Hash::from_hex(event.payload["commit"].as_str().unwrap()).is_some());
    assert!(crate::hash::Hash::from_hex(event.payload["state_before"].as_str().unwrap()).is_some());
    assert!(crate::hash::Hash::from_hex(event.payload["state_after"].as_str().unwrap()).is_some());
}

fn assert_audit_clean(repo: &Repo) {
    let report = crate::audit::status(repo).unwrap();
    assert!(report.ok, "{}: {:#?}", repo.root().display(), report.issues);
}

fn central_after_response(root: &std::path::Path, op_id: &str) -> Repo {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(central) = Repo::open(root.join("central"))
            && central.journal().events().iter().any(|event| {
                event.kind == "pull"
                    && event.payload["schema"] == sync::SCHEMA
                    && event.payload["op_id"] == op_id
            })
        {
            return central;
        }
        assert!(
            Instant::now() < deadline,
            "中央仓迟迟没有 response_sent 事件"
        );
        std::thread::yield_now();
    }
}

fn raw_publish(addr: std::net::SocketAddr, target: &str, tip: Option<&str>) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    let mut head = format!(
        "POST {target} HTTP/1.1\r\nhost: {addr}\r\nauthorization: Bearer {TOKEN}\r\n\
         content-length: 0\r\nconnection: close\r\n"
    );
    if let Some(tip) = tip {
        head.push_str(&format!("x-trit-tip: {tip}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

fn raw_pull(addr: std::net::SocketAddr, target: &str) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    let head = format!(
        "GET {target} HTTP/1.1\r\nhost: {addr}\r\nauthorization: Bearer {TOKEN}\r\n\
         connection: close\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

fn response_header(response: &str, name: &str) -> String {
    response
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name)
                .then(|| value.trim().to_string())
        })
        .unwrap_or_else(|| panic!("响应缺 {name}：{response}"))
}

#[test]
fn legacy_http_sync_without_op_id_is_accepted_and_audited() {
    let root = temp("legacy-http");
    let mut src = Repo::init(root.join("src")).unwrap();
    commit_all(
        &mut src,
        &BTreeMap::from([("a.txt".to_string(), b"a\n".to_vec())]),
        1_000,
    );
    let tip = src.head().unwrap().unwrap();
    let body = publish_body(&src, tip).unwrap();
    let length = body.byte_len(src.store()).unwrap();
    let server = start(&root);
    let mut stream = TcpStream::connect(server.addr()).unwrap();
    write!(
        stream,
        "POST /v1/publish?ref=main HTTP/1.1\r\nhost: {}\r\nauthorization: Bearer {TOKEN}\r\nx-trit-tip: {}\r\ncontent-length: {length}\r\nconnection: close\r\n\r\n",
        server.addr(),
        tip.to_hex()
    )
    .unwrap();
    body.write(src.store(), &mut stream).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let request_id = response_header(&response, "x-trit-request-id");
    let op_id = response_header(&response, "x-trit-op-id");
    assert!(Hash::from_hex(&request_id).is_some());
    assert!(Hash::from_hex(&op_id).is_some());

    let central = Repo::open(root.join("central")).unwrap();
    assert_sync(
        &central,
        "publish",
        "central",
        &op_id,
        Some(&request_id),
        Some("qoder:ci"),
    );
    assert_audit_clean(&central);
    assert!(
        !src.journal()
            .events()
            .iter()
            .any(|event| { event.kind == "publish" && event.payload["schema"] == sync::SCHEMA })
    );

    let mut stream = TcpStream::connect(server.addr()).unwrap();
    write!(
        stream,
        "GET /v1/pull?ref=main HTTP/1.1\r\nhost: {}\r\nauthorization: Bearer {TOKEN}\r\nconnection: close\r\n\r\n",
        server.addr()
    )
    .unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reader = std::io::BufReader::new(stream);
    let mut head = String::new();
    loop {
        let mut line = String::new();
        assert!(reader.read_line(&mut line).unwrap() > 0, "pull 响应被截断");
        if line == "\r\n" {
            break;
        }
        head.push_str(&line);
    }
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let request_id = response_header(&head, "x-trit-request-id");
    let op_id = response_header(&head, "x-trit-op-id");
    assert!(Hash::from_hex(&request_id).is_some());
    assert!(Hash::from_hex(&op_id).is_some());
    let length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap();
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();

    let central = central_after_response(&root, &op_id);
    assert_sync(
        &central,
        "pull",
        "central",
        &op_id,
        Some(&request_id),
        Some("qoder:ci"),
    );
    assert_audit_clean(&central);
    server.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn pull_refuses_missing_commit_evidence_before_materializing() {
    let root = temp("missing-evidence");
    let mut src = Repo::init(root.join("src")).unwrap();
    commit_all(
        &mut src,
        &BTreeMap::from([("a.txt".to_string(), b"a\n".to_vec())]),
        1_000,
    );
    let tip = src.head().unwrap().unwrap();
    let commit = src.commit_at(&tip).unwrap();
    let claim_set = commit.claim_set.expect("夹具必须带认领证据");
    let mut client = Repo::init(root.join("client")).unwrap();
    let objects = crate::bundle::commit_closure(src.store(), tip).unwrap();
    crate::bundle::transfer(src.store(), client.store(), &objects).unwrap();
    assert!(!client.store().has_chunk(&claim_set));
    let files = client.store().tree_entries(&commit.tree).unwrap().len();
    let journal_len = client.journal().events().len();
    let reply = PullReply {
        tip,
        manifest: commit.tree,
        files,
        objects: objects.len(),
        declared: 0,
        received: objects.len(),
        request_id: Hash::of(b"request").to_hex(),
    };

    let err = apply_pull(
        &mut client,
        &reply,
        None,
        false,
        "main",
        &Hash::of(b"op").to_hex(),
        "http://test",
        None,
    )
    .unwrap_err();
    assert!(matches!(err, RemoteError::HistoryGap(_)), "{err}");
    assert!(client.head().unwrap().is_none());
    assert_eq!(client.journal().events().len(), journal_len);
    assert!(!client.root().join("a.txt").exists());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn publish_shape_rejections_are_denied_and_audited() {
    let root = temp("publish-shape");
    let mut src = Repo::init(root.join("src")).unwrap();
    let files = BTreeMap::from([("a.txt".to_string(), b"a\n".to_vec())]);
    commit_all(&mut src, &files, 1_000);
    let tip = src.head().unwrap().unwrap().to_hex();
    let server = start(&root);
    raw_publish(server.addr(), "/v1/publish", None);
    raw_publish(server.addr(), "/v1/publish?ref=main", None);
    raw_publish(server.addr(), "/v1/publish?ref=main", Some("not-a-hash"));
    raw_publish(server.addr(), "/v1/publish?ref=main", Some(tip.as_str()));

    let central = Repo::open(root.join("central")).unwrap();
    let denies: Vec<_> = central
        .journal()
        .events()
        .iter()
        .filter(|event| event.kind == "deny")
        .collect();
    assert_eq!(denies.len(), 4, "四个形状错误都要有 deny");
    for (deny, reason) in
        denies
            .iter()
            .zip(["missing_ref", "missing_tip", "bad_tip", "bad_body_size"])
    {
        assert_eq!(deny.payload["action"], "publish");
        assert_eq!(deny.payload["reason"], reason);
        assert_eq!(
            deny.payload["state_before"], deny.payload["state_after"],
            "请求形状拒绝不改仓库状态"
        );
    }
    server.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn pull_shape_and_unknown_ref_are_denied_and_audited() {
    let root = temp("pull-shape");
    let server = start(&root);
    let missing = raw_pull(server.addr(), "/v1/pull");
    assert!(missing.starts_with("HTTP/1.1 400"), "{missing}");
    let unknown = raw_pull(server.addr(), "/v1/pull?ref=main");
    assert!(unknown.starts_with("HTTP/1.1 404"), "{unknown}");

    let central = Repo::open(root.join("central")).unwrap();
    let denies: Vec<_> = central
        .journal()
        .events()
        .iter()
        .filter(|event| event.kind == "deny")
        .collect();
    assert_eq!(denies.len(), 2, "缺 ref/未知 ref 都要有 deny");
    assert_eq!(denies[0].payload["action"], "pull");
    assert_eq!(denies[0].payload["reason"], "missing_ref");
    assert_eq!(denies[1].payload["action"], "pull");
    assert_eq!(denies[1].payload["reason"], "unknown_ref");
    for deny in denies {
        assert_eq!(
            deny.payload["state_before"], deny.payload["state_after"],
            "pull 拒绝不写中央仓状态"
        );
    }
    server.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn publish_then_full_pull_adopts_head() {
    let root = temp("full");
    let mut src = Repo::init(root.join("src")).unwrap();
    let files = BTreeMap::from([
        ("gen/a.txt".to_string(), b"aaa\n".to_vec()),
        ("gen/b.txt".to_string(), b"bbb\n".to_vec()),
    ]);
    commit_all(&mut src, &files, 1_000);
    let server = start(&root);
    let remote = format!("http://{}", server.addr());
    let stats = publish_to(&remote, TOKEN, &mut src, "main", None).unwrap();
    assert!(stats.objects > 0);
    assert_sync(
        &src,
        "publish",
        "source",
        &stats.op_id,
        Some(&stats.request_id),
        None,
    );
    let central = Repo::open(root.join("central")).unwrap();
    assert_sync(
        &central,
        "publish",
        "central",
        &stats.op_id,
        Some(&stats.request_id),
        Some("qoder:ci"),
    );
    assert_audit_clean(&src);
    assert_audit_clean(&central);

    let client_dir = root.join("client");
    std::fs::create_dir_all(&client_dir).unwrap();
    let mut client = Repo::init(&client_dir).unwrap();
    let pulled = pull_from(&remote, TOKEN, &mut client, "main", None, false).unwrap();
    assert_eq!(pulled.written, 2);
    let source_commit = src.commit_at(&pulled.commit.unwrap()).unwrap();
    if let Some(claim_set) = source_commit.claim_set {
        assert!(
            client.store().has_chunk(&claim_set),
            "pull 必须带上认领证据"
        );
    }
    assert_sync(
        &client,
        "pull",
        "client",
        &pulled.op_id,
        Some(&pulled.request_id),
        None,
    );
    let central = central_after_response(&root, &pulled.op_id);
    assert_sync(
        &central,
        "pull",
        "central",
        &pulled.op_id,
        Some(&pulled.request_id),
        Some("qoder:ci"),
    );
    assert_audit_clean(&client);
    assert_audit_clean(&central);
    assert_eq!(client.head().unwrap(), Some(pulled.commit.unwrap()));
    assert!(
        worktree::status(&client).unwrap().is_empty(),
        "pull 后 status 必须干净"
    );
    assert!(client.index().unwrap().is_some(), "索引要落到被拉的树");
    assert_eq!(client.log().unwrap().len(), 1);
    server.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn prefix_pull_materializes_only_that_dir_and_keeps_head() {
    let root = temp("prefix");
    let mut src = Repo::init(root.join("src")).unwrap();
    let files = BTreeMap::from([
        ("gen/d00/a.txt".to_string(), b"a\n".to_vec()),
        ("gen/d01/b.txt".to_string(), b"b\n".to_vec()),
    ]);
    commit_all(&mut src, &files, 1_000);
    let server = start(&root);
    let remote = format!("http://{}", server.addr());
    publish_to(&remote, TOKEN, &mut src, "main", None).unwrap();

    let client_dir = root.join("client");
    std::fs::create_dir_all(&client_dir).unwrap();
    let mut client = Repo::init(&client_dir).unwrap();
    let pulled = pull_from(&remote, TOKEN, &mut client, "main", Some("gen/d00"), false).unwrap();
    assert_eq!(pulled.written, 1);
    assert!(client_dir.join("gen/d00/a.txt").is_file());
    assert!(!client_dir.join("gen/d01").exists());
    assert_sync(
        &client,
        "pull",
        "client",
        &pulled.op_id,
        Some(&pulled.request_id),
        None,
    );
    let central = central_after_response(&root, &pulled.op_id);
    assert_sync(
        &central,
        "pull",
        "central",
        &pulled.op_id,
        Some(&pulled.request_id),
        Some("qoder:ci"),
    );
    assert_audit_clean(&client);
    assert_audit_clean(&central);
    assert!(client.head().unwrap().is_none(), "前缀 pull 不擅动 HEAD");
    server.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn dirty_worktree_pull_is_denied_and_audited() {
    let root = temp("dirty-pull");
    let mut src = Repo::init(root.join("src")).unwrap();
    let files = BTreeMap::from([("a.txt".to_string(), b"a\n".to_vec())]);
    commit_all(&mut src, &files, 1_000);
    let server = start(&root);
    let remote = format!("http://{}", server.addr());
    publish_to(&remote, TOKEN, &mut src, "main", None).unwrap();

    let client_dir = root.join("client");
    std::fs::create_dir_all(&client_dir).unwrap();
    let mut client = Repo::init(&client_dir).unwrap();
    std::fs::write(client_dir.join("dirty.txt"), b"local\n").unwrap();
    client
        .stage(
            &BTreeMap::from([("dirty.txt".to_string(), b"local\n".to_vec())]),
            2_000,
        )
        .unwrap();
    let err = pull_from(&remote, TOKEN, &mut client, "main", None, false).unwrap_err();
    assert!(
        matches!(err, RemoteError::Worktree(WorktreeError::Dirty(..))),
        "{err}"
    );
    let deny = client
        .journal()
        .events()
        .iter()
        .find(|event| event.kind == "deny")
        .expect("脏工作树 pull 必须留下 deny 事件");
    assert_eq!(deny.payload["action"], "pull");
    assert_eq!(deny.payload["decision"], "denied");
    assert_eq!(deny.payload["reason"], "worktree_dirty");
    assert_eq!(deny.payload["detail"]["ref"], "main");
    assert_eq!(
        deny.payload["state_before"], deny.payload["state_after"],
        "被拒的 pull 不改 HEAD/index"
    );
    assert!(client.head().unwrap().is_none(), "被拒的 pull 不落 HEAD");
    server.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn wrong_token_and_non_fast_forward_are_loud() {
    let root = temp("gates");
    let mut src = Repo::init(root.join("src")).unwrap();
    let files = BTreeMap::from([("a.txt".to_string(), b"a\n".to_vec())]);
    commit_all(&mut src, &files, 1_000);
    let server = start(&root);
    let remote = format!("http://{}", server.addr());
    publish_to(&remote, TOKEN, &mut src, "main", None).unwrap();

    let err = publish_to(&remote, "wrong-token-0000", &mut src, "main", None).unwrap_err();
    assert!(
        matches!(err, RemoteError::Net(NetError::Status(401, _))),
        "{err}"
    );
    let central = Repo::open(root.join("central")).unwrap();
    let denied: Vec<_> = central
        .journal()
        .events()
        .iter()
        .filter(|event| {
            event.kind == "auth" && event.payload["decision"].as_str() == Some("denied")
        })
        .collect();
    // 已有 pin 时先做只读 view 预检；token 错就在发 publish 之前被挡住，只留一条 GET 拒绝。
    assert_eq!(denied.len(), 1, "预检失败不应再发 publish");
    let auth = denied[0];
    assert_eq!(auth.payload["decision"], "denied");
    assert_eq!(auth.payload["reason"], "bad_token");
    assert_eq!(auth.payload["method"], "GET");
    assert_eq!(auth.payload["path"], "/v1/view");
    assert_eq!(
        auth.payload["state_before"], auth.payload["state_after"],
        "鉴权失败不改仓库状态"
    );

    // 另一个客户端从零起一条不相干的历史：不是 main 的后代 ⇒ 409。
    let other_dir = root.join("other");
    std::fs::create_dir_all(&other_dir).unwrap();
    let mut other = Repo::init(&other_dir).unwrap();
    let other_files = BTreeMap::from([("x.txt".to_string(), b"x\n".to_vec())]);
    commit_all(&mut other, &other_files, 2_000);
    let err = publish_to(&remote, TOKEN, &mut other, "main", None).unwrap_err();
    assert!(
        matches!(
            err,
            RemoteError::Repo(RepoError::NonFastForward { .. })
                | RemoteError::Net(NetError::Status(409, _))
        ),
        "{err}"
    );
    let central = Repo::open(root.join("central")).unwrap();
    let deny = central
        .journal()
        .events()
        .iter()
        .find(|event| event.kind == "deny")
        .expect("非快进 publish 必须留下 deny 事件");
    assert_eq!(deny.payload["action"], "publish");
    assert_eq!(deny.payload["decision"], "denied");
    assert_eq!(deny.payload["reason"], "non_fast_forward");
    assert_eq!(deny.payload["detail"]["ref"], "main");
    assert_eq!(
        deny.payload["state_before"], deny.payload["state_after"],
        "被拒的 publish 不改 ref 状态"
    );
    assert_eq!(
        pull_plan(&central, "main", None).unwrap().tip,
        src.head().unwrap().unwrap(),
        "被拒的 publish 不该把 ref 挪走"
    );
    server.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn state_lock_blocks_publish_and_pull() {
    let root = temp("state-lock");
    let mut src = Repo::init(root.join("src")).unwrap();
    let files = BTreeMap::from([("gen/d00/a.txt".to_string(), b"a\n".to_vec())]);
    let tip = commit_all(&mut src, &files, 1_000);
    let server = start(&root);
    let remote = format!("http://{}", server.addr());
    publish_to(&remote, TOKEN, &mut src, "main", None).unwrap();

    let mut central = Repo::open(root.join("central")).unwrap();
    let guard = crate::claims::lock(central.root()).unwrap();
    assert!(matches!(
        accept_publish(&mut central, "main", &tip),
        Err(RemoteError::Repo(RepoError::StateLocked(_)))
    ));
    drop(guard);

    let client_dir = root.join("client");
    std::fs::create_dir_all(&client_dir).unwrap();
    let mut client = Repo::init(&client_dir).unwrap();
    let network = Client::new(&remote, TOKEN).unwrap();
    let op_id = sync::new_op_id();
    let reply = network
        .pull(
            "main",
            Some("gen/d00"),
            client.store(),
            Limits::default(),
            &op_id,
        )
        .unwrap();
    let guard = crate::claims::lock(client.root()).unwrap();
    assert!(matches!(
        apply_pull(
            &mut client,
            &reply,
            Some("gen/d00"),
            false,
            "main",
            &op_id,
            "http://test",
            None
        ),
        Err(RemoteError::Repo(RepoError::StateLocked(_)))
    ));
    drop(guard);
    assert!(
        apply_pull(
            &mut client,
            &reply,
            Some("gen/d00"),
            false,
            "main",
            &op_id,
            "http://test",
            None
        )
        .is_ok()
    );
    server.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn second_pull_is_idempotent_and_incremental() {
    let root = temp("again");
    let mut src = Repo::init(root.join("src")).unwrap();
    let files = BTreeMap::from([("a.txt".to_string(), b"a\n".to_vec())]);
    commit_all(&mut src, &files, 1_000);
    let server = start(&root);
    let remote = format!("http://{}", server.addr());
    publish_to(&remote, TOKEN, &mut src, "main", None).unwrap();

    let client_dir = root.join("client");
    std::fs::create_dir_all(&client_dir).unwrap();
    let mut client = Repo::init(&client_dir).unwrap();
    let first = pull_from(&remote, TOKEN, &mut client, "main", None, false).unwrap();
    let second = pull_from(&remote, TOKEN, &mut client, "main", None, false).unwrap();
    assert_eq!(second.written, 0);
    assert!(second.objects <= first.objects, "重复拉不该再多搬对象");
    assert!(worktree::status(&client).unwrap().is_empty());
    server.shutdown();
    let _ = std::fs::remove_dir_all(&root);
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
