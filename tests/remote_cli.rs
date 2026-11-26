//! 命令行端到端：`serve` 起服务 → `publish --remote` → 另一侧 `pull --remote` 落 HEAD。
//! 同时把鉴权与"不开放 force"这两条边界钉在进程边界上，而不是只测库函数。

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};

/// 这两条测试都会起真实 `serve` 子进程；Windows runner 上并行起两个监听者会互相干扰
/// （复现为其中一条在首个 publish 时 connection refused），所以进程级网络用例串行跑。
fn serial() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_trit-vcs")
}

fn run(root: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .current_dir(root)
        .output()
        .expect("启动 trit-vcs 失败")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn temp(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("trit-vcs-remotecli-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

const TOKEN: &str = "0123456789abcdef";

/// 起一个 `serve`，从它的第一行拿到真实端口；Drop 时 kill，避免测试线程退出后留下监听者。
struct ServerProc {
    child: Child,
    base: String,
}

impl Drop for ServerProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn serve(root: &Path, token_file: &Path) -> ServerProc {
    serve_inner(root, token_file, None)
}

fn serve_keyed(root: &Path, token_file: &Path, key: &Path) -> ServerProc {
    serve_inner(root, token_file, Some(key))
}

fn serve_inner(root: &Path, token_file: &Path, view_key: Option<&Path>) -> ServerProc {
    let token = token_file.to_string_lossy().to_string();
    let mut command = Command::new(bin());
    command.args([
        "serve",
        "--dir",
        &root.join("central").to_string_lossy(),
        "--bind",
        "127.0.0.1:0",
        "--actor",
        "qoder:remote-cli",
        "--token-file",
        &token,
        "--read-timeout",
        "20",
    ]);
    if let Some(key) = view_key {
        command.arg("--view-key").arg(key);
    }
    let mut child = command
        .current_dir(root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("起 serve 失败");
    let out = child.stdout.take().expect("serve 没有 stdout");
    let mut lines = BufReader::new(out).lines();
    let line = lines
        .next()
        .transpose()
        .expect("读 serve 启动行失败")
        .unwrap_or_default();
    let Some(rest) = line.split("http://").nth(1) else {
        let err = child.stderr.take().map(|mut pipe| {
            let mut text = String::new();
            use std::io::Read;
            let _ = pipe.read_to_string(&mut text);
            text
        });
        panic!("serve 没打印地址：{line}｜stderr {err:?}");
    };
    let base = rest
        .split('（')
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    assert!(!base.is_empty(), "地址是空的：{line}");
    // stdout 只剩服务日志；继续读会阻塞，直接丢弃尾部，让子进程自己往管道里写。
    ServerProc {
        child,
        base: format!("http://{base}"),
    }
}

fn init(dir: &Path) {
    fs::create_dir_all(dir).unwrap();
    let out = run(dir, &["init"]);
    assert!(out.status.success(), "{}", stderr(&out));
}

fn commit(dir: &Path, message: &str, files: &[(&str, &str)]) {
    for (path, body) in files {
        let full = dir.join(path);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(full, body).unwrap();
    }
    let added = run(dir, &["add", "."]);
    assert!(added.status.success(), "{}", stderr(&added));
    let committed = run(
        dir,
        &[
            "commit",
            "-m",
            message,
            "--owner",
            "qoder:remote-cli",
            "--allow-unclaimed",
        ],
    );
    assert!(committed.status.success(), "{}", stderr(&committed));
}

#[test]
fn serve_publish_pull_end_to_end() {
    let _serial = serial();
    let root = temp("flow");
    let token_file = root.join("token.txt");
    fs::write(&token_file, format!("{TOKEN}\n")).unwrap();

    let src = root.join("src");
    init(&src);
    commit(
        &src,
        "first",
        &[
            ("gen/d00/a.txt", "a\n"),
            ("gen/d01/b.txt", "b\n"),
            ("top.txt", "top\n"),
        ],
    );

    let central = root.join("central");
    fs::create_dir_all(&central).unwrap();
    let server = serve(&root, &token_file);

    // 1) 发布成功，服务端收下对象并推进 ref。
    let published = run(
        &src,
        &[
            "publish",
            "main",
            "--remote",
            &server.base,
            "--token-file",
            token_file.to_str().unwrap(),
        ],
    );
    assert!(published.status.success(), "{}", stderr(&published));
    assert!(
        stdout(&published).contains("已发布"),
        "发布要报告结果：{}",
        stdout(&published)
    );
    // 1b) 只读 view 必须能对上刚落的 pin，且不因查询本身改工作树或再落 pin。
    let viewed = run(
        &src,
        &[
            "view",
            "main",
            "--remote",
            &server.base,
            "--token-file",
            token_file.to_str().unwrap(),
            "--json",
        ],
    );
    assert!(viewed.status.success(), "{}", stderr(&viewed));
    let view: serde_json::Value = serde_json::from_str(&stdout(&viewed)).unwrap();
    assert_eq!(view["ok"], true);
    let status = view["pin_status"].as_str().unwrap_or_default();
    assert!(
        matches!(status, "advanced" | "unchanged"),
        "只读 view 自己的 auth 事件会让高度前进，但绝不该回滚：{status}"
    );
    let pinned_height = view["pin_before"]["height"].as_u64().unwrap_or(0);
    assert!(pinned_height > 0, "发布后应已有 pin：{view}");
    if status == "advanced" {
        assert!(
            view["view"]["height"].as_u64().unwrap_or(0) > pinned_height,
            "advanced 必须真的更高：{view}"
        );
    }
    let log = run(&src, &["log", "--json"]);
    assert!(log.status.success(), "{}", stderr(&log));
    let rows: serde_json::Value = serde_json::from_str(&stdout(&log)).unwrap();
    assert_eq!(
        view["view"]["tip"], rows[0]["id"],
        "view 的 ref tip 必须指向刚发布的提交"
    );

    // 2) 另一个侧从零拉全量：文件落盘、HEAD 与索引一起落，status 立刻干净。
    let client = root.join("client");
    init(&client);
    let pulled = run(
        &client,
        &[
            "pull",
            "main",
            "--remote",
            &server.base,
            "--token-file",
            token_file.to_str().unwrap(),
        ],
    );
    assert!(pulled.status.success(), "{}", stderr(&pulled));
    assert!(
        stdout(&pulled).contains("物化 3 个文件"),
        "全量 pull 该写 3 个：{}",
        stdout(&pulled)
    );
    assert!(stdout(&pulled).contains("HEAD 与索引已落到该提交"));
    assert_eq!(fs::read(client.join("top.txt")).unwrap(), b"top\n");
    assert_eq!(fs::read(client.join("gen/d00/a.txt")).unwrap(), b"a\n");

    let status = run(&client, &["status", "--json"]);
    assert!(status.status.success(), "{}", stderr(&status));
    let payload: serde_json::Value = serde_json::from_str(&stdout(&status)).unwrap();
    assert_eq!(
        payload["changes"].as_array().map(Vec::len),
        Some(0),
        "pull 落 HEAD 后 status 必须干净：{payload}"
    );
    let log = run(&client, &["log", "--json"]);
    let rows: serde_json::Value = serde_json::from_str(&stdout(&log)).unwrap();
    assert_eq!(
        rows.as_array().map(Vec::len),
        Some(1),
        "HEAD 要指到被拉的提交"
    );

    // 3) 前缀 pull 只物化范围内，且不擅动 HEAD（否则范围外会被算成删除）。
    let sparse = root.join("sparse");
    init(&sparse);
    let partial = run(
        &sparse,
        &[
            "pull",
            "main",
            "--remote",
            &server.base,
            "--token-file",
            token_file.to_str().unwrap(),
            "--prefix",
            "gen/d00",
        ],
    );
    assert!(partial.status.success(), "{}", stderr(&partial));
    assert!(sparse.join("gen/d00/a.txt").is_file());
    assert!(!sparse.join("gen/d01").exists(), "范围外不该落文件");
    let view = run(&sparse, &["sparse", "--json"]);
    let view_value: serde_json::Value = serde_json::from_str(&stdout(&view)).unwrap();
    assert_eq!(
        view_value["prefix"], "gen/d00",
        "网络前缀 pull 也要记 sparse 索引"
    );
    let sparse_status = run(&sparse, &["status", "--json"]);
    let sparse_value: serde_json::Value = serde_json::from_str(&stdout(&sparse_status)).unwrap();
    assert_eq!(
        sparse_value["changes"].as_array().map(Vec::len),
        Some(0),
        "前缀 pull 之后 status 不该把没检出的目录算成删除"
    );
    let sparse_log = run(&sparse, &["log", "--json"]);
    let rows: serde_json::Value = serde_json::from_str(&stdout(&sparse_log)).unwrap();
    assert_eq!(
        rows.as_array().map(Vec::len),
        Some(0),
        "前缀 pull 不挪 HEAD"
    );

    // 4) token 不对：401 要在进程边界上判失败，而不是静默退回。
    let wrong = root.join("wrong-token.txt");
    fs::write(&wrong, "wrong-token-0000\n").unwrap();
    let denied = run(
        &src,
        &[
            "publish",
            "main",
            "--remote",
            &server.base,
            "--token-file",
            wrong.to_str().unwrap(),
        ],
    );
    assert!(!denied.status.success(), "错 token 必须判失败");
    assert!(stderr(&denied).contains("FAIL"), "{}", stderr(&denied));
    assert!(
        stderr(&denied).contains("401"),
        "要把服务端状态码带出来：{}",
        stderr(&denied)
    );

    // 5) 一条不相干的历史推到同一个 ref：409，server 不接。
    let other = root.join("other");
    init(&other);
    commit(&other, "unrelated", &[("x.txt", "x\n")]);
    let diverged = run(
        &other,
        &[
            "publish",
            "main",
            "--remote",
            &server.base,
            "--token-file",
            token_file.to_str().unwrap(),
        ],
    );
    assert!(!diverged.status.success(), "不相干历史必须被拒");
    assert!(
        stderr(&diverged).contains("409"),
        "非快进要回 409：{}",
        stderr(&diverged)
    );

    // 6) 网络面不开放 force：口头允许也不行，改写只能在中央仓本地做。
    let forced = run(
        &src,
        &[
            "publish",
            "main",
            "--remote",
            &server.base,
            "--token-file",
            token_file.to_str().unwrap(),
            "--force",
        ],
    );
    assert!(!forced.status.success());
    assert!(
        stderr(&forced).contains("网络不开放 --force"),
        "{}",
        stderr(&forced)
    );

    // 服务端被拒之后 ref 仍在原处：再拉一次拿到的还是第一次那个提交。
    let again = run(
        &client,
        &[
            "pull",
            "main",
            "--remote",
            &server.base,
            "--token-file",
            token_file.to_str().unwrap(),
        ],
    );
    assert!(again.status.success(), "{}", stderr(&again));

    let audit = run(&central, &["audit", "log", "--json"]);
    assert!(audit.status.success(), "{}", stderr(&audit));
    let events: serde_json::Value = serde_json::from_str(&stdout(&audit)).unwrap();
    let allowed: Vec<_> = events
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["kind"] == "auth" && event["payload"]["decision"] == "allowed")
        .collect();
    assert!(allowed.len() >= 3, "publish/pull 成功鉴权都要落账");
    assert!(
        allowed
            .iter()
            .all(|event| event["payload"]["actor"] == "qoder:remote-cli")
    );
    let request_ids: std::collections::HashSet<_> = allowed
        .iter()
        .map(|event| event["payload"]["request_id"].as_str().unwrap())
        .collect();
    assert_eq!(request_ids.len(), allowed.len(), "request id 不得复用");

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn view_reports_and_checks_server_signer() {
    let _serial = serial();
    let root = temp("view-signer");
    let token_file = root.join("token.txt");
    fs::write(&token_file, format!("{TOKEN}\n")).unwrap();
    let key_path = root.join("view-key.json");
    let keyed = run(
        &root,
        &["key", "init", "--out", key_path.to_str().unwrap(), "--json"],
    );
    assert!(keyed.status.success(), "{}", stderr(&keyed));
    let key: serde_json::Value = serde_json::from_str(&stdout(&keyed)).unwrap();
    let key_id = key["key_id"].as_str().unwrap();

    let src = root.join("src");
    init(&src);
    commit(&src, "first", &[("a.txt", "a\n")]);
    let central = root.join("central");
    fs::create_dir_all(&central).unwrap();
    let server = serve_keyed(&root, &token_file, &key_path);
    let published = run(
        &src,
        &[
            "publish",
            "main",
            "--remote",
            &server.base,
            "--token-file",
            token_file.to_str().unwrap(),
        ],
    );
    assert!(published.status.success(), "{}", stderr(&published));

    let viewed = run(
        &src,
        &[
            "view",
            "main",
            "--remote",
            &server.base,
            "--token-file",
            token_file.to_str().unwrap(),
            "--expect-view-key",
            key_id,
            "--json",
        ],
    );
    assert!(viewed.status.success(), "{}", stderr(&viewed));
    let payload: serde_json::Value = serde_json::from_str(&stdout(&viewed)).unwrap();
    assert_eq!(payload["signature"]["key_id"], key_id, "{payload}");

    let wrong = run(
        &src,
        &[
            "view",
            "main",
            "--remote",
            &server.base,
            "--token-file",
            token_file.to_str().unwrap(),
            "--expect-view-key",
            "ed25519:0000000000000000",
        ],
    );
    assert!(!wrong.status.success(), "不匹配的指纹必须拒绝");
    assert!(
        stderr(&wrong).contains("不是 --expect-view-key 要求"),
        "{:?}",
        stderr(&wrong)
    );

    let _ = fs::remove_dir_all(&root);
}
