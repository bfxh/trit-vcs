//! 最小 HTTP/1.1 往返（只用 `std::net`）：服务器 + 客户端 + 鉴权 + 边界。
//!
//! 为什么自己写而不是拉一个框架：本仓的依赖面是"能算的都要能复算"，
//! 网络面只做**一个**协议版本、一个方法集、一种鉴权，够用即可；多一个 HTTP 框架
//! 就多一层"它的行为谁保证"的问题。这里只支持 HTTP/1.1 的子集：
//! `GET` / `POST`、`Content-Length`、每请求一条连接（`Connection: close`）、
//! 不接受 `Transfer-Encoding: chunked`。
//!
//! 安全边界（都写进 README，不在代码里装作有）：
//! - 明文 HTTP，**没有 TLS**：默认只该绑回环，跨机请套 SSH 隧道或反代；
//! - 鉴权是 Bearer token（文件或环境变量给，不进 argv），比较用常量时间；
//! - 请求头 ≤ 8 KiB、头数 ≤ 24、body ≤ `max_body`、对象数/单对象有上限；
//! - 每连接读写超时，连接数上限，超出回 503 而不是把线程堆爆。

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::wire;
pub use crate::wire::Limits;

mod auth;

const MAX_HEAD_BYTES: usize = 8 * 1024;
const MAX_HEADERS: usize = 24;

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("仓库: {0}")]
    Repo(String),
    #[error("地址不合法：{0}")]
    BadBind(String),
    #[error("只支持 http://（没有 TLS）：{0}")]
    NotHttp(String),
    #[error("URL 缺端口：{0}")]
    MissingPort(String),
    #[error("请求头超过 {MAX_HEAD_BYTES} 字节")]
    HeadTooLarge,
    #[error("请求头行数超过 {MAX_HEADERS}")]
    TooManyHeaders,
    #[error("请求行不是 `方法 路径 HTTP/1.x`：{0}")]
    BadRequestLine(String),
    #[error("不支持的 HTTP 版本：{0}")]
    BadVersion(String),
    #[error("不支持的传输编码：{0}（只认 Content-Length）")]
    BadTransferEncoding(String),
    #[error("POST 必须带 Content-Length")]
    MissingLength,
    #[error("请求体超过上限：{0} 字节")]
    BodyTooLarge(u64),
    #[error("鉴权失败：缺 Bearer token 或对不上")]
    Unauthorized,
    #[error("token 不合法：{0}")]
    BadToken(String),
    #[error("响应状态 {0}：{1}")]
    Status(u16, String),
    #[error("对象流: {0}")]
    Wire(String),
    #[error("响应头不完整或超过上限")]
    BadResponse,
    #[error("连接数已满（上限 {0}）")]
    Busy(usize),
}

impl NetError {
    /// 给 HTTP 状态码用的档位：客户端据此分支，不抠文案。
    pub fn status(&self) -> u16 {
        match self {
            NetError::Unauthorized => 401,
            NetError::BodyTooLarge(_) => 413,
            NetError::Busy(_) => 503,
            NetError::Status(status, _) => *status,
            NetError::BadBind(_)
            | NetError::NotHttp(_)
            | NetError::MissingPort(_)
            | NetError::HeadTooLarge
            | NetError::TooManyHeaders
            | NetError::BadRequestLine(_)
            | NetError::BadVersion(_)
            | NetError::BadTransferEncoding(_)
            | NetError::MissingLength
            | NetError::BadToken(_)
            | NetError::Wire(_)
            | NetError::BadResponse => 400,
            _ => 500,
        }
    }

    /// 机器可读档位：401/409/413 这些必须能被分支，而不是让人回来看中文。
    pub fn kind(&self) -> &'static str {
        match self {
            NetError::Unauthorized => "unauthorized",
            NetError::BodyTooLarge(_) => "body_too_large",
            NetError::Busy(_) => "server_busy",
            NetError::Status(_, _) => "remote_status",
            NetError::BadToken(_) => "bad_token",
            NetError::BadBind(_) => "bad_bind",
            NetError::Repo(_) => "server_repo",
            NetError::NotHttp(_) | NetError::MissingPort(_) => "bad_remote_url",
            NetError::HeadTooLarge | NetError::TooManyHeaders => "bad_request_head",
            NetError::BadRequestLine(_) | NetError::BadVersion(_) | NetError::MissingLength => {
                "bad_request"
            }
            NetError::BadTransferEncoding(_) => "bad_transfer_encoding",
            NetError::Wire(_) => "wire_bad_stream",
            NetError::BadResponse => "bad_response",
            NetError::Io(_) => "net_io",
        }
    }

    /// 下一步命令：网络失败的可执行动作（服务端起没起、token 从哪来、地址对不对）。
    pub fn commands(&self, ctx: crate::remediation::Context<'_>) -> Vec<String> {
        let repo = ctx.dir.display().to_string();
        match self {
            NetError::Unauthorized => vec![
                "确认 token：服务端 `trit-vcs serve --dir <中央仓> --bind 127.0.0.1:7878 --token-file <文件>`".to_string(),
                "客户端用同一个文件：`--token-file <文件>`（或 TRIT_VCS_TOKEN）".to_string(),
            ],
            NetError::Status(status, message) => vec![
                format!("服务端回 {status}：{message}"),
                format!(
                    "先 `trit-vcs log --repo {repo}` 与 `trit-vcs pull <ref> --remote http://<host>:<port>` 对齐，再重发"
                ),
            ],
            NetError::NotHttp(_) | NetError::MissingPort(_) => vec![
                "地址写成 `http://host:port`（v0 没有 TLS，跨机请套 SSH 隧道/反代）".to_string(),
            ],
            NetError::Io(_) => vec![
                "确认服务端在跑：`trit-vcs serve --dir <中央仓> --bind 127.0.0.1:7878 --token-file <文件>`"
                    .to_string(),
                "确认端口/防火墙/隧道；本机先用 127.0.0.1 试一遍".to_string(),
            ],
            NetError::BodyTooLarge(_) => {
                vec!["把 `--max-body-mb` 调大（服务端与客户端同一档），或先分批发布".to_string()]
            }
            NetError::BadToken(_) => vec![
                "token 至少 16 字节、至多 256 字节；用 `--token-file` 给，不要放进 argv"
                    .to_string(),
            ],
            NetError::Repo(detail) => vec![
                format!("中央仓不可用：{detail}"),
                "确认 `--dir` 是中央仓目录（不是客户端仓）；先 `trit-vcs init --repo <dir>` 也可以"
                    .to_string(),
            ],
            _ => vec!["重跑一次；仍然失败就贴出完整 FAIL 行".to_string()],
        }
    }
}

/// 服务器配置。`token` 必须非空（≥16 字节）；没有 token 的服务器不启动。
#[derive(Clone, Debug)]
pub struct Config {
    pub repo: PathBuf,
    pub bind: String,
    pub token: String,
    pub limits: Limits,
    pub max_body: u64,
    pub read_timeout: Duration,
    pub max_connections: usize,
}

impl Config {
    pub fn new(
        repo: impl Into<PathBuf>,
        bind: impl Into<String>,
        token: impl Into<String>,
    ) -> Self {
        Self {
            repo: repo.into(),
            bind: bind.into(),
            token: token.into(),
            limits: Limits::default(),
            max_body: 256 * 1024 * 1024,
            read_timeout: Duration::from_secs(30),
            max_connections: 8,
        }
    }

    /// 一条命令能改的边界都先过闸：token 太短、上限为 0 都不启动。
    /// 绑非回环不拦（跨机可以套 SSH 隧道/反代），但 v0 没有 TLS，README 已写明这条边界。
    pub fn validated(self) -> Result<Self, NetError> {
        if self.token.len() < 16 {
            return Err(NetError::BadToken(
                "至少 16 字节（短 token 等于没有）".to_string(),
            ));
        }
        if self.token.len() > 256 {
            return Err(NetError::BadToken("至多 256 字节".to_string()));
        }
        if self.max_body == 0 {
            return Err(NetError::BadBind("max_body 不能为 0".to_string()));
        }
        Ok(self)
    }
}

struct State {
    repo: Mutex<crate::repo::Repo>,
    token: String,
    limits: Limits,
    max_body: u64,
    connections: AtomicUsize,
    max_connections: usize,
    stop: Arc<AtomicBool>,
    read_timeout: Duration,
}

/// 已启动的服务器：`addr()` 能拿到实际端口（`bind` 带 `:0` 时由系统分配）。
pub struct Server {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl Server {
    pub fn start(config: Config) -> Result<Self, NetError> {
        let config = config.validated()?;
        let repo =
            crate::repo::Repo::init(&config.repo).map_err(|err| NetError::Repo(err.to_string()))?;
        let listener = TcpListener::bind(&config.bind)
            .map_err(|err| NetError::BadBind(format!("{}: {err}", config.bind)))?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let state = Arc::new(State {
            repo: Mutex::new(repo),
            token: config.token.clone(),
            limits: config.limits,
            max_body: config.max_body,
            connections: AtomicUsize::new(0),
            max_connections: config.max_connections.max(1),
            stop: stop.clone(),
            read_timeout: config.read_timeout,
        });
        let join = thread::spawn(move || accept_loop(listener, state));
        Ok(Self {
            addr,
            stop,
            join: Some(join),
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// 关掉监听并等收 accept 线程（处理中的连接各自超时退出）。
    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn accept_loop(listener: TcpListener, state: Arc<State>) {
    while !state.stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                // Windows 上 accept 会继承监听套接字的非阻塞模式：不关掉就会在 read 上
                // 拿到 WSAEWOULDBLOCK，表现成"对象流 io 错误"而不是等待。
                let _ = stream.set_nonblocking(false);
                let state = state.clone();
                let now = state.connections.fetch_add(1, Ordering::SeqCst) + 1;
                if now > state.max_connections {
                    state.connections.fetch_sub(1, Ordering::SeqCst);
                    let mut stream = stream;
                    let _ = respond_json(
                        &mut stream,
                        503,
                        "busy",
                        &format!("连接数已满（上限 {}）", state.max_connections),
                        &[],
                    );
                    continue;
                }
                thread::spawn(move || {
                    if let Err(err) = handle_conn(stream, &state) {
                        eprintln!("trit-vcs serve: 连接失败：{err}");
                    }
                    state.connections.fetch_sub(1, Ordering::SeqCst);
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => thread::sleep(Duration::from_millis(5)),
        }
    }
}

fn handle_conn(stream: TcpStream, state: &Arc<State>) -> Result<(), NetError> {
    let timeout = state.read_timeout;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    // 一条连接只用一个句柄：Windows 上 try_clone 出两个句柄时，
    // 先关副本会把还没被对端确认的响应字节变成 RST（客户端看到 10054 而不是 JSON）。
    let mut reader = BufReader::new(stream);
    let request = match read_request(&mut reader)? {
        Some(request) => request,
        None => return Ok(()),
    };
    if !token_eq(&request.headers, &state.token) {
        let reason = if request.headers.contains_key("authorization") {
            "bad_token"
        } else {
            "missing_token"
        };
        if auth::attempt_should_be_logged(&request) {
            auth::record_denied(state, &request, reason);
        }
        // 401 在读完 body 前就回，Windows 上服务端带着未读数据关连接会发 RST，
        // 客户端连已经写好的 401 都读不到。小 body 先排空再回（大 body 仍直接关，见 README）。
        drain_body(&mut reader, request.length);
        return respond_json(
            reader.get_mut(),
            401,
            "unauthorized",
            "缺 Bearer token 或对不上",
            &[("WWW-Authenticate", "Bearer")],
        );
    }
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/v1/health") => respond_json(
            reader.get_mut(),
            200,
            "ok",
            &format!("trit-vcs {}", env!("CARGO_PKG_VERSION")),
            &[],
        ),
        ("GET", "/v1/refs") => {
            let repo = state.repo.lock().expect("服务器仓库锁中毒");
            match repo.list_refs() {
                Ok(refs) => {
                    let rows: Vec<serde_json::Value> = refs
                        .into_iter()
                        .map(|(name, commit)| {
                            serde_json::json!({"name": name, "commit": commit.to_hex()})
                        })
                        .collect();
                    drop(repo);
                    respond_json_value(
                        reader.get_mut(),
                        200,
                        &serde_json::json!({"ok": true, "refs": rows}),
                    )
                }
                Err(err) => {
                    drop(repo);
                    let err: crate::remote::RemoteError = err.into();
                    respond_remote(reader.get_mut(), &err)
                }
            }
        }
        ("POST", "/v1/publish") => publish(&mut reader, &request, state),
        ("GET", "/v1/pull") => pull(reader.get_mut(), &request, state),
        _ => respond_json(reader.get_mut(), 404, "not_found", "没有这个端点", &[]),
    }
}

fn publish(
    reader: &mut BufReader<TcpStream>,
    request: &Request,
    state: &Arc<State>,
) -> Result<(), NetError> {
    let Some(name) = request.query.get("ref") else {
        return reject_json(
            reader,
            request,
            400,
            "bad_request",
            "publish 需要 ?ref=NAME",
            &[],
        );
    };
    let Some(tip_hex) = request.headers.get("x-trit-tip") else {
        return reject_json(
            reader,
            request,
            400,
            "bad_request",
            "publish 需要 X-Trit-Tip",
            &[],
        );
    };
    let Some(tip) = crate::hash::Hash::from_hex(tip_hex) else {
        return reject_json(
            reader,
            request,
            400,
            "bad_request",
            "X-Trit-Tip 不是合法提交 id",
            &[],
        );
    };
    if request.length == 0 || request.length > state.max_body {
        return reject_json(
            reader,
            request,
            413,
            "too_large",
            "请求体为空或超过上限",
            &[],
        );
    }
    let mut repo = state.repo.lock().expect("服务器仓库锁中毒");
    // 只读 Content-Length 声明的那一段：`finish()` 的"尾部不许有多余字节"探针若直接读
    // 套接字，会在客户端还等响应时多等一个超时（实测 Windows 上就是 20 s 的 WSAETIMEDOUT）。
    let outcome = read_publish_body(&mut *reader, request.length, state.limits, repo.store());
    let received = match outcome {
        Ok(received) => received,
        Err(err) => {
            repo.record_deny(
                "publish",
                err.kind(),
                &err.to_string(),
                serde_json::json!({"ref": name, "tip": tip.to_hex()}),
            );
            drop(repo);
            return respond_remote(reader.get_mut(), &err);
        }
    };
    match crate::remote::accept_publish(&mut repo, name, &tip) {
        Ok(previous) => {
            let _ = previous;
            drop(repo);
            respond_json_value(
                reader.get_mut(),
                200,
                &serde_json::json!({
                    "ok": true,
                    "ref": name,
                    "commit": tip.to_hex(),
                    "received": received,
                }),
            )
        }
        Err(err) => {
            repo.record_deny(
                "publish",
                err.kind(),
                &err.to_string(),
                serde_json::json!({"ref": name, "tip": tip.to_hex()}),
            );
            drop(repo);
            respond_remote(reader.get_mut(), &err)
        }
    }
}

/// 提前拒绝时最多排空多少请求体。超过就直关闭：宁可让客户端看到 RST，
/// 也不为了回一条 JSON 把 256 MiB body 读进内存/带宽。
const DRAIN_LIMIT: u64 = 1024 * 1024;

/// 读掉一小段请求体，避免"服务端没读完就关连接"在 Windows 上变成 RST（连回执一起丢）。
fn drain_body<R: Read>(reader: R, length: u64) {
    if length == 0 || length > DRAIN_LIMIT {
        return;
    }
    let mut limited = reader.take(length);
    let _ = std::io::copy(&mut limited, &mut std::io::sink());
}

/// 提前拒绝的统一出口：先排空（有上限），再回 JSON。
fn reject_json(
    reader: &mut BufReader<TcpStream>,
    request: &Request,
    status: u16,
    kind: &str,
    message: &str,
    extra: &[(&str, &str)],
) -> Result<(), NetError> {
    drain_body(&mut *reader, request.length);
    respond_json(reader.get_mut(), status, kind, message, extra)
}

/// 读一段 `Content-Length` 限定的对象流并逐块入库，返回收到的对象数。
fn read_publish_body<R: Read>(
    reader: R,
    length: u64,
    limits: Limits,
    store: &crate::store::Store,
) -> Result<usize, crate::remote::RemoteError> {
    let mut limited = reader.take(length);
    let mut wire_reader = wire::Reader::open(&mut limited, limits)?;
    let mut received = 0usize;
    while wire_reader.next(store)?.is_some() {
        received += 1;
    }
    wire_reader.finish()?;
    Ok(received)
}

fn pull(stream: &mut TcpStream, request: &Request, state: &Arc<State>) -> Result<(), NetError> {
    let Some(name) = request.query.get("ref") else {
        return respond_json(stream, 400, "bad_request", "pull 需要 ?ref=NAME", &[]);
    };
    let prefix = request
        .query
        .get("prefix")
        .map(String::as_str)
        .filter(|p| !p.is_empty());
    let repo = state.repo.lock().expect("服务器仓库锁中毒");
    let plan = match crate::remote::pull_plan(&repo, name, prefix) {
        Ok(plan) => plan,
        Err(err) => return respond_remote(stream, &err),
    };
    let total = match plan.body.byte_len(repo.store()) {
        Ok(total) => total,
        Err(err) => return respond_remote(stream, &err.into()),
    };
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\ncontent-length: {total}\r\n\
         x-trit-ref: {name}\r\nx-trit-tip: {}\r\nx-trit-manifest: {}\r\nx-trit-files: {}\r\n\
         x-trit-objects: {}\r\nconnection: close\r\n\r\n",
        plan.tip.to_hex(),
        plan.manifest.to_hex(),
        plan.files,
        plan.body.count()
    );
    stream.write_all(head.as_bytes())?;
    if let Err(err) = plan.body.write(repo.store(), &mut *stream) {
        // 头已经发出去了，只能在流上直接断；客户端会读到截断并判红。
        return Err(NetError::Wire(err.to_string()));
    }
    Ok(())
}

struct Request {
    method: String,
    path: String,
    query: BTreeMap<String, String>,
    headers: BTreeMap<String, String>,
    length: u64,
}

fn read_request(reader: &mut BufReader<TcpStream>) -> Result<Option<Request>, NetError> {
    let mut head_bytes = 0usize;
    let mut first = String::new();
    if reader.read_line(&mut first)? == 0 {
        return Ok(None);
    }
    head_bytes += first.len();
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();
    let version = parts.next().unwrap_or_default().to_string();
    if method.is_empty() || target.is_empty() {
        return Err(NetError::BadRequestLine(first.trim().to_string()));
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(NetError::BadVersion(version));
    }
    let (path, query) = split_target(&target);
    let mut headers = BTreeMap::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        head_bytes += line.len();
        if head_bytes > MAX_HEAD_BYTES {
            return Err(NetError::HeadTooLarge);
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        let Some((name, value)) = trimmed.split_once(':') else {
            return Err(NetError::BadRequestLine(trimmed.to_string()));
        };
        let name = name.trim().to_ascii_lowercase();
        if headers.contains_key(&name) {
            return Err(NetError::BadRequestLine(format!("重复的头：{name}")));
        }
        if headers.len() >= MAX_HEADERS {
            return Err(NetError::TooManyHeaders);
        }
        headers.insert(name, value.trim().to_string());
    }
    if let Some(encoding) = headers.get("transfer-encoding") {
        return Err(NetError::BadTransferEncoding(encoding.clone()));
    }
    let length = match headers.get("content-length") {
        Some(raw) => raw
            .parse::<u64>()
            .map_err(|_| NetError::BadRequestLine(format!("Content-Length 不合法：{raw}")))?,
        None if method == "POST" => return Err(NetError::MissingLength),
        None => 0,
    };
    Ok(Some(Request {
        method,
        path,
        query,
        headers,
        length,
    }))
}

fn split_target(target: &str) -> (String, BTreeMap<String, String>) {
    let (path, raw_query) = match target.split_once('?') {
        Some((path, query)) => (path, query),
        None => (target, ""),
    };
    let mut query = BTreeMap::new();
    for pair in raw_query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = match pair.split_once('=') {
            Some((key, value)) => (key, value),
            None => (pair, ""),
        };
        query.insert(percent_decode(key), percent_decode(value));
    }
    (path.to_string(), query)
}

fn percent_decode(raw: &str) -> String {
    let mut out = Vec::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hex = &raw[index + 1..index + 3];
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    out.push(byte);
                    index += 3;
                    continue;
                }
                out.push(bytes[index]);
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

/// 常量时间比较：先比长度，再逐字节 xor 累积；不因为第一个字节不同就提前返回。
fn token_eq(headers: &BTreeMap<String, String>, expected: &str) -> bool {
    let Some(raw) = headers.get("authorization") else {
        return false;
    };
    let Some(token) = raw.strip_prefix("Bearer ") else {
        return false;
    };
    ct_eq(token.as_bytes(), expected.as_bytes())
}

pub fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

fn respond_json(
    stream: &mut TcpStream,
    status: u16,
    kind: &str,
    message: &str,
    extra: &[(&str, &str)],
) -> Result<(), NetError> {
    let value = serde_json::json!({"ok": status < 400, "kind": kind, "message": message});
    respond_with_headers(stream, status, &value, extra)
}

fn respond_json_value(
    stream: &mut TcpStream,
    status: u16,
    value: &serde_json::Value,
) -> Result<(), NetError> {
    respond_with_headers(stream, status, value, &[])
}

fn respond_with_headers(
    stream: &mut TcpStream,
    status: u16,
    value: &serde_json::Value,
    extra: &[(&str, &str)],
) -> Result<(), NetError> {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Payload Too Large",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n",
        body.len()
    );
    for (name, value) in extra {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(&body)?;
    Ok(())
}

fn respond_remote(
    stream: &mut TcpStream,
    err: &crate::remote::RemoteError,
) -> Result<(), NetError> {
    let status = err.status();
    respond_json(stream, status, err.kind(), &err.to_string(), &[])
}

// ---- 客户端 ----

mod client;
pub use client::{Client, PullReply};

// ---- 客户端共用的 URL 助手 ----

fn normalize_base(raw: &str) -> Result<String, NetError> {
    let trimmed = raw.trim().trim_end_matches('/');
    let Some(rest) = trimmed.strip_prefix("http://") else {
        return Err(NetError::NotHttp(trimmed.to_string()));
    };
    if rest.is_empty() {
        return Err(NetError::NotHttp(trimmed.to_string()));
    }
    // 只要 host[:port]；带路径的 base 直接拒（避免把请求发到别的前缀上）。
    if rest.contains('/') {
        return Err(NetError::NotHttp(format!("base 只能到端口：{trimmed}")));
    }
    if !rest.contains(':') {
        return Err(NetError::MissingPort(trimmed.to_string()));
    }
    Ok(format!("http://{rest}"))
}

fn percent_encode(raw: &str) -> String {
    raw.bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':') {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

#[cfg(test)]
mod tests;
