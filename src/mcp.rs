//! MCP 工具面 v0：stdio JSON-RPC 2.0、13 个工具、每个响应带 token 估算，
//! 且都能接 `budget`（读数上限）与 `commit.dry_run`（写前预检）。
//!
//! 目标不是"再包一层 CLI"，而是让智能体**一次调用拿到结构化结论**：状态、提交、冲突对象、准入、
//! 传输、反查都在这里；schema 尽量短（工具描述本身就是上下文成本）。
//! 传输用 MCP stdio 的换行分隔 JSON；没有网络面。

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{Value, json};

use crate::bundle;
use crate::gate::ClaimSpec;
use crate::hash::Hash;
use crate::merge;
use crate::model::Intent;
use crate::remediation::{self, Context};
use crate::repo::{CommitFilter, CommitRequest, Repo};
use crate::techmap::{Techmap, test_command};
use crate::tokens::{cap_rows, estimate};
use crate::worktree;

pub const PROTOCOL_VERSION: &str = "2024-11-05";

fn tool(name: &str, description: &str, props: Value, required: &[&str]) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": {"type": "object", "properties": props, "required": required},
    })
}

/// 工具清单（13 个；改数量必须同时改测试断言）。
pub fn tools() -> Vec<Value> {
    vec![
        tool(
            "status",
            "工作树 vs HEAD：改动列表 + stat 缓存读数",
            json!({}),
            &[],
        ),
        tool(
            "log",
            "按 tag/evidence/session/grep 过滤提交",
            json!({
                "tag": {"type": "string"}, "evidence": {"type": "string"},
                "session": {"type": "string"}, "grep": {"type": "string"},
                "limit": {"type": "integer"},
            }),
            &[],
        ),
        tool(
            "explain",
            "提交的会话/证据/见证/意图 + techmap 技术与测试命令",
            json!({"commit": {"type": "string"}, "techmap": {"type": "string"}}),
            &["commit"],
        ),
        tool(
            "add",
            "暂存路径（文件或目录）",
            json!({"paths": {"type": "array", "items": {"type": "string"}}}),
            &["paths"],
        ),
        tool(
            "commit",
            "提交暂存区；默认拒绝未认领（allow_unclaimed=true 才放行）；dry_run=true 只判决不写盘，被拒时文本里直接给下一步命令",
            json!({
                "message": {"type": "string"}, "session": {"type": "string"},
                "tags": {"type": "array", "items": {"type": "string"}},
                "evidence": {"type": "array", "items": {"type": "string"}},
                "goal": {"type": "string"},
                "accept": {"type": "array", "items": {"type": "string"}},
                "witness_path": {"type": "string"},
                "allow_unclaimed": {"type": "boolean"},
                "dry_run": {"type": "boolean"},
            }),
            &["message", "session"],
        ),
        tool(
            "diff",
            "两个提交的路径级差异",
            json!({"from": {"type": "string"}, "to": {"type": "string"}}),
            &["from", "to"],
        ),
        tool(
            "merge",
            "三方合并；冲突返回结构化对象（无冲突标记）",
            json!({"ours": {"type": "string"}, "theirs": {"type": "string"}, "base": {"type": "string"}}),
            &["ours", "theirs"],
        ),
        tool(
            "admit",
            "合并准入：见证必须绑该提交树且通过",
            json!({"commit": {"type": "string"}, "witness_path": {"type": "string"}}),
            &["commit", "witness_path"],
        ),
        tool(
            "bundle_export",
            "导出块级包；prefix 只发一个目录，dest 跳过目标已有对象",
            json!({"tree": {"type": "string"}, "out": {"type": "string"},
                   "prefix": {"type": "string"}, "dest": {"type": "string"}}),
            &["tree", "out"],
        ),
        tool(
            "bundle_import",
            "导入块级包（已有块跳过，逐块校验）",
            json!({"bundle": {"type": "string"}}),
            &["bundle"],
        ),
        tool(
            "where",
            "techmap 反查：路径/测试/标签 → 技术条目",
            json!({"needle": {"type": "string"}, "techmap": {"type": "string"}}),
            &["needle", "techmap"],
        ),
        tool(
            "tests",
            "techmap 反查后的可跑测试命令",
            json!({"needle": {"type": "string"}, "techmap": {"type": "string"}}),
            &["needle", "techmap"],
        ),
        tool("verify", "对象库/事件链/见证体检", json!({}), &[]),
    ]
    .into_iter()
    .map(with_budget)
    .collect()
}

/// 给每个工具的入参补一个 `budget`（元）：超上限时从尾部丢整行，并把丢了多少写回读数。
fn with_budget(mut entry: Value) -> Value {
    entry["inputSchema"]["properties"]["budget"] = json!({
        "type": "integer",
        "minimum": 1,
        "description": "读数上限（元）",
    });
    entry
}

fn ok_result(value: Value) -> Value {
    let text = serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string());
    json!({
        "content": [{"type": "text", "text": text}],
        "isError": false,
        "_meta": {"usage": {"bytes": text.len(), "tokens_est": estimate(&text)}},
    })
}

/// MCP 工具面的一条失败：与 CLI 同形状 —— 档位 + 至少一条下一步。
///
/// 以前工具面返回 `String`：库层的 `WorktreeError` / `BundleError` 在 `map_err(|e| e.to_string())`
/// 那里被抹平成一句话，智能体读到"某文件: 拒绝访问"既分不出是哪张面、也拿不到解锁命令。
pub struct McpFail {
    kind: String,
    message: String,
    next: Vec<String>,
}

impl McpFail {
    pub fn new(kind: &str, message: impl Into<String>, next: Vec<String>) -> Self {
        Self {
            kind: kind.to_string(),
            message: message.into(),
            next,
        }
    }

    /// 库层错误原样带上来：档位与下一步归 `crate::remediation` 决定，这里不复制规则。
    pub fn from_error<E: remediation::Remediable + std::fmt::Display>(
        err: &E,
        ctx: Context<'_>,
    ) -> Self {
        Self {
            kind: err.kind().to_string(),
            message: err.to_string(),
            next: err.commands(ctx),
        }
    }

    pub fn local_io(path: &str, err: &std::io::Error) -> Self {
        Self::new(
            "mcp_local_io",
            format!("{path}: {err}"),
            vec![
                format!("确认 {path} 可读写；换一个工作目录内的路径再试"),
                "读不到的对象不做猜测：先 `verify` 看对象库本身有没有缺块".to_string(),
            ],
        )
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn next_steps(&self) -> &[String] {
        &self.next
    }
}

impl std::fmt::Display for McpFail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

fn err_result(fail: McpFail) -> Value {
    let mut text = fail.message.clone();
    for (index, command) in fail.next.iter().enumerate() {
        text.push_str(&format!("\n  下一步 {}. {command}", index + 1));
    }
    json!({
        "content": [{"type": "text", "text": text}],
        "isError": true,
        "_meta": {
            "kind": fail.kind,
            "next_steps": fail.next,
            "usage": {"bytes": text.len(), "tokens_est": estimate(&text)},
        },
    })
}

fn arg<'a>(args: &'a Value, name: &str) -> Option<&'a str> {
    args.get(name).and_then(Value::as_str)
}

/// 必填参数：缺了就判 `mcp_bad_args`，下一步直接说清这个工具要什么。
fn need<'a>(args: &'a Value, name: &str) -> Result<&'a str, McpFail> {
    arg(args, name).ok_or_else(|| {
        McpFail::new(
            "mcp_bad_args",
            format!("缺少 {name}"),
            vec![
                format!("这个工具要 {name}；`tools/list` 里有 schema"),
                "把上一轮成功调用的参数照抄再把这一项补上".to_string(),
            ],
        )
    })
}

fn arg_strings(args: &Value, name: &str) -> Vec<String> {
    args.get(name)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn hex(value: &str, what: &str) -> Result<Hash, McpFail> {
    Hash::from_hex(value).ok_or_else(|| {
        McpFail::new(
            "mcp_bad_args",
            format!("{what} 不是合法 id：{value}"),
            vec!["先用 `log` 拿最近的提交 id（十六进制），再把同一条传回来".to_string()],
        )
    })
}

fn collect(root: &Path, targets: &[String]) -> Result<BTreeMap<String, Vec<u8>>, McpFail> {
    let mut out = BTreeMap::new();
    let mut stack: Vec<std::path::PathBuf> =
        targets.iter().map(|target| root.join(target)).collect();
    while let Some(path) = stack.pop() {
        if path.is_dir() {
            for entry in std::fs::read_dir(&path)
                .map_err(|err| McpFail::local_io(&path.display().to_string(), &err))?
            {
                let entry =
                    entry.map_err(|err| McpFail::local_io(&path.display().to_string(), &err))?;
                let name = entry.file_name().to_string_lossy().to_string();
                if name == ".tritvcs" || name == ".git" {
                    continue;
                }
                stack.push(entry.path());
            }
        } else if path.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|_| {
                    McpFail::new(
                        "mcp_path_outside_repo",
                        format!("不在仓库内：{}", path.display()),
                        vec![format!("用仓库根 `{}` 之下的相对路径", root.display())],
                    )
                })?
                .to_string_lossy()
                .replace('\\', "/");
            out.insert(
                rel,
                std::fs::read(&path)
                    .map_err(|err| McpFail::local_io(&path.display().to_string(), &err))?,
            );
        } else {
            return Err(McpFail::new(
                "mcp_path_missing",
                format!("找不到：{}", path.display()),
                vec!["路径是相对仓库根的；目录会递归展开（`.tritvcs` 与 `.git` 跳过）".to_string()],
            ));
        }
    }
    Ok(out)
}

fn techmap(args: &Value) -> Result<Techmap, McpFail> {
    let path = arg(args, "techmap")
        .map(str::to_string)
        .or_else(|| std::env::var("TRIT_TECHMAP").ok())
        .ok_or_else(|| {
            McpFail::new(
                "mcp_bad_args",
                "需要 techmap 路径",
                vec!["给 techmap 参数（或设 TRIT_TECHMAP）指向索引文件".to_string()],
            )
        })?;
    Techmap::load(&path).map_err(|err| {
        McpFail::new(
            "mcp_techmap_unreadable",
            format!("{path}: {err}"),
            vec!["确认这个文件是 techmap 导出的 JSON（不是仓库自己的对象库）".to_string()],
        )
    })
}

/// MCP 服务状态：持有一个打开的仓库。
pub struct Mcp {
    repo: Repo,
}

impl Mcp {
    pub fn new(repo: Repo) -> Self {
        Self { repo }
    }

    pub fn repo(&self) -> &Repo {
        &self.repo
    }

    /// 处理一条 JSON-RPC；通知返回 `None`。
    pub fn dispatch(&mut self, request: &Value) -> Option<Value> {
        let id = request.get("id")?.clone();
        let method = request.get("method").and_then(Value::as_str).unwrap_or("");
        let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
        match method {
            "initialize" => Some(json!({
                "jsonrpc": "2.0", "id": id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "trit-vcs", "version": env!("CARGO_PKG_VERSION")},
                }
            })),
            "ping" => Some(json!({"jsonrpc": "2.0", "id": id, "result": {}})),
            "tools/list" => {
                let tools = tools();
                let text = serde_json::to_string(&tools).unwrap_or_default();
                Some(json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": {
                        "tools": tools,
                        "_meta": {"usage": {"bytes": text.len(), "tokens_est": estimate(&text)}},
                    }
                }))
            }
            "tools/call" => {
                let name = params.get("name").and_then(Value::as_str).unwrap_or("");
                let args = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                let result = match self.call(name, &args) {
                    Ok(mut value) => {
                        if let Some(budget) = args.get("budget").and_then(Value::as_u64) {
                            cap_rows(&mut value, budget);
                        }
                        ok_result(value)
                    }
                    Err(fail) => err_result(fail),
                };
                Some(json!({"jsonrpc": "2.0", "id": id, "result": result}))
            }
            other => Some(json!({
                "jsonrpc": "2.0", "id": id,
                "error": {"code": -32601, "message": format!("未知方法：{other}")}
            })),
        }
    }

    fn ctx(&self) -> Context<'_> {
        Context {
            dir: self.repo.root(),
            session: "",
        }
    }

    fn call(&mut self, name: &str, args: &Value) -> Result<Value, McpFail> {
        match name {
            "status" => {
                let (changes, stats) = worktree::status_with_cache(&self.repo)
                    .map_err(|err| McpFail::from_error(&err, self.ctx()))?;
                Ok(json!({
                    "changes": changes,
                    "hashed": stats.hashed,
                    "cached": stats.cached,
                }))
            }
            "log" => {
                let filter = CommitFilter {
                    tag: arg(args, "tag").map(str::to_string),
                    evidence: arg(args, "evidence").map(str::to_string),
                    session: arg(args, "session").map(str::to_string),
                    grep: arg(args, "grep").map(str::to_string),
                };
                let limit = args
                    .get("limit")
                    .and_then(Value::as_u64)
                    .map(|n| n as usize)
                    .unwrap_or(20);
                let rows: Vec<Value> = self
                    .repo
                    .query(&filter)
                    .map_err(|err| McpFail::from_error(&err, self.ctx()))?
                    .into_iter()
                    .take(limit)
                    .map(|(id, commit)| {
                        json!({
                            "id": id.to_hex(), "tree": commit.tree.to_hex(),
                            "session": commit.session, "claims": commit.claims,
                            "evidence": commit.evidence, "tags": commit.tags,
                            "message": commit.message,
                            "witness": commit.witness.map(|w| w.to_hex()),
                            "intent": commit.intent.as_ref().map(|i| json!({
                                "goal": i.goal, "accept": i.accept,
                                "base": i.base.map(|b| b.to_hex()),
                            })),
                        })
                    })
                    .collect();
                Ok(json!({"commits": rows, "count": rows.len()}))
            }
            "explain" => {
                let id = hex(need(args, "commit")?, "commit")?;
                let commit = self
                    .repo
                    .commit_at(&id)
                    .map_err(|err| McpFail::from_error(&err, self.ctx()))?;
                let map = techmap(args)?;
                let entries = map.for_tags(&commit.tags);
                let mut tests = std::collections::BTreeSet::new();
                for entry in &entries {
                    for spec in &entry.tests {
                        tests.insert(test_command(spec).unwrap_or_else(|| spec.clone()));
                    }
                }
                Ok(json!({
                    "id": id.to_hex(), "tree": commit.tree.to_hex(),
                    "session": commit.session, "claims": commit.claims,
                    "tags": commit.tags, "evidence": commit.evidence,
                    "message": commit.message,
                    "witness": commit.witness.map(|w| w.to_hex()),
                    "intent": commit.intent.as_ref().map(|i| json!({
                        "goal": i.goal, "accept": i.accept,
                        "base": i.base.map(|b| b.to_hex()),
                    })),
                    "entries": entries,
                    "tests": tests.into_iter().collect::<Vec<_>>(),
                }))
            }
            "add" => {
                let paths = arg_strings(args, "paths");
                if paths.is_empty() {
                    return Err(McpFail::new(
                        "mcp_bad_args",
                        "paths 不能为空",
                        vec!["至少要给一个相对仓库根的路径（目录会递归展开）".to_string()],
                    ));
                }
                let files = collect(self.repo.root(), &paths)?;
                let (tree, put) = self
                    .repo
                    .stage(&files, now_secs())
                    .map_err(|err| McpFail::from_error(&err, self.ctx()))?;
                Ok(json!({
                    "tree": tree.to_hex(), "files": files.len(),
                    "new_chunks": put.new_chunks, "reused_chunks": put.reused_chunks,
                }))
            }
            "commit" => {
                let message = need(args, "message")?;
                let session = need(args, "session")?;
                let intent =
                    arg(args, "goal").map(|goal| Intent::new(goal, arg_strings(args, "accept")));
                let witness = match arg(args, "witness_path") {
                    Some(path) => {
                        Some(std::fs::read(path).map_err(|err| McpFail::local_io(path, &err))?)
                    }
                    None => None,
                };
                let request = CommitRequest {
                    message: message.to_string(),
                    session: session.to_string(),
                    claims: Vec::<ClaimSpec>::new(),
                    evidence: arg_strings(args, "evidence"),
                    tags: arg_strings(args, "tags"),
                    allow_unclaimed: args
                        .get("allow_unclaimed")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    witness,
                    intent,
                    parent_override: None,
                    now_secs: now_secs(),
                };
                // 判决段与 commit() 同源（preflight::decide），所以 dry_run 说放行就真放行
                if args
                    .get("dry_run")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    return match self.repo.preflight(&request) {
                        Ok(facts) => {
                            Ok(json!({"dry_run": true, "verdict": facts.verdict, "facts": facts}))
                        }
                        Err(err) => Err(McpFail::from_error(&err, self.ctx())),
                    };
                }
                let outcome = self
                    .repo
                    .commit(request)
                    .map_err(|err| McpFail::from_error(&err, self.ctx()))?;
                Ok(json!({"id": outcome.id.to_hex(), "verdict": outcome.verdict.label()}))
            }
            "diff" => {
                let from = hex(need(args, "from")?, "from")?;
                let to = hex(need(args, "to")?, "to")?;
                let changes = worktree::diff(&self.repo, &from, &to)
                    .map_err(|err| McpFail::from_error(&err, self.ctx()))?;
                Ok(json!({"changes": changes}))
            }
            "merge" => {
                let ours = hex(need(args, "ours")?, "ours")?;
                let theirs = hex(need(args, "theirs")?, "theirs")?;
                let base = match arg(args, "base") {
                    Some(value) => Some(hex(value, "base")?),
                    None => None,
                };
                let outcome = merge::merge(&self.repo, &ours, &theirs, base.as_ref())
                    .map_err(|err| McpFail::from_error(&err, self.ctx()))?;
                let conflicts: Vec<Value> = outcome
                    .conflicts
                    .iter()
                    .map(|conflict| {
                        let mut value = serde_json::to_value(conflict).unwrap_or_default();
                        value["object_bytes"] = json!(conflict.object_bytes());
                        value["id"] = json!(conflict.id().to_hex());
                        value
                    })
                    .collect();
                Ok(json!({
                    "tree": outcome.tree.map(|tree| tree.to_hex()),
                    "merged_files": outcome.merged_files,
                    "removed_files": outcome.removed_files,
                    "conflicts": conflicts,
                }))
            }
            "admit" => {
                let id = hex(need(args, "commit")?, "commit")?;
                let path = need(args, "witness_path")?;
                let bytes = std::fs::read(path).map_err(|err| McpFail::local_io(path, &err))?;
                let witness = self
                    .repo
                    .admit(&id, &bytes)
                    .map_err(|err| McpFail::from_error(&err, self.ctx()))?;
                let subject_tree = witness.subject_tree().map_err(|err| {
                    McpFail::new(
                        "mcp_witness_shape",
                        err.to_string(),
                        vec!["见证文件要用 `witness` 导出的那份；重跑一次再传回来".to_string()],
                    )
                })?;
                Ok(json!({
                    "admitted": true,
                    "tree": subject_tree.to_hex(),
                    "command": witness.predicate.command,
                    "exit": witness.predicate.exit,
                }))
            }
            "bundle_export" => {
                let tree = hex(need(args, "tree")?, "tree")?;
                let out_path = need(args, "out")?;
                let dest = match arg(args, "dest") {
                    Some(path) => Some(
                        Repo::open(path).map_err(|err| McpFail::from_error(&err, self.ctx()))?,
                    ),
                    None => None,
                };
                let mut file = std::fs::File::create(out_path)
                    .map_err(|err| McpFail::local_io(out_path, &err))?;
                let stats = bundle::export(
                    self.repo.store(),
                    tree,
                    arg(args, "prefix"),
                    dest.as_ref().map(|repo| repo.store()),
                    &mut file,
                )
                .map_err(|err| McpFail::from_error(&err, self.ctx()))?;
                Ok(json!({
                    "files": stats.files, "objects": stats.objects,
                    "sent_objects": stats.sent_objects,
                    "total_bytes": stats.total_bytes, "sent_bytes": stats.sent_bytes,
                }))
            }
            "bundle_import" => {
                let path = need(args, "bundle")?;
                let mut file =
                    std::fs::File::open(path).map_err(|err| McpFail::local_io(path, &err))?;
                let stats = bundle::import(self.repo.store(), &mut file)
                    .map_err(|err| McpFail::from_error(&err, self.ctx()))?;
                Ok(json!({
                    "received": stats.received, "skipped": stats.skipped,
                    "bytes": stats.bytes,
                    "tree": stats.tree.map(|tree| tree.to_hex()),
                }))
            }
            "where" => {
                let needle = need(args, "needle")?;
                let map = techmap(args)?;
                let hits = map.where_entries(needle);
                Ok(json!({"entries": hits, "count": hits.len()}))
            }
            "tests" => {
                let needle = need(args, "needle")?;
                let map = techmap(args)?;
                let mut seen = std::collections::BTreeSet::new();
                for entry in map.where_entries(needle) {
                    for spec in &entry.tests {
                        seen.insert(test_command(spec).unwrap_or_else(|| spec.clone()));
                    }
                }
                Ok(json!({"commands": seen.into_iter().collect::<Vec<_>>()}))
            }
            "verify" => {
                let report = self
                    .repo
                    .verify()
                    .map_err(|err| McpFail::from_error(&err, self.ctx()))?;
                Ok(json!({
                    "events": report.events, "objects": report.objects,
                    "commits": report.commits, "witnessed": report.witnessed,
                    "head": report.head,
                }))
            }
            other => Err(McpFail::new(
                "mcp_unknown_tool",
                format!("未知工具：{other}"),
                vec!["`tools/list` 看可用工具与它们的 schema".to_string()],
            )),
        }
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests;
