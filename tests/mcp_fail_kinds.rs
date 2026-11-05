//! MCP 工具面的失败形状：`_meta.kind` 非空、`_meta.next_steps` 至少一条、正文里也带编号命令。
//!
//! 这一面以前返回 `Result<Value, String>`：库层的 `WorktreeError` / `BundleError` / `RepoError`
//! 在 `map_err(|err| err.to_string())` 处被抹平成一句话 ⇒ 智能体既分不出是哪张面，也拿不到解锁命令。
//! 判据钉形状，不钉条数：将来多加一档不会顶穿。

use std::fs;
use std::path::PathBuf;

use serde_json::{Value, json};
use trit_vcs::mcp::Mcp;
use trit_vcs::repo::Repo;

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("trit-vcs-mcpkind-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn call(mcp: &mut Mcp, tool: &str, args: Value) -> Value {
    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": args},
    });
    mcp.dispatch(&request)
        .expect("tools/call 必须有响应")
        .get("result")
        .cloned()
        .expect("响应里要有 result")
}

/// 一条失败：档位对不对 + 至少一条下一步 + 正文里有编号命令（客户端只看 content 也够用）。
fn check_failure(mcp: &mut Mcp, tool: &str, args: Value, kind: &str) {
    let result = call(mcp, tool, args.clone());
    assert_eq!(result["isError"], true, "{tool} {args} 本该失败：{result}");
    assert_eq!(
        result["_meta"]["kind"], kind,
        "{tool} {args} 档位不对：{result}"
    );
    let steps = result["_meta"]["next_steps"]
        .as_array()
        .unwrap_or_else(|| panic!("{tool} {args} 没有 next_steps：{result}"));
    assert!(!steps.is_empty(), "{tool} {args} 的 next_steps 是空的");
    let text = result["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        text.contains("下一步 1. "),
        "{tool} {args} 的正文里没有编号命令：{text}"
    );
    assert!(
        result["_meta"]["usage"]["tokens_est"].as_u64().unwrap_or(0) > 0,
        "失败也要报读数"
    );
}

#[test]
fn mcp_failures_carry_kind_and_next_steps() {
    let root = temp("kinds");
    let mut mcp = Mcp::new(Repo::init(&root).unwrap());

    // CLI 自判的档位
    check_failure(&mut mcp, "nope", json!({}), "mcp_unknown_tool");
    check_failure(&mut mcp, "explain", json!({}), "mcp_bad_args");
    check_failure(&mut mcp, "explain", json!({"commit": "zz"}), "mcp_bad_args");
    check_failure(&mut mcp, "add", json!({"paths": []}), "mcp_bad_args");
    check_failure(
        &mut mcp,
        "add",
        json!({"paths": ["nope.txt"]}),
        "mcp_path_missing",
    );
    check_failure(
        &mut mcp,
        "bundle_import",
        json!({"bundle": "nope.bundle"}),
        "mcp_local_io",
    );

    // 库层错误的档位**原样透传**：这里不许自己编一档（两份规则迟早分叉）。
    // 注意判决顺序：`commit_at` 先读对象 ⇒ 不存在的 id 会先落到 `store_missing_object`
    // （库里就是这么判的），而不是 `unknown_commit` —— 这正是透传要保住的细节。
    let zeros = "0".repeat(64);
    check_failure(
        &mut mcp,
        "explain",
        json!({"commit": zeros}),
        "store_missing_object",
    );
    check_failure(
        &mut mcp,
        "commit",
        json!({"message": "空仓提交", "session": "qoder:test"}),
        "nothing_staged",
    );

    // 正例反证：不红的时候不许带 kind / next_steps（否则上面的形状断言会因为"什么都红"而假过）
    let ok = call(&mut mcp, "status", json!({}));
    assert_eq!(ok["isError"], false, "{ok}");
    assert!(ok["_meta"]["kind"].is_null(), "正例不该带 kind：{ok}");
    assert!(
        ok["_meta"]["next_steps"].is_null(),
        "正例不该带 next_steps：{ok}"
    );

    let _ = fs::remove_dir_all(&root);
}
