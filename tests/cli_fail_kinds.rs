//! CLI 层每条 FAIL 的形状：带档位、带至少一条可直接执行的下一步。
//!
//! 判据钉的是**形状**而不是条数 —— 以后多加一档也不会顶穿这条断言。
//! 这一层以前只有 `fail(format!(...))` 的一句话文案：智能体读到"需要 -m <说明>"
//! 不知道整条命令长什么样，读到"某文件: 拒绝访问"不知道属于哪张面。

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_trit-vcs")
}

fn run(root: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        // 认索引那条会读这个环境变量；别人机器上恰好配了它会让"没给参数"这条变成另一种失败。
        .env_remove("TRIT_TECHMAP")
        .current_dir(root)
        .output()
        .expect("启动 trit-vcs 失败")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("trit-vcs-kind-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// 一条 FAIL 判决面：`FAIL <原话>（<档位>）` + `下一步 1. <命令>`。
///
/// 断言分三层，缺任何一层都算这条没测到：档位对不对、有没有下一步、FAIL 行是不是以 `）` 收尾
/// （收尾了才说明档位没被后面的文字挤掉）。
fn check(root: &Path, args: &[&str], kind: &str) {
    let out = run(root, args);
    let text = stderr(&out);
    assert!(!out.status.success(), "{args:?} 本该判失败：{text}");
    let line = text
        .lines()
        .find(|line| line.starts_with("FAIL"))
        .unwrap_or_else(|| panic!("{args:?} 没打 FAIL 行：{text}"));
    assert!(
        line.contains(&format!("（{kind}）")),
        "{args:?} 档位不对，期望（{kind}），实际：{line}"
    );
    assert!(
        line.trim_end().ends_with("）"),
        "{args:?} 的 FAIL 行没以档位收尾：{line}"
    );
    assert!(
        text.contains("下一步 1. "),
        "{args:?}（{kind}）没给可执行的下一步：{text}"
    );
}

#[test]
fn every_cli_failure_names_its_kind_and_next_step() {
    let root = temp("kinds");
    assert!(run(&root, &["init"]).status.success());
    fs::write(root.join("a.txt"), "a\n").unwrap();

    // 参数面（cli_usage）：三条各缺一样，下一步都得是补齐后的整条命令
    check(&root, &["commit", "--owner", "qoder:1"], "cli_usage");
    check(&root, &["commit", "-m", "做了什么"], "cli_usage");
    check(
        &root,
        &[
            "commit",
            "-m",
            "做了什么",
            "--owner",
            "qoder:1",
            "--accept",
            "判据",
        ],
        "cli_usage",
    );
    // 既没暂存也没提交 —— 也是 cli_usage，但文案与下一步不同（add 而不是补参数）
    check(
        &root,
        &["witness", "--", "definitely-not-a-command"],
        "cli_usage",
    );

    // 本地文件面（cli_local_io）：见证文件读不到
    check(
        &root,
        &[
            "commit",
            "-m",
            "x",
            "--owner",
            "qoder:1",
            "--witness",
            "nope.bin",
        ],
        "cli_local_io",
    );

    // 认领表面（cli_claims_unreadable）：文件不存在 / 不是合法 JSON 都归这一档
    check(
        &root,
        &[
            "commit",
            "-m",
            "x",
            "--owner",
            "qoder:1",
            "--claims",
            "nope.json",
        ],
        "cli_claims_unreadable",
    );
    fs::write(root.join("bad.json"), "{ 不是数组 }").unwrap();
    check(
        &root,
        &[
            "commit", "-m", "x", "--owner", "qoder:1", "--claims", "bad.json",
        ],
        "cli_claims_unreadable",
    );

    // 路径面：不在仓库里的绝对路径 ⇒ 相对路径算不出来
    let outside =
        std::env::temp_dir().join(format!("trit-vcs-kind-outside-{}", std::process::id()));
    let _ = fs::remove_dir_all(&outside);
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("c.txt"), "c\n").unwrap();
    check(
        &root,
        &["add", &outside.join("c.txt").to_string_lossy()],
        "cli_path_outside_repo",
    );
    // 目标根本不存在
    check(&root, &["add", "没有这个文件.txt"], "cli_path_missing");

    // 索引面（techmap）：没给参数 / 给了但读不到
    check(&root, &["where", "a.txt"], "cli_usage");
    check(
        &root,
        &["where", "a.txt", "--techmap", "nope.json"],
        "cli_techmap_unreadable",
    );

    // 坏 index：树 id 不是合法十六进制 ⇒ 档位要说清是索引坏了，不是对象库坏了
    fs::write(
        root.join(".tritvcs").join("index.json"),
        r#"{"tree":"zz-not-hex","paths":["a.txt"]}"#,
    )
    .unwrap();
    check(
        &root,
        &["witness", "--", "definitely-not-a-command"],
        "cli_index_bad_tree",
    );

    // 库层错误透传：index.json 连 JSON 都不是 ⇒ 走 RepoError 那一支，
    // 档位与下一步必须由库里那份决定（这里不许自己编一档，否则两份规则迟早分叉）。
    fs::write(root.join(".tritvcs").join("index.json"), "{ 不是合法 JSON ").unwrap();
    check(
        &root,
        &["witness", "--", "definitely-not-a-command"],
        "bad_head",
    );

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&outside);
}

/// 反证：正例不许带 FAIL 行（否则上面的形状断言会因为"什么都红"而假过）。
#[test]
fn a_good_command_still_passes_without_a_fail_line() {
    let root = temp("positive");
    assert!(run(&root, &["init"]).status.success());
    fs::write(root.join("a.txt"), "a\n").unwrap();
    let out = run(&root, &["add", "a.txt"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        !stderr(&out).contains("FAIL"),
        "正例不该出现 FAIL：{}",
        stderr(&out)
    );
    let _ = fs::remove_dir_all(&root);
}
