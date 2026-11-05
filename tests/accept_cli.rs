//! `--verify-accept`：默认关、要认领、命令形状把关、失败就不放行。
//!
//! 这条面的每一条断言都对着一个具体后果：
//!  · 默认关 ⇒ 不带开关时命令**一次都不许被执行**（用会落盘的 canary 证，不看文案）；
//!  · 要认领 ⇒ 不在在效认领里的改动不执行；
//!  · 命令形状 ⇒ 带 shell 元字符直接拒（判据是 argv，不是脚本）；
//!  · 红判据 ⇒ 退出码非 0 且带 `accept_failed` 档位与下一步。

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("trit-vcs-accept-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// 仓里有一个已提交的 `a.txt`，随后又改了它并重新暂存 ⇒ preflight 的改动路径非空。
fn seed(root: &Path) {
    assert!(run(root, &["init"]).status.success());
    fs::write(root.join("a.txt"), "first\n").unwrap();
    assert!(run(root, &["add", "a.txt"]).status.success());
    let commit = run(
        root,
        &[
            "commit",
            "-m",
            "底座",
            "--owner",
            "qoder:test",
            "--allow-unclaimed",
        ],
    );
    assert!(commit.status.success(), "{}", stderr(&commit));
    fs::write(root.join("a.txt"), "second\n").unwrap();
    assert!(run(root, &["add", "a.txt"]).status.success());
}

fn claims(root: &Path, paths: &str) -> PathBuf {
    let path = root.join("claims.json");
    fs::write(
        &path,
        format!(
            r#"[{{"id":"c1","owner":"qoder:test","paths":{paths},"acquired_at":1,"expires_at":4000000000}}]"#
        ),
    )
    .unwrap();
    path
}

fn preflight(root: &Path, accept: &str, extra: &[&str]) -> Output {
    let mut args = vec![
        "preflight",
        "-m",
        "验判据",
        "--owner",
        "qoder:test",
        "--goal",
        "判据要能跑",
        "--accept",
        accept,
    ];
    args.extend_from_slice(extra);
    run(root, &args)
}

#[test]
fn accept_is_off_by_default_and_failures_stop_the_preflight() {
    let root = temp("default");
    seed(&root);
    let table = claims(&root, r#"["a.txt"]"#);
    let table_arg = table.to_string_lossy().to_string();

    // 1) 不开关：同一个红命令也不跑，预检照旧通过。
    //    `--allow-unclaimed` 是给**提交门**的：这一条验的是"判据没被执行"，别让另一道门的红搅进来。
    let off = preflight(
        &root,
        "cargo --definitely-not-a-flag",
        &["--allow-unclaimed"],
    );
    assert!(off.status.success(), "默认关时预检不该红：{}", stderr(&off));
    assert!(
        !stderr(&off).contains("判据"),
        "默认关时不该有判据读数：{}",
        stderr(&off)
    );

    // 2) 开关 + 过
    let ok = preflight(
        &root,
        "cargo --version",
        &["--verify-accept", "--claims", &table_arg],
    );
    assert!(ok.status.success(), "判据该过：{}", stderr(&ok));
    assert!(stderr(&ok).contains("判据 过"), "{}", stderr(&ok));
    assert!(stderr(&ok).contains("全过"), "{}", stderr(&ok));

    // 3) 开关 + 红 ⇒ 退出码非 0、带档位与下一步
    let red = preflight(
        &root,
        "cargo --definitely-not-a-flag",
        &["--verify-accept", "--claims", &table_arg],
    );
    assert!(!red.status.success(), "红判据必须拦：{}", stderr(&red));
    let text = stderr(&red);
    assert!(text.contains("（accept_failed）"), "{text}");
    assert!(text.contains("下一步 1. "), "{text}");
    assert!(text.contains("判据 没过"), "{text}");

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn accept_refuses_to_run_without_claim_coverage() {
    let root = temp("guard");
    seed(&root);
    let canary = root.join("canary");
    let canary_cmd = format!("{} init --repo {}", bin(), canary.display());

    // 没给认领表 ⇒ 不跑（canary 目录不存在就是"一次都没执行"）
    let no_claims = preflight(&root, &canary_cmd, &["--verify-accept"]);
    assert!(!no_claims.status.success(), "{}", stderr(&no_claims));
    assert!(
        stderr(&no_claims).contains("（accept_needs_claims）"),
        "{}",
        stderr(&no_claims)
    );
    assert!(
        !canary.exists(),
        "没给认领表也把命令跑了：{}",
        canary.display()
    );

    // 认领表覆盖的是别的路径 ⇒ 不跑
    let elsewhere = claims(&root, r#"["other.txt"]"#);
    let elsewhere_arg = elsewhere.to_string_lossy().to_string();
    let uncovered = preflight(
        &root,
        &canary_cmd,
        &["--verify-accept", "--claims", &elsewhere_arg],
    );
    assert!(!uncovered.status.success(), "{}", stderr(&uncovered));
    assert!(
        stderr(&uncovered).contains("（accept_unclaimed）"),
        "{}",
        stderr(&uncovered)
    );
    assert!(!canary.exists(), "认领没覆盖时也把命令跑了");

    // 带 shell 元字符 ⇒ 不跑（判据是 argv，不是脚本）
    let meta_cmd = format!("{} init --repo {}", bin(), canary.display());
    let with_meta = format!("{meta_cmd} > out.txt");
    let covered = claims(&root, r#"["a.txt"]"#);
    let covered_arg = covered.to_string_lossy().to_string();
    let meta = preflight(
        &root,
        &with_meta,
        &["--verify-accept", "--claims", &covered_arg],
    );
    assert!(!meta.status.success(), "{}", stderr(&meta));
    assert!(
        stderr(&meta).contains("（accept_shell_meta）"),
        "{}",
        stderr(&meta)
    );
    assert!(!canary.exists(), "含元字符的命令也被执行了");

    // 覆盖到位 ⇒ 真的跑了（canary 出现），这才证明前面三条的"没跑"不是空转
    let ran = preflight(
        &root,
        &canary_cmd,
        &["--verify-accept", "--claims", &covered_arg],
    );
    assert!(ran.status.success(), "{}", stderr(&ran));
    assert!(
        canary.join(".tritvcs").is_dir(),
        "正例没真执行：{}",
        canary.display()
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn accept_timeout_is_a_failure_not_a_skip() {
    let root = temp("timeout");
    seed(&root);
    let table = claims(&root, r#"["a.txt"]"#);
    let table_arg = table.to_string_lossy().to_string();
    #[cfg(windows)]
    let sleeper = "cmd /c ping -n 20 127.0.0.1";
    #[cfg(unix)]
    let sleeper = "sleep 20";

    let out = preflight(
        &root,
        sleeper,
        &[
            "--verify-accept",
            "--claims",
            &table_arg,
            "--accept-timeout",
            "1",
        ],
    );
    assert!(!out.status.success(), "超时算没通过：{}", stderr(&out));
    let text = stderr(&out);
    assert!(text.contains("（accept_failed）"), "{text}");
    assert!(text.contains("超时"), "{text}");

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_judgement_that_writes_the_repo_is_red() {
    let root = temp("mutates");
    seed(&root);
    let table = claims(&root, r#"["a.txt"]"#);
    let table_arg = table.to_string_lossy().to_string();
    // 判据自己提交一笔 ⇒ 对象库与 HEAD 都变了，必须判红（判据不许写仓库）。
    let mutator = format!(
        "{} commit -m 判据越界 --owner qoder:test --allow-unclaimed",
        bin()
    );

    let out = preflight(
        &root,
        &mutator,
        &["--verify-accept", "--claims", &table_arg],
    );
    assert!(
        !out.status.success(),
        "写仓库的判据必须拦：{}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("（accept_mutated_repo）"),
        "{}",
        stderr(&out)
    );

    let _ = fs::remove_dir_all(&root);
}
