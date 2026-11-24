//! `trit-vcs audit`：审计员入口。默认 `audit status`，失败返回非零。
//!
//! 这里不重复实现对账逻辑，只做三件事：打开仓库、调 `trit_vcs::audit`、把结果按
//! “人读的一屏 / `--json` 的机器可分支对象”两种出口打出来。

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use trit_vcs::audit::{self, AuditError, AuditReport};
use trit_vcs::checkpoint::anchor::{self, AnchorOutcome};
use trit_vcs::checkpoint::consistency::{self, ConsistencyProof};
use trit_vcs::checkpoint::{merkle_proof, verify_merkle_proof};
use trit_vcs::hash::Hash;
use trit_vcs::repo::Repo;

use crate::cli_fail::CliFail;
use crate::verdict::{fail_err, fail_repo, print_json};
use crate::{flag, has, now_secs, repo_path};

pub(crate) fn audit_cmd(args: &[String]) -> ExitCode {
    let root = repo_path(args);
    let sub = args
        .get(1)
        .filter(|value| !value.starts_with("--"))
        .map(String::as_str)
        .unwrap_or("status");
    let repo = match sub {
        "log" | "show" | "checkpoint" => Repo::open(&root),
        _ => Repo::open_for_audit(&root),
    };
    let mut repo = match repo {
        Ok(repo) => repo,
        Err(err) => return fail_repo(&err, &root, "", args),
    };
    match sub {
        "status" | "verify" | "reconcile" => status_cmd(&repo, args),
        "log" => log_cmd(&repo, args),
        "show" => show_cmd(&repo, args),
        "checkpoint" => checkpoint_cmd(&mut repo, args),
        "proof" => proof_cmd(&repo, args),
        "consistency" => consistency_cmd(&repo, args),
        "verify-consistency" => verify_consistency_cmd(&repo, args),
        "anchor" => anchor_cmd(&repo, args),
        "verify-anchor" => verify_anchor_cmd(&repo, args),
        other => {
            eprintln!(
                "audit 未知子命令：{other}（可用：status / verify / reconcile / log / show / checkpoint / proof / consistency / verify-consistency / anchor / verify-anchor）"
            );
            ExitCode::from(2)
        }
    }
}

fn proof_cmd(repo: &Repo, args: &[String]) -> ExitCode {
    let checkpoint_seq = flag(args, "--checkpoint")
        .and_then(|value| value.parse::<u64>().ok())
        .map(|value| value as usize);
    let event_seq = flag(args, "--event")
        .and_then(|value| value.parse::<u64>().ok())
        .map(|value| value as usize);
    let (Some(checkpoint_seq), Some(event_seq)) = (checkpoint_seq, event_seq) else {
        eprintln!("audit proof 需要 --checkpoint <检查点事件序号> 和 --event <事件序号>");
        return ExitCode::from(2);
    };
    let events = repo.journal().events();
    let Some(checkpoint) = events.get(checkpoint_seq) else {
        eprintln!("检查点事件 #{checkpoint_seq} 不存在");
        return ExitCode::from(2);
    };
    if checkpoint.kind != "checkpoint" {
        eprintln!(
            "事件 #{checkpoint_seq} 不是 checkpoint，而是 {}",
            checkpoint.kind
        );
        return ExitCode::from(2);
    }
    let Some(height) = checkpoint
        .payload
        .get("height")
        .and_then(|value| value.as_u64())
        .map(|value| value as usize)
    else {
        eprintln!("检查点 #{checkpoint_seq} 缺 height");
        return ExitCode::from(2);
    };
    if checkpoint_seq != height {
        eprintln!("检查点 #{checkpoint_seq} 的 height={height}，自身不在前缀里");
        return ExitCode::from(2);
    }
    if event_seq >= height {
        eprintln!("事件 #{event_seq} 不在检查点 #{checkpoint_seq} 的前缀里（height={height}）");
        return ExitCode::from(2);
    }
    let Some(root) = checkpoint
        .payload
        .get("merkle_root")
        .and_then(|value| value.as_str())
        .and_then(trit_vcs::hash::Hash::from_hex)
    else {
        eprintln!("检查点 #{checkpoint_seq} 缺合法 merkle_root");
        return ExitCode::from(2);
    };
    let leaves: Vec<trit_vcs::hash::Hash> =
        events[..height].iter().map(|event| event.hash).collect();
    let Some(proof) = merkle_proof(&leaves, event_seq) else {
        eprintln!("事件 #{event_seq} 无法生成 inclusion proof");
        return ExitCode::from(2);
    };
    let event_hash = events[event_seq].hash;
    if !verify_merkle_proof(event_hash, event_seq, &proof, root, height) {
        eprintln!("事件 #{event_seq} 的 proof 与检查点 root 不一致");
        return ExitCode::FAILURE;
    }
    if has(args, "--json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "checkpoint": checkpoint_seq,
                "checkpoint_event": checkpoint.hash.to_hex(),
                "event": event_hash.to_hex(),
                "height": height,
                "index": event_seq,
                "merkle_root": root.to_hex(),
                "proof": proof.iter().map(|hash| hash.to_hex()).collect::<Vec<_>>(),
            }))
            .unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!(
            "事件 #{event_seq} ({}) 在检查点 #{checkpoint_seq} 下：root {}，proof {} 段",
            event_hash.short(),
            root.short(),
            proof.len()
        );
        for (index, sibling) in proof.iter().enumerate() {
            println!("  [{index}] {}", sibling.to_hex());
        }
    }
    ExitCode::SUCCESS
}

#[derive(Clone, Copy)]
struct CheckpointRef {
    seq: usize,
    height: usize,
    root: Hash,
}

fn checkpoint_ref(
    repo: &Repo,
    args: &[String],
    flag_name: &str,
    command: &str,
) -> Result<CheckpointRef, CliFail> {
    let Some(raw) = flag(args, flag_name) else {
        return Err(CliFail::usage(
            format!("{command} 需要 {flag_name} <检查点事件序号>"),
            [format!("trit-vcs {command} {flag_name} <seq> --json")],
        ));
    };
    let Ok(seq) = raw.parse::<usize>() else {
        return Err(CliFail::usage(
            format!("{flag_name} 不是合法事件序号：{raw}"),
            ["trit-vcs audit log checkpoint --json 查看检查点序号"],
        ));
    };
    let Some(event) = repo.journal().events().get(seq) else {
        return Err(CliFail::new(
            "audit_checkpoint_missing",
            format!("检查点事件 #{seq} 不存在"),
            ["先跑 `trit-vcs audit log checkpoint --json` 查看现有检查点"],
        ));
    };
    if event.kind != "checkpoint" {
        return Err(CliFail::new(
            "audit_checkpoint_bad",
            format!("事件 #{seq} 是 {}，不是 checkpoint", event.kind),
            ["先跑 `trit-vcs audit log checkpoint --json` 查看现有检查点"],
        ));
    }
    let height = event
        .payload
        .get("height")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| {
            CliFail::new(
                "audit_checkpoint_bad",
                format!("检查点 #{seq} 缺合法 height"),
                ["先跑 `trit-vcs audit status --json` 定位坏检查点"],
            )
        })?;
    let root = event
        .payload
        .get("merkle_root")
        .and_then(Value::as_str)
        .and_then(Hash::from_hex)
        .ok_or_else(|| {
            CliFail::new(
                "audit_checkpoint_bad",
                format!("检查点 #{seq} 缺合法 merkle_root"),
                ["先跑 `trit-vcs audit status --json` 定位坏检查点"],
            )
        })?;
    if height != seq {
        return Err(CliFail::new(
            "audit_checkpoint_bad",
            format!("检查点 #{seq} 的 height={height}，自身不在前缀里"),
            ["先跑 `trit-vcs audit status --json` 定位坏检查点"],
        ));
    }
    Ok(CheckpointRef { seq, height, root })
}

fn consistency_cmd(repo: &Repo, args: &[String]) -> ExitCode {
    let from = match checkpoint_ref(repo, args, "--from", "audit consistency") {
        Ok(value) => value,
        Err(err) => return fail_err(&err, repo.root(), "", args),
    };
    let to = match checkpoint_ref(repo, args, "--to", "audit consistency") {
        Ok(value) => value,
        Err(err) => return fail_err(&err, repo.root(), "", args),
    };
    if from.height > to.height {
        return fail_err(
            &CliFail::usage(
                "--from 必须指向不晚于 --to 的检查点",
                ["把 --from 换成较早的检查点事件序号"],
            ),
            repo.root(),
            "",
            args,
        );
    }
    let leaves = repo.journal().events()[..to.height]
        .iter()
        .map(|event| event.hash)
        .collect::<Vec<_>>();
    let proof = match consistency::consistency_proof(&leaves, from.height) {
        Ok(value) => value,
        Err(err) => {
            return fail_err(
                &CliFail::new(
                    "audit_consistency_failed",
                    err.to_string(),
                    ["先跑 `trit-vcs audit status --json` 确认两个检查点都合法"],
                ),
                repo.root(),
                "",
                args,
            );
        }
    };
    if proof.old_root != from.root || proof.new_root != to.root {
        return fail_err(
            &CliFail::new(
                "audit_consistency_failed",
                "检查点 root 与当前事件前缀重算结果不符",
                ["先跑 `trit-vcs audit status --json` 确认检查点未被篡改"],
            ),
            repo.root(),
            "",
            args,
        );
    }
    if let Some(out) = flag(args, "--out") {
        if let Err(err) = write_new_json(out, &proof) {
            return fail_err(&err, repo.root(), "", args);
        }
        if has(args, "--json") {
            return print_json(
                serde_json::json!({
                    "ok": true,
                    "out": out,
                    "from": from.seq,
                    "to": to.seq,
                    "from_size": proof.from_size,
                    "to_size": proof.to_size,
                    "old_root": proof.old_root.to_hex(),
                    "new_root": proof.new_root.to_hex(),
                    "proof_nodes": proof.subtrees.len() + proof.siblings.len(),
                }),
                args,
            );
        }
        println!(
            "已写一致性证明 {out}：{} → {}，{} 个节点",
            from.height,
            to.height,
            proof.subtrees.len() + proof.siblings.len()
        );
        return ExitCode::SUCCESS;
    }
    if has(args, "--json") {
        return print_json(serde_json::to_value(&proof).unwrap_or(Value::Null), args);
    }
    println!(
        "一致性证明：{} → {}，root {} → {}，{} 个节点",
        from.height,
        to.height,
        proof.old_root.short(),
        proof.new_root.short(),
        proof.subtrees.len() + proof.siblings.len()
    );
    ExitCode::SUCCESS
}

fn verify_consistency_cmd(repo: &Repo, args: &[String]) -> ExitCode {
    let from = match checkpoint_ref(repo, args, "--from", "audit verify-consistency") {
        Ok(value) => value,
        Err(err) => return fail_err(&err, repo.root(), "", args),
    };
    let to = match checkpoint_ref(repo, args, "--to", "audit verify-consistency") {
        Ok(value) => value,
        Err(err) => return fail_err(&err, repo.root(), "", args),
    };
    let Some(path) = flag(args, "--proof") else {
        return fail_err(
            &CliFail::usage(
                "audit verify-consistency 需要 --proof <证明文件>",
                ["trit-vcs audit verify-consistency --from <seq> --to <seq> --proof <file> --json"],
            ),
            repo.root(),
            "",
            args,
        );
    };
    let proof = match read_json::<ConsistencyProof>(path) {
        Ok(value) => value,
        Err(err) => return fail_err(&err, repo.root(), "", args),
    };
    let valid = proof.from_size == from.height
        && proof.to_size == to.height
        && proof.old_root == from.root
        && proof.new_root == to.root
        && consistency::verify_consistency(&proof).unwrap_or(false);
    if !valid {
        return fail_err(
            &CliFail::new(
                "audit_consistency_failed",
                "一致性证明与两个检查点或 Merkle 节点不符",
                ["重新生成证明：`trit-vcs audit consistency --from <seq> --to <seq> --out <file>`"],
            ),
            repo.root(),
            "",
            args,
        );
    }
    if has(args, "--json") {
        return print_json(
            serde_json::json!({
                "ok": true,
                "from": from.seq,
                "to": to.seq,
                "from_size": from.height,
                "to_size": to.height,
                "old_root": from.root.to_hex(),
                "new_root": to.root.to_hex(),
                "proof_nodes": proof.subtrees.len() + proof.siblings.len(),
            }),
            args,
        );
    }
    println!(
        "一致性证明有效：{} → {}，{} 个节点",
        from.height,
        to.height,
        proof.subtrees.len() + proof.siblings.len()
    );
    ExitCode::SUCCESS
}

fn anchor_cmd(repo: &Repo, args: &[String]) -> ExitCode {
    let checkpoint = match checkpoint_ref(repo, args, "--checkpoint", "audit anchor") {
        Ok(value) => value,
        Err(err) => return fail_err(&err, repo.root(), "", args),
    };
    let Some(out) = flag(args, "--out") else {
        return fail_err(
            &CliFail::usage(
                "audit anchor 需要 --out <仓库外文件>",
                ["trit-vcs audit anchor --checkpoint <seq> --out <file> --json"],
            ),
            repo.root(),
            "",
            args,
        );
    };
    let (value, outcome) = match anchor::from_repo(repo, checkpoint.seq)
        .and_then(|value| anchor::verify_against_repo(repo, &value).map(|outcome| (value, outcome)))
    {
        Ok(value) => value,
        Err(err) => return fail_anchor(&err, repo, args),
    };
    if let Err(err) = write_new_json(out, &value) {
        return fail_err(&err, repo.root(), "", args);
    }
    if has(args, "--json") {
        return print_json(
            serde_json::to_value(serde_json::json!({
                "ok": true,
                "out": out,
                "anchor": outcome,
            }))
            .unwrap_or(Value::Null),
            args,
        );
    }
    println!(
        "已写仓外锚 {out}：检查点 #{}，前缀 {} 条，root {}",
        checkpoint.seq, outcome.height, outcome.merkle_root
    );
    ExitCode::SUCCESS
}

fn verify_anchor_cmd(repo: &Repo, args: &[String]) -> ExitCode {
    let Some(path) = flag(args, "--anchor") else {
        return fail_err(
            &CliFail::usage(
                "audit verify-anchor 需要 --anchor <仓库外文件>",
                ["trit-vcs audit verify-anchor --anchor <file> --json"],
            ),
            repo.root(),
            "",
            args,
        );
    };
    let value = match anchor::load(Path::new(path)) {
        Ok(value) => value,
        Err(err) => return fail_anchor(&err, repo, args),
    };
    let outcome = match anchor::verify_against_repo(repo, &value) {
        Ok(value) => value,
        Err(err) => return fail_anchor(&err, repo, args),
    };
    if has(args, "--json") {
        return print_json(serde_json::to_value(outcome).unwrap_or(Value::Null), args);
    }
    println!(
        "仓外锚有效：检查点 #{}，前缀 {} 条，root {}",
        outcome.checkpoint, outcome.height, outcome.merkle_root
    );
    ExitCode::SUCCESS
}

fn write_new_json<T: Serialize>(path: &str, value: &T) -> Result<(), CliFail> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|err| {
        CliFail::new(
            "audit_proof_bad",
            format!("证明序列化失败：{err}"),
            ["缩小证明范围后重试"],
        )
    })?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|err| {
            CliFail::local_io(
                path,
                &format!("写入失败（{err}）"),
                ["换一个不存在的 --out 路径；不要覆盖已有审计证明或锚"],
            )
        })?;
    file.write_all(&bytes)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_data())
        .map_err(|err| {
            CliFail::local_io(
                path,
                &format!("写入失败（{err}）"),
                ["检查磁盘空间与文件权限后重试"],
            )
        })
}

fn read_json<T: DeserializeOwned>(path: &str) -> Result<T, CliFail> {
    let bytes = fs::read(path).map_err(|err| {
        CliFail::local_io(
            path,
            &format!("读取失败（{err}）"),
            ["确认文件存在且当前用户可读"],
        )
    })?;
    serde_json::from_slice(&bytes).map_err(|err| {
        CliFail::new(
            "audit_proof_bad",
            format!("{path}: 不是合法 JSON（{err}）"),
            ["确认传入的是本命令生成的证明或锚文件"],
        )
    })
}

fn fail_anchor(err: &anchor::AnchorError, repo: &Repo, args: &[String]) -> ExitCode {
    fail_err(
        &CliFail::new(
            err.kind(),
            err.to_string(),
            [
                "先跑 `trit-vcs audit status --json` 确认日志、检查点和信任表",
                "再跑 `trit-vcs audit verify-anchor --anchor <file> --json` 单独验锚",
            ],
        ),
        repo.root(),
        "",
        args,
    )
}

fn checkpoint_cmd(repo: &mut Repo, args: &[String]) -> ExitCode {
    let key_path = flag(args, "--key-file").unwrap_or("");
    let owner = flag(args, "--owner").unwrap_or("");
    if key_path.is_empty() || owner.is_empty() {
        eprintln!("audit checkpoint 需要 --key-file <私钥文件> 和 --owner <宿主:会话id>");
        return ExitCode::from(2);
    }
    let at_ms = now_secs() * 1000;
    match repo.checkpoint(Path::new(key_path), owner, at_ms) {
        Ok(outcome) => {
            if has(args, "--json") {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "event": outcome.event.to_hex(),
                        "height": outcome.height,
                        "head": outcome.head.map(|hash| hash.to_hex()),
                        "merkle_root": outcome.merkle_root.to_hex(),
                        "previous": outcome.previous.map(|hash| hash.to_hex()),
                        "key_id": outcome.key_id,
                        "signature": outcome.signature,
                    }))
                    .unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!(
                    "已写检查点 {}：前缀 {} 条，root {}",
                    outcome.event.short(),
                    outcome.height,
                    outcome.merkle_root.short()
                );
                println!(
                    "  previous：{}",
                    outcome
                        .previous
                        .map(|hash| hash.to_hex())
                        .unwrap_or_else(|| "（首个检查点）".to_string())
                );
            }
            ExitCode::SUCCESS
        }
        Err(err) => fail_err(&err, repo.root(), owner, args),
    }
}

fn status_cmd(repo: &Repo, args: &[String]) -> ExitCode {
    let mut report = match audit::status(repo) {
        Ok(report) => report,
        Err(err) => return fail_audit(&err, repo, args),
    };
    let mut anchor_status = None;
    if let Some(path) = flag(args, "--anchor") {
        match anchor::load(Path::new(path))
            .and_then(|value| anchor::verify_against_repo(repo, &value))
        {
            Ok(outcome) => anchor_status = Some(outcome),
            Err(err) => {
                report.ok = false;
                report.issues.push(audit::AuditIssue {
                    kind: err.kind().to_string(),
                    detail: err.to_string(),
                });
            }
        }
    }
    if has(args, "--json") {
        let mut value = audit::json(&report);
        if let Some(outcome) = &anchor_status {
            value["anchor"] = serde_json::to_value(outcome).unwrap_or(Value::Null);
        }
        let code = print_json(value, args);
        return if report.ok { code } else { ExitCode::FAILURE };
    }
    render(&report, anchor_status.as_ref());
    if report.ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn log_cmd(repo: &Repo, args: &[String]) -> ExitCode {
    let kind = args
        .get(2)
        .filter(|value| !value.starts_with("--"))
        .map(String::as_str);
    let from = flag(args, "--from").and_then(|value| value.parse::<u64>().ok());
    let to = flag(args, "--to").and_then(|value| value.parse::<u64>().ok());
    let rows = match audit::log(repo, kind, from, to) {
        Ok(rows) => rows,
        Err(err) => return fail_audit(&err, repo, args),
    };
    if has(args, "--json") {
        return print_json(serde_json::json!(rows), args);
    }
    for row in &rows {
        let seq = row
            .get("seq")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let kind = row
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("-");
        let at = row
            .get("at_ms")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        println!(
            "{seq:>5}  {kind:<10}  {at}  {}",
            serde_json::to_string(&row.get("payload").cloned().unwrap_or_default())
                .unwrap_or_else(|_| "{}".to_string())
        );
    }
    if rows.is_empty() {
        println!("（没有匹配的事件）");
    }
    ExitCode::SUCCESS
}

fn show_cmd(repo: &Repo, args: &[String]) -> ExitCode {
    let Some(target) = args.get(2).filter(|value| !value.starts_with("--")) else {
        eprintln!("audit show 需要事件序号");
        return ExitCode::from(2);
    };
    let Ok(seq) = target.parse::<u64>() else {
        eprintln!("事件序号不是数字：{target}");
        return ExitCode::from(2);
    };
    let event = match audit::show(repo, seq) {
        Ok(event) => event,
        Err(err) => return fail_audit(&err, repo, args),
    };
    let Some(event) = event else {
        eprintln!("没有第 {seq} 条事件");
        return ExitCode::FAILURE;
    };
    if has(args, "--json") {
        return print_json(event, args);
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&event).unwrap_or_else(|_| "{}".to_string())
    );
    ExitCode::SUCCESS
}

fn render(report: &AuditReport, anchor_status: Option<&AnchorOutcome>) {
    println!(
        "审计状态：{}  {}",
        report.level,
        if report.ok { "绿" } else { "红" }
    );
    println!(
        "  链：{}　事件：{} 条　开放操作：{} 个",
        if report.chain_ok { "绿" } else { "红" },
        report.events,
        report.open_ops
    );
    println!("  HEAD：{}", report.head.as_deref().unwrap_or("（空）"));
    if report.refs.is_empty() {
        println!("  refs：（无）");
    } else {
        for (name, id) in &report.refs {
            println!("  ref {name} → {id}");
        }
    }
    println!("  状态摘要：{}", report.state_digest);
    if let Some(anchor_status) = anchor_status {
        println!(
            "  仓外锚：检查点 #{}，前缀 {} 条，root {}",
            anchor_status.checkpoint, anchor_status.height, anchor_status.merkle_root
        );
    }
    println!("  下一层：{}", report.next_level);
    for issue in &report.issues {
        println!("  [问题] {}：{}", issue.kind, issue.detail);
    }
    for warning in &report.warnings {
        println!("  [提示] {}：{}", warning.kind, warning.detail);
    }
    if report.level == "L1" {
        println!("  说明：L1 只证明链内自洽；要 L2 需要最新事件带 state_after 且对账无问题");
    }
    if report.level == "L2" {
        println!(
            "  说明：L2 已把日志对到当前状态；仓内检查点、一致性证明和文件锚已可用，但文件锚不是抗全机篡改的外部信任根"
        );
    }
}

fn fail_audit(err: &AuditError, repo: &Repo, args: &[String]) -> ExitCode {
    match err {
        AuditError::Repo(inner) => fail_repo(inner, repo.root(), "", args),
        other => {
            let cli = CliFail::new(
                "audit",
                other.to_string(),
                [
                    "先跑 `trit-vcs verify --repo <仓库>` 确认对象库本身是绿的",
                    "再跑 `trit-vcs audit status --json --repo <仓库>` 看结构化问题",
                ],
            );
            fail_err(&cli, repo.root(), "", args)
        }
    }
}
