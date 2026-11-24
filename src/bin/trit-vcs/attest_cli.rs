//! `attest`：给已提交的 witness 追加签名 sidecar；不改提交 id。

use std::process::ExitCode;

use serde_json::json;
use trit_vcs::hash::Hash;
use trit_vcs::repo::Repo;

use super::verdict::fail_err;
use super::{flag, has, now_ms, positionals, repo_path};

pub(crate) fn attest_cmd(args: &[String]) -> ExitCode {
    let root = repo_path(args);
    let words = positionals(args, &["--repo", "--witness", "--key-file", "--owner"]);
    let Some(target) = words.first() else {
        eprintln!("attest 需要提交 id");
        return ExitCode::from(2);
    };
    let Some(id) = Hash::from_hex(target) else {
        eprintln!("不是合法提交 id：{target}");
        return ExitCode::from(2);
    };
    let Some(witness) = flag(args, "--witness") else {
        eprintln!("attest 需要 --witness FILE");
        return ExitCode::from(2);
    };
    let Some(key) = flag(args, "--key-file") else {
        eprintln!("attest 需要 --key-file FILE");
        return ExitCode::from(2);
    };
    let owner = flag(args, "--owner").unwrap_or("");
    if owner.is_empty() {
        eprintln!("attest 需要 --owner <宿主:会话id>");
        return ExitCode::from(2);
    }
    let bytes = match std::fs::read(witness) {
        Ok(bytes) => bytes,
        Err(err) => return fail_err(&trit_vcs::repo::RepoError::Io(err), &root, owner, args),
    };
    let mut repo = match Repo::open(&root) {
        Ok(repo) => repo,
        Err(err) => return fail_err(&err, &root, owner, args),
    };
    match repo.attest_witness(&id, &bytes, std::path::Path::new(key), owner, now_ms()) {
        Ok(digest) => {
            if has(args, "--json") {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true, "commit": id.to_hex(), "attestation": digest.to_hex(),
                    }))
                    .unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!(
                    "已签见证：提交 {}，attestation {}",
                    id.short(),
                    digest.short()
                );
            }
            ExitCode::SUCCESS
        }
        Err(err) => fail_err(&err, repo.root(), owner, args),
    }
}
