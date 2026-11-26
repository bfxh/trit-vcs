//! Git 标签读取与导出映射：只认指向提交的 refs/tags，保留名字，附注标记单独记账。

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use crate::hash::Hash;
use crate::model::Commit;

use super::{GitError, git_raw, one_line};

#[derive(Clone, Debug)]
pub(super) struct GitTagInfo {
    pub(super) name: String,
    pub(super) annotated: bool,
}

/// 读 `refs/tags`：轻量标签直接指提交，附注标签经 tag 对象剥到提交。
/// 指向 tree/blob 的标签不搬，也不计进 `tags_skipped`；`tags_skipped` 只统计指向图外提交的标签。
pub(super) fn git_tags(dir: &Path) -> Result<BTreeMap<String, Vec<GitTagInfo>>, GitError> {
    let raw = git_raw(
        dir,
        &[
            "for-each-ref",
            "refs/tags",
            "--format=%(refname:short)%00%(objecttype)%00%(objectname)%00%(*objecttype)%00%(*objectname)",
        ],
    )?;
    let text = String::from_utf8(raw)
        .map_err(|_| GitError::BadPath("refs/tags 含非 UTF-8 名称".to_string()))?;
    let mut out: BTreeMap<String, Vec<GitTagInfo>> = BTreeMap::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split('\0').collect();
        if fields.len() != 5 {
            continue;
        }
        let name = fields[0];
        let object_type = fields[1];
        let object = fields[2];
        let peeled_type = fields[3];
        let peeled = fields[4];
        let (sha, annotated) = if object_type == "commit" && peeled_type.is_empty() {
            (object, false)
        } else if object_type == "tag" && peeled_type == "commit" && !peeled.is_empty() {
            (peeled, true)
        } else {
            continue;
        };
        if name.is_empty() || sha.len() != 40 {
            continue;
        }
        out.entry(sha.to_string()).or_default().push(GitTagInfo {
            name: name.to_string(),
            annotated,
        });
    }
    Ok(out)
}

pub(super) fn tag_evidence(tag: &GitTagInfo) -> String {
    format!(
        "git-tag{}:{}",
        if tag.annotated { "-annotated" } else { "" },
        one_line(&tag.name)
    )
}

/// 先收齐标签名到提交的映射，再交给导出统一写 refs/tags。
/// 同名标签指向两个提交时直接失败，不静默覆盖。
pub(super) fn collect_tag_refs(
    commits: &[(Hash, Commit)],
    shas: &HashMap<Hash, String>,
) -> Result<BTreeMap<String, (String, bool)>, GitError> {
    let mut refs: BTreeMap<String, (String, bool)> = BTreeMap::new();
    for (id, commit) in commits {
        let Some(sha) = shas.get(id) else {
            continue;
        };
        for evidence in &commit.evidence {
            let (name, annotated) = if let Some(name) = evidence.strip_prefix("git-tag-annotated:")
            {
                (name, true)
            } else if let Some(name) = evidence.strip_prefix("git-tag:") {
                (name, false)
            } else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            if let Some((previous, _)) = refs.insert(name.to_string(), (sha.clone(), annotated))
                && previous != *sha
            {
                return Err(GitError::Graph(format!(
                    "标签 {name} 同时指向两个提交：{previous} / {sha}",
                )));
            }
        }
    }
    Ok(refs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commit_with(tag: &str) -> Commit {
        let mut commit = Commit::new(
            Hash::of(b"tree"),
            "test",
            "tagged",
            crate::model::Hlc::zero(),
        );
        commit.evidence.push(format!("git-tag:{tag}"));
        commit
    }

    #[test]
    fn duplicate_tag_names_are_rejected_instead_of_overwritten() {
        let first = commit_with("v1");
        let second = commit_with("v1");
        let first_id = Hash::of(b"first");
        let second_id = Hash::of(b"second");
        let commits = vec![(first_id, first), (second_id, second)];
        let shas = HashMap::from([(first_id, "a".repeat(40)), (second_id, "b".repeat(40))]);
        match collect_tag_refs(&commits, &shas) {
            Err(GitError::Graph(message)) => assert!(message.contains("v1"), "{message}"),
            other => panic!("同名标签必须报错，不能静默覆盖：{other:?}"),
        }
    }
}
