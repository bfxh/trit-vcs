//! 全父图遍历：给 Git 桥、`log --all` 和审计复盘用。
//!
//! `log()` 只跟第一父链；多父提交（Git merge 导入、merge 工具）需要能走到所有父。
//! 这里用显式栈做后序 DFS，避免十万级历史递归爆栈；返回顺序与 `log()` 一致（新→旧）。

use std::collections::HashMap;

use crate::hash::Hash;
use crate::model::Commit;

use super::{Repo, RepoError};

impl Repo {
    /// 从 HEAD 可达的所有提交（新→旧，父一定排在子之后）。
    pub fn log_all(&self) -> Result<Vec<(Hash, Commit)>, RepoError> {
        match self.head()? {
            Some(head) => self.log_from(head),
            None => Ok(Vec::new()),
        }
    }

    /// 从任意 tip 可达的所有提交（新→旧，父一定排在子之后）。
    pub fn log_from(&self, tip: Hash) -> Result<Vec<(Hash, Commit)>, RepoError> {
        // 0=未访问，1=在栈上，2=已完成。
        let mut state: HashMap<Hash, u8> = HashMap::new();
        let mut frames: Vec<(Hash, usize, Commit)> = Vec::new();
        state.insert(tip, 1);
        frames.push((tip, 0, self.commit_at(&tip)?));
        let mut out = Vec::new();
        let mut steps = 0usize;
        while let Some((id, index, parents)) = frames
            .last()
            .map(|(id, index, commit)| (*id, *index, commit.parents.clone()))
        {
            steps += 1;
            if steps > 100_000 {
                return Err(RepoError::BadHead("提交图过长（成环？）".to_string()));
            }
            if index < parents.len() {
                frames.last_mut().expect("栈非空").1 += 1;
                let parent = parents[index];
                match state.get(&parent).copied() {
                    Some(2) => continue,
                    Some(1) => {
                        return Err(RepoError::BadHead(format!(
                            "提交 {} 的父 {} 指回仍在栈上的提交（环）",
                            id.to_hex(),
                            parent.to_hex()
                        )));
                    }
                    _ => {
                        let commit = self.commit_at(&parent)?;
                        state.insert(parent, 1);
                        frames.push((parent, 0, commit));
                    }
                }
            } else {
                let (done, _, commit) = frames.pop().expect("栈非空");
                state.insert(done, 2);
                out.push((done, commit));
            }
        }
        out.reverse();
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::repo::CommitRequest;

    fn temp(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("trit-vcs-repograph-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn commit_with(repo: &mut Repo, name: &str, parents: Vec<Hash>, now: u64) -> Hash {
        let mut files = BTreeMap::new();
        files.insert("part.txt".to_string(), name.as_bytes().to_vec());
        repo.stage(&files, now).unwrap();
        repo.commit(CommitRequest {
            message: name.to_string(),
            session: "qoder:graph".to_string(),
            claims: Vec::new(),
            allow_unclaimed: true,
            parents_override: Some(parents),
            now_secs: now,
            ..Default::default()
        })
        .unwrap()
        .id
    }

    #[test]
    fn all_parents_are_visited_and_returned_newest_first() {
        let root = temp("all");
        let mut repo = Repo::init(root.join("repo")).unwrap();
        let base = commit_with(&mut repo, "base", vec![], 1_000);
        let left = commit_with(&mut repo, "left", vec![base], 1_001);
        let right = commit_with(&mut repo, "right", vec![base], 1_002);
        let merge = commit_with(&mut repo, "merge", vec![left, right], 1_003);
        assert_eq!(repo.head().unwrap(), Some(merge));

        let graph = repo.log_all().unwrap();
        let messages: Vec<&str> = graph
            .iter()
            .map(|(_, commit)| commit.message.as_str())
            .collect();
        assert_eq!(messages, vec!["merge", "right", "left", "base"]);
        assert_eq!(graph[0].1.parents, vec![left, right]);
        assert_eq!(repo.merge_base(&left, &right).unwrap(), Some(base));
        assert_eq!(repo.merge_base(&merge, &left).unwrap(), Some(left));
        assert_eq!(
            repo.verify().unwrap().commits,
            4,
            "verify 要体检全图，不能漏掉侧分支"
        );
        for (id, _) in &graph[1..] {
            assert_ne!(*id, merge);
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn empty_repo_is_empty_graph() {
        let root = temp("empty");
        let repo = Repo::init(root.join("repo")).unwrap();
        assert!(repo.log_all().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }
}
