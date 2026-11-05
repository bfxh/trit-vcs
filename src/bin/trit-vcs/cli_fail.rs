//! CLI 这一层自己的失败：把"一句话文案"换成带档位与下一步的判决出口。
//!
//! 库里的六张面各有 `Remediable` 实现（`src/remediation/faces.rs`），但 CLI 自己也会判红：
//! 参数没给对、本地文件读写不了、认领表/索引读不到、既没暂存也没提交。以前这些只能
//! `fail(format!(...))` 打一句话 ⇒ 智能体读到"commit/preflight 需要 -m <说明>"不知道
//! 完整命令长什么样，读到"某文件: 拒绝访问"不知道属于哪张面。这里给它们同一形状：
//! `FAIL <原话>（档位）` + 编号的下一步，与 A8 那六张面一致。

use trit_vcs::remediation::{Context, Remediable};
use trit_vcs::repo::RepoError;

/// 一次 CLI 层的失败。
///
/// `Repo` 那一支是**透传**：档位与下一步仍由 `remediation` 那一份决定，这里不复制规则
/// （复制的第二份实现迟早和第一份分叉，那正是 A8 之前六张面各自的病）。
pub(crate) enum CliFail {
    /// CLI 自己判出来的：档位、原文案、至少一条下一步。
    Own {
        kind: &'static str,
        message: String,
        next: Vec<String>,
    },
    /// 库层错误原样带上来（`Repo::head` / `index` / `commit_at` 这些）。
    Repo(RepoError),
}

impl CliFail {
    pub(crate) fn new(
        kind: &'static str,
        message: impl Into<String>,
        next: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self::Own {
            kind,
            message: message.into(),
            next: next.into_iter().map(Into::into).collect(),
        }
    }

    /// 参数档位：下一步一律是**补齐后的整条命令**，不是"去看 --help"。
    pub(crate) fn usage(
        message: impl Into<String>,
        next: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self::new("cli_usage", message, next)
    }

    /// 本地文件读写不上：路径进文案，下一步给一条能证明权限/路径的只读命令。
    pub(crate) fn local_io(
        path: &str,
        reason: &str,
        next: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self::new("cli_local_io", format!("{path}: {reason}"), next)
    }
}

impl From<RepoError> for CliFail {
    fn from(err: RepoError) -> Self {
        Self::Repo(err)
    }
}

impl std::fmt::Display for CliFail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Own { message, .. } => f.write_str(message),
            Self::Repo(err) => err.fmt(f),
        }
    }
}

impl Remediable for CliFail {
    fn kind(&self) -> &'static str {
        match self {
            Self::Own { kind, .. } => kind,
            Self::Repo(err) => err.kind(),
        }
    }

    fn commands(&self, ctx: Context<'_>) -> Vec<String> {
        match self {
            Self::Own { next, .. } => next.clone(),
            Self::Repo(err) => err.commands(ctx),
        }
    }
}
