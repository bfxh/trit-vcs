// 对象库 / 包 / 工作树 / 中央仓这四张判决面。
//
// 为什么单拆一个文件：`remediation` 的 RepoError 面已经有 19 条判决，再加进这四张面（6 + 7 + 4 + 3）
// 就顶穿 800 行的上帝模块门。分文件不改公开路径 —— 调用方仍然 `trit_vcs::remediation::*`。
//
// 一条贯穿的口径：**转发性质的判决与里面那层共用同一个 kind**（`CentralError::Repo(NonFastForward)`
// 就该是 `non_fast_forward`）；自己新加的判定值必须独一无二，否则按 kind 分支的调用方还得回去抠文案。

use crate::bundle::BundleError;
use crate::central::CentralError;
use crate::git_bridge::GitError;
use crate::merge::MergeError;
use crate::remediation::{Context, VCS, commands, join_paths, kind};
use crate::repo::RepoError;
use crate::store::StoreError;
use crate::worktree::WorktreeError;

/// 对象库的坏法先分名字，动作才谈得上分开。
///
/// 都带 `store_` 前缀：与 `RepoError::Io` 的 `io` 不撞名（同一本索引里两条判决共用一个 kind，
/// 按 kind 分支的调用方就只能回去抠文案，那正是这一层要消灭的东西）。
pub fn kind_store(err: &StoreError) -> &'static str {
    match err {
        StoreError::Io(_) => "store_io",
        StoreError::Missing(_) => "store_missing_object",
        StoreError::Corrupt { .. } => "store_corrupt_object",
        StoreError::BadMap(_) => "store_bad_map",
        StoreError::Locked(_) => "store_locked",
        StoreError::BadIndex(_) => "store_bad_index",
    }
}

/// 从对等仓把缺/坏的那个对象重取回来该怎么跑（本版本**没有** `repair` 动词，不虚构）。
///
/// `import` 跳过目标已有的块 ⇒ 这条路径天然只补差异；但内容寻址下"手改 pack/index"永远对不上 id，
/// 所以命令里绝不出现改文件的动作。
fn refetch_from_peer(repo: &str, object: &str) -> Vec<String> {
    vec![
        format!("{VCS} verify --repo {repo}   # 先确认还有没有别的块也不对"),
        format!(
            "{VCS} export <对等仓的树id> --out <包文件> --repo <对等仓>   # 从一份好副本导出（对象 {object}）"
        ),
        format!("{VCS} import <包文件> --repo {repo}   # 已有块会跳过，只补这一个"),
    ]
}

pub fn commands_store(err: &StoreError, ctx: Context<'_>) -> Vec<String> {
    let repo = ctx.dir.display().to_string();
    match err {
        StoreError::Io(_) | StoreError::BadIndex(_) => {
            vec![
                format!("{VCS} verify --repo {repo}"),
                format!("{VCS} stats --repo {repo}"),
            ]
        }
        StoreError::Missing(id) => refetch_from_peer(&repo, id),
        StoreError::Corrupt { expected, actual } => {
            let mut out = vec![format!(
                "{VCS} verify --repo {repo}   # 期望 {expected}，读到 {actual}"
            )];
            out.extend(refetch_from_peer(&repo, expected));
            out
        }
        StoreError::BadMap(_) => vec![
            format!("{VCS} verify --repo {repo}"),
            format!("{VCS} status --repo {repo}"),
        ],
        StoreError::Locked(lock) => vec![
            format!("等那个进程跑完再重来（锁文件 {lock} 是它正在写的证据，别删）"),
            format!("{VCS} verify --repo {repo}   # 它结束后再确认库是完整的"),
        ],
    }
}

/// 包（`TVBD`）的坏法。`Store` 那一路直接接对象的口径，不复述一遍。
pub fn kind_bundle(err: &BundleError) -> &'static str {
    match err {
        BundleError::Io(_) => "bundle_io",
        BundleError::Store(inner) => kind_store(inner),
        BundleError::BadMagic => "bundle_bad_magic",
        BundleError::UnsupportedSchema(_) => "bundle_unsupported_schema",
        BundleError::Truncated => "bundle_truncated",
        BundleError::Corrupt { .. } => "bundle_corrupt_object",
        BundleError::MissingTree(_) => "bundle_missing_tree",
    }
}

pub fn commands_bundle(err: &BundleError, ctx: Context<'_>) -> Vec<String> {
    let repo = ctx.dir.display().to_string();
    match err {
        BundleError::Io(_) => vec![
            format!("{VCS} verify --repo {repo}"),
            format!("{VCS} stats --repo {repo}"),
        ],
        BundleError::Store(inner) => commands_store(inner, ctx),
        BundleError::BadMagic => vec![format!(
            "{VCS} export <树id> --out <包文件> --repo {repo}   # 这个文件不是 TVBD 包（多半不是 trit-vcs 写的）"
        )],
        BundleError::UnsupportedSchema(found) => vec![format!(
            "{VCS} export <树id> --out <包文件> --repo {repo}   # 包是 schema {found}，本版本读不了；让写它的版本重导"
        )],
        BundleError::Truncated => vec![
            format!(
                "{VCS} import <同一个包文件> --repo {repo}   # 断点续传：已有块跳过，接着补剩下的"
            ),
            format!("还缺就把源仓整包重导一次（{VCS} export <树id> --out <包文件> --repo <源仓>）"),
        ],
        BundleError::Corrupt { expected, actual } => vec![
            format!(
                "{VCS} verify --repo <源仓>   # 包里 {expected} 与 {actual} 对不上，说明源仓本身有问题"
            ),
            format!(
                "{VCS} export <树id> --out <包文件> --repo <源仓>   # 修好源仓再重导，别改包文件"
            ),
        ],
        BundleError::MissingTree(id) => vec![
            format!("{VCS} log --json --repo <源仓>   # 看 {id} 在不在源仓里"),
            format!(
                "{VCS} export <树id> --out <包文件> --repo <源仓>   # 不带 --prefix 重导（前缀包只带清单）"
            ),
        ],
    }
}

pub fn kind_worktree(err: &WorktreeError) -> &'static str {
    match err {
        WorktreeError::Io(_) => "worktree_io",
        WorktreeError::Repo(inner) => kind(inner),
        WorktreeError::Store(inner) => kind_store(inner),
        WorktreeError::Dirty(..) => "worktree_dirty",
    }
}

pub fn commands_worktree(err: &WorktreeError, ctx: Context<'_>) -> Vec<String> {
    let repo = ctx.dir.display().to_string();
    match err {
        WorktreeError::Io(_) => vec![
            format!("{VCS} status --repo {repo}"),
            format!("{VCS} verify --repo {repo}"),
        ],
        WorktreeError::Repo(inner) => commands(inner, ctx),
        WorktreeError::Store(inner) => commands_store(inner, ctx),
        WorktreeError::Dirty(count, paths) => {
            let listed = join_paths(paths);
            vec![
                format!("{VCS} status --repo {repo}   # 这 {count} 条就是挡着的改动：{listed}"),
                format!(
                    "{VCS} commit --repo {repo} …   # 想把改动留下就先入库（未认领会被拒，按提示认领）"
                ),
                format!(
                    "{VCS} pull <ref> --central <仓目录> --repo {repo} --force   # 确定这些改动可以丢时才覆盖"
                ),
            ]
        }
    }
}

/// 中央仓的三条判决都是转发：kind 与命令都跟着里面那一层走（不新造一套语义）。
pub fn kind_central(err: &CentralError) -> &'static str {
    match err {
        CentralError::Repo(inner) => kind(inner),
        CentralError::Bundle(inner) => kind_bundle(inner),
        CentralError::Worktree(inner) => kind_worktree(inner),
    }
}

pub fn commands_central(err: &CentralError, ctx: Context<'_>) -> Vec<String> {
    match err {
        CentralError::Repo(inner) => commands(inner, ctx),
        CentralError::Bundle(inner) => commands_bundle(inner, ctx),
        CentralError::Worktree(inner) => commands_worktree(inner, ctx),
    }
}

/// "任何一条判决都能被解释"的公共形状：CLI 与 MCP 对四类错误走同一条出口。
///
/// 有意的不对称：转发型（`Repo`/`Store`/`Bundle` 里的 `Store`）与里面那层**共用** kind——
/// 同一条根因判决就该是同一个值，调用方按它分支才不用再看文案。
pub trait Remediable {
    fn kind(&self) -> &'static str;
    fn commands(&self, ctx: Context<'_>) -> Vec<String>;
}

impl Remediable for RepoError {
    fn kind(&self) -> &'static str {
        kind(self)
    }
    fn commands(&self, ctx: Context<'_>) -> Vec<String> {
        commands(self, ctx)
    }
}

impl Remediable for StoreError {
    fn kind(&self) -> &'static str {
        kind_store(self)
    }
    fn commands(&self, ctx: Context<'_>) -> Vec<String> {
        commands_store(self, ctx)
    }
}

impl Remediable for BundleError {
    fn kind(&self) -> &'static str {
        kind_bundle(self)
    }
    fn commands(&self, ctx: Context<'_>) -> Vec<String> {
        commands_bundle(self, ctx)
    }
}

impl Remediable for WorktreeError {
    fn kind(&self) -> &'static str {
        kind_worktree(self)
    }
    fn commands(&self, ctx: Context<'_>) -> Vec<String> {
        commands_worktree(self, ctx)
    }
}

impl Remediable for CentralError {
    fn kind(&self) -> &'static str {
        kind_central(self)
    }
    fn commands(&self, ctx: Context<'_>) -> Vec<String> {
        commands_central(self, ctx)
    }
}

/// 四类判决共用的文字出口（`explain` 是它的 `RepoError` 特例）。
pub fn explain_any<E: Remediable + std::fmt::Display>(err: &E, ctx: Context<'_>) -> String {
    let mut out = format!("{}（{}）", err, err.kind());
    for (index, command) in err.commands(ctx).iter().enumerate() {
        out.push_str(&format!("\n  {}. {}", index + 1, command));
    }
    out
}

/// 四类判决共用的 JSON 出口：`kind` 可分支、`remediation` 是能跑的命令行。
pub fn explain_json_any<E: Remediable + std::fmt::Display>(
    err: &E,
    ctx: Context<'_>,
) -> serde_json::Value {
    serde_json::json!({
        "ok": false,
        "error": {
            "kind": err.kind(),
            "message": err.to_string(),
        },
        "remediation": err.commands(ctx),
    })
}

/// Git 生态桥的坏法：外部 `git` 是这条路径唯一的外部依赖，红在哪里必须原样带回来。
pub fn kind_git(err: &GitError) -> &'static str {
    match err {
        GitError::Io(_) => "git_io",
        GitError::Repo(inner) => kind(inner),
        GitError::Store(inner) => kind_store(inner),
        GitError::Git { .. } => "git_command_failed",
        GitError::BadPath(_) => "git_bad_path",
        GitError::NoCommits => "git_no_commits",
    }
}

pub fn commands_git(err: &GitError, ctx: Context<'_>) -> Vec<String> {
    let repo = ctx.dir.display().to_string();
    match err {
        GitError::Io(_) => vec![format!("{VCS} verify --repo {repo}")],
        GitError::Repo(inner) => commands(inner, ctx),
        GitError::Store(inner) => commands_store(inner, ctx),
        GitError::Git { args, stderr } => vec![
            format!(
                "外部 git 在跑 `git {args}` 时红了：{stderr}   # 先确认这台机器上的 git 能跑：git --version"
            ),
            format!(
                "{VCS} export <树id> --out <包文件> --repo {repo}   # 只要传对象，用原生包这条路径不依赖 git"
            ),
        ],
        GitError::BadPath(bad) => vec![format!(
            "{VCS} export <树id> --out <包文件> --repo {repo}   # Git 桥只吃 UTF-8 路径（{bad} 不是）；对象仍走原生包"
        )],
        GitError::NoCommits => vec![
            format!("{VCS} status --repo {repo}"),
            format!(
                "{VCS} add <文件或目录> --repo {repo}，然后 {VCS} commit --repo {repo} …   # 空仓没什么可导"
            ),
        ],
    }
}

pub fn kind_merge(err: &MergeError) -> &'static str {
    match err {
        MergeError::Repo(inner) => kind(inner),
        MergeError::Store(inner) => kind_store(inner),
    }
}

pub fn commands_merge(err: &MergeError, ctx: Context<'_>) -> Vec<String> {
    match err {
        MergeError::Repo(inner) => commands(inner, ctx),
        MergeError::Store(inner) => commands_store(inner, ctx),
    }
}

impl Remediable for GitError {
    fn kind(&self) -> &'static str {
        kind_git(self)
    }
    fn commands(&self, ctx: Context<'_>) -> Vec<String> {
        commands_git(self, ctx)
    }
}

impl Remediable for MergeError {
    fn kind(&self) -> &'static str {
        kind_merge(self)
    }
    fn commands(&self, ctx: Context<'_>) -> Vec<String> {
        commands_merge(self, ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remediation::explain;
    use std::collections::BTreeSet;
    use std::path::Path;

    fn ctx() -> Context<'static> {
        Context {
            dir: Path::new("/tmp/w"),
            session: "qoder:s1",
        }
    }

    fn store_cases() -> Vec<StoreError> {
        vec![
            StoreError::Io(std::io::Error::other("读不动")),
            StoreError::Missing("abc123".to_string()),
            StoreError::Corrupt {
                expected: "aaa".to_string(),
                actual: "bbb".to_string(),
            },
            StoreError::BadMap("文件映射坏了".to_string()),
            StoreError::Locked("objects/.lock".to_string()),
            StoreError::BadIndex("第 3 行不是 JSON".to_string()),
        ]
    }

    #[test]
    fn every_store_verdict_has_its_own_snake_case_kind() {
        let mut seen = BTreeSet::new();
        for err in store_cases() {
            let name = kind_store(&err);
            assert!(
                name.chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch == '_' || ch.is_ascii_digit()),
                "{name} 不是 snake_case"
            );
            assert!(seen.insert(name), "两条对象库判决共用一个 kind：{name}");
            assert!(!name.is_empty());
        }
        assert_eq!(seen.len(), 6, "对象库六种坏法必须给出六个值");
        // 经过 RepoError 转发也必须拿到同一个值：不能因为套了一层就退回成一个笼统的 `store`。
        assert_eq!(
            kind(&RepoError::Store(StoreError::Locked(
                "objects/.lock".to_string()
            ))),
            "store_locked"
        );
        // 命令也必须转过去：套了一层 RepoError 就退回「verify + stats」两句老话，等于这次拆分白做。
        let forwarded = commands(
            &RepoError::Store(StoreError::Locked("objects/.lock".to_string())),
            ctx(),
        );
        assert!(forwarded[0].contains("别删"), "{forwarded:?}");
    }

    #[test]
    fn every_store_verdict_ships_commands() {
        for err in store_cases() {
            let lines = commands_store(&err, ctx());
            assert!(!lines.is_empty(), "{err} 一条动作都没给");
            assert!(
                lines
                    .iter()
                    .all(|l| l.contains("trit-vcs") || l.contains("等")),
                "{err} 的命令里出现了跑不通的东西：{lines:?}"
            );
        }
    }

    #[test]
    fn a_locked_store_never_tells_me_to_delete_someone_elses_lock() {
        let lines = commands_store(&StoreError::Locked("objects/.lock".to_string()), ctx());
        assert!(
            lines[0].contains("objects/.lock"),
            "要点名是哪把锁：{lines:?}"
        );
        assert!(lines[0].contains("别删"), "{lines:?}");
        for line in &lines {
            for banned in ["rm ", "del ", "unlink", "移除 ", "删掉 "] {
                assert!(
                    !line.contains(banned),
                    "锁是别人正在写的证据，命令不许叫我删它：{line}"
                );
            }
        }
    }

    #[test]
    fn a_missing_object_is_refetched_from_a_peer_not_hand_edited() {
        let lines = commands_store(&StoreError::Missing("abc123".to_string()), ctx());
        assert!(
            lines[0].contains("verify"),
            "先看还有没有别的块坏：{lines:?}"
        );
        assert!(lines.iter().any(|l| l.contains("export")), "{lines:?}");
        assert!(
            lines
                .iter()
                .any(|l| l.contains("import") && l.contains("已有块会跳过")),
            "重取的路径要说清只补差异：{lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("abc123")),
            "要点名是哪个对象"
        );
        for line in &lines {
            for banned in ["pack-", "index.jsonl", "编辑", "手改"] {
                assert!(!line.contains(banned), "不许叫我改内容寻址的文件：{line}");
            }
        }
    }

    #[test]
    fn corrupt_object_advice_leads_with_the_expected_id_it_saw() {
        let lines = commands_store(
            &StoreError::Corrupt {
                expected: "eee".to_string(),
                actual: "fff".to_string(),
            },
            ctx(),
        );
        assert!(
            lines[0].contains("eee") && lines[0].contains("fff"),
            "{lines:?}"
        );
        assert!(lines.len() >= 3, "坏了还得给出怎么补回来：{lines:?}");
    }

    fn bundle_cases() -> Vec<BundleError> {
        vec![
            BundleError::Io(std::io::Error::other("写不动")),
            BundleError::Store(StoreError::Missing("abc".to_string())),
            BundleError::BadMagic,
            BundleError::UnsupportedSchema(9),
            BundleError::Truncated,
            BundleError::Corrupt {
                expected: "aaa".to_string(),
                actual: "bbb".to_string(),
            },
            BundleError::MissingTree("ddd".to_string()),
        ]
    }

    #[test]
    fn bundle_kinds_are_distinct_except_the_delegating_one() {
        let mut seen = BTreeSet::new();
        for err in bundle_cases() {
            let name = kind_bundle(&err);
            if matches!(err, BundleError::Store(_)) {
                // 转发型与里面那层共用同一个值（同一条根因就该是同一个分支）。
                assert_eq!(name, "store_missing_object", "{name}");
                continue;
            }
            assert!(seen.insert(name), "两条包判决共用一个 kind：{name}");
        }
        assert!(seen.contains("bundle_bad_magic"));
        assert!(seen.contains("bundle_unsupported_schema"));
        assert!(seen.contains("bundle_truncated"));
        assert!(seen.contains("bundle_missing_tree"));
    }

    #[test]
    fn a_truncated_bundle_retries_import_before_reexporting() {
        let lines = commands_bundle(&BundleError::Truncated, ctx());
        assert!(lines[0].contains("import"), "断点续传是第一条：{lines:?}");
        assert!(lines[1].contains("export"), "补不回才重导：{lines:?}");
    }

    #[test]
    fn an_unreadable_bundle_names_what_it_is_not() {
        let lines = commands_bundle(&BundleError::BadMagic, ctx());
        assert!(
            lines[0].contains("TVBD"),
            "要说明这文件为什么不被认：{lines:?}"
        );
        let schema = commands_bundle(&BundleError::UnsupportedSchema(9), ctx());
        assert!(
            schema[0].contains("9"),
            "要把读不到的版本号点名：{schema:?}"
        );
    }

    #[test]
    fn worktree_dirty_orders_status_commit_then_force_last() {
        let paths = vec!["a.txt".to_string(), "b.txt".to_string()];
        let err = WorktreeError::Dirty(2, paths.clone());
        assert_eq!(kind_worktree(&err), "worktree_dirty");
        let lines = commands_worktree(&err, ctx());
        assert!(lines[0].contains("status"), "{lines:?}");
        assert!(lines[1].contains("commit"), "想留改动就先入库：{lines:?}");
        assert!(
            lines.last().unwrap().contains("--force"),
            "破坏性选项必须排最后：{lines:?}"
        );
        assert!(lines[0].contains("2 条"), "要说清挡了几条：{lines:?}");
        for path in paths {
            assert!(lines[0].contains(&path), "要点名挡住的文件：{lines:?}");
        }
    }

    #[test]
    fn worktree_and_central_verdicts_delegate_to_the_layer_inside() {
        let inner = WorktreeError::Repo(RepoError::Unclaimed {
            paths: vec!["x.txt".to_string()],
        });
        assert_eq!(kind_worktree(&inner), "unclaimed");
        assert!(
            commands_worktree(&inner, ctx())[0].contains("claim"),
            "转发要连命令一起转：{inner:?}"
        );
        let central = CentralError::Worktree(WorktreeError::Dirty(1, vec!["y".to_string()]));
        assert_eq!(kind_central(&central), "worktree_dirty");
        assert!(
            commands_central(&central, ctx())[0].contains("status"),
            "转发的命令要跟里面那层一致"
        );
        let nff = CentralError::Repo(RepoError::NonFastForward {
            name: "main".to_string(),
            current: "aaaa".to_string(),
            incoming: "bbbb".to_string(),
        });
        assert_eq!(kind_central(&nff), "non_fast_forward");
        assert!(commands_central(&nff, ctx())[0].contains("pull main"));
    }

    #[test]
    fn every_face_explains_with_kind_message_and_runnable_steps() {
        let faces: Vec<(&str, String, serde_json::Value)> = vec![
            (
                "repo",
                explain_any(&RepoError::NothingStaged, ctx()),
                explain_json_any(&RepoError::NothingStaged, ctx()),
            ),
            (
                "store",
                explain_any(&StoreError::Locked("l".to_string()), ctx()),
                explain_json_any(&StoreError::Locked("l".to_string()), ctx()),
            ),
            (
                "bundle",
                explain_any(&BundleError::Truncated, ctx()),
                explain_json_any(&BundleError::Truncated, ctx()),
            ),
            (
                "worktree",
                explain_any(&WorktreeError::Dirty(3, vec!["p".to_string()]), ctx()),
                explain_json_any(&WorktreeError::Dirty(3, vec!["p".to_string()]), ctx()),
            ),
            (
                "central",
                explain_any(&CentralError::Bundle(BundleError::BadMagic), ctx()),
                explain_json_any(&CentralError::Bundle(BundleError::BadMagic), ctx()),
            ),
        ];
        for (face, text, json) in faces {
            assert!(
                text.contains("\n  1. "),
                "{face} 的文字出口没编号步骤：{text}"
            );
            let list = json["remediation"]
                .as_array()
                .unwrap_or_else(|| panic!("{face} 没有 remediation 数组：{json}"));
            assert!(!list.is_empty(), "{face} 一条动作都没给");
            let kind = json["error"]["kind"].as_str().unwrap_or_default();
            assert!(
                kind.contains('_') || kind == "io",
                "{face} 的 kind 不像分支值：{kind}"
            );
            assert!(json["ok"].is_boolean());
            assert!(
                !json["error"]["message"].as_str().unwrap().is_empty(),
                "{face} 要带上原来的判决文字"
            );
        }
        // `explain` / `explain_json` 是同一出口在 RepoError 上的特例，不许分叉出第二种形状。
        assert_eq!(
            explain(&RepoError::NothingStaged, ctx()),
            explain_any(&RepoError::NothingStaged, ctx())
        );
    }

    #[test]
    fn the_git_bridge_face_returns_the_external_failure_and_a_way_around_it() {
        let err = GitError::Git {
            args: "fast-export --all".to_string(),
            stderr: "fatal: bad object abc".to_string(),
        };
        assert_eq!(kind_git(&err), "git_command_failed");
        let lines = commands_git(&err, ctx());
        assert!(
            lines[0].contains("fatal: bad object abc"),
            "外部 git 的 stderr 要原样带回来，不然只能重跑一次才知道红在哪：{lines:?}"
        );
        assert!(
            lines[1].contains("export"),
            "要指出不依赖 git 的那条路：{lines:?}"
        );
        let empty = commands_git(&GitError::NoCommits, ctx());
        assert!(
            empty.iter().any(|l| l.contains("commit")),
            "空仓的下一步是先把东西提交进去：{empty:?}"
        );
        let bad = commands_git(&GitError::BadPath("path".to_string()), ctx());
        assert!(bad[0].contains("export"), "{bad:?}");
        // 转发型判决与里面那层共用同一个值（同一条根因就该是同一个分支）。
        assert_eq!(
            kind_git(&GitError::Store(StoreError::Locked("l".to_string()))),
            "store_locked"
        );
        assert_eq!(
            kind_git(&GitError::Repo(RepoError::NothingStaged)),
            "nothing_staged"
        );
    }

    #[test]
    fn merge_face_delegates_and_ships_the_inner_action() {
        assert_eq!(
            kind_merge(&MergeError::Repo(RepoError::NothingStaged)),
            "nothing_staged"
        );
        let err = MergeError::Store(StoreError::Missing("abc".to_string()));
        assert_eq!(kind_merge(&err), "store_missing_object");
        let lines = commands_merge(&err, ctx());
        assert!(lines[0].contains("verify"), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("import")), "{lines:?}");
    }
}
