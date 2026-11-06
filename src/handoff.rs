//! 交接包：把一个提交的上下文打成可审计的包，`verify` 逐项复核。
//!
//! 两种形态共用同一套部件与判据：
//! - **目录包**（`handoff --out DIR`）：`manifest.json` + 各部件文件，便于人读/逐件抽查；
//! - **单文件包**（`handoff --out FILE.tvhp --bundle`）：`TVHP` 容器，便于一条命令搬运（见 `handoff_bundle`）。
//!
//! 包里有：commit / tree / parents、intent、claims、冲突面、diff、改动文件的文件映射与内容。
//! `manifest.json` 记每个部件的对象 id、相对路径、字节数与来源。
//! 判据：删掉包里任意一个部件、改一个字节、改清单里的 id，`verify` 都判红；
//! 交付方不需要再跑五六条命令去拼上下文。

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::handoff_bundle;
use crate::hash::Hash;
use crate::model::{Commit, Intent};
use crate::remediation::{Context, Remediable};
use crate::repo::{Repo, RepoError};
use crate::store::StoreError;
use crate::worktree::{Change, Kind, WorktreeError};

const SCHEMA: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum HandoffError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("仓库: {0}")]
    Repo(#[from] RepoError),
    #[error("对象库: {0}")]
    Store(#[from] StoreError),
    #[error("工作树: {0}")]
    Worktree(#[from] WorktreeError),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("清单: {0}")]
    Manifest(String),
    #[error("缺件: {0}")]
    Missing(String),
    #[error("哈希不符: {0}")]
    HashMismatch(String),
    #[error("悬空引用: {0}")]
    Dangling(String),
    #[error("提交: {0}")]
    Commit(String),
    #[error("路径不安全: {0}")]
    UnsafePath(String),
    #[error("参数: {0}")]
    Usage(String),
}

impl Remediable for HandoffError {
    fn kind(&self) -> &'static str {
        match self {
            Self::Repo(err) => err.kind(),
            Self::Usage(_) => "handoff_usage",
            Self::Io(_) => "handoff_io",
            Self::Store(_) | Self::Worktree(_) => "handoff_repo",
            Self::Json(_) | Self::Manifest(_) => "handoff_manifest",
            Self::Missing(_) => "handoff_missing",
            Self::HashMismatch(_) => "handoff_hash",
            Self::Dangling(_) => "handoff_dangling",
            Self::Commit(_) => "handoff_commit",
            Self::UnsafePath(_) => "handoff_path",
        }
    }

    fn commands(&self, ctx: Context<'_>) -> Vec<String> {
        if let Self::Repo(err) = self {
            return err.commands(ctx);
        }
        if let Self::Usage(_) = self {
            return vec![
                format!(
                    "trit-vcs handoff <提交id> --out <包目录|FILE.tvhp> [--bundle] --repo {}",
                    ctx.dir.display()
                ),
                format!(
                    "trit-vcs handoff-verify <包目录|FILE.tvhp> --repo {}",
                    ctx.dir.display()
                ),
            ];
        }
        vec![
            format!(
                "trit-vcs handoff-verify <包目录|FILE.tvhp> --repo {}",
                ctx.dir.display()
            ),
            "包是派生物，不要手改；重做：`trit-vcs handoff <提交id> --out <包目录|FILE.tvhp>`"
                .to_string(),
        ]
    }
}

/// 一个部件：对象 id、包内相对路径、字节数与来源。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    pub name: String,
    pub kind: String,
    pub object: String,
    pub path: String,
    pub bytes: u64,
    pub source: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub schema: u32,
    pub package_id: String,
    pub commit: String,
    pub tree: String,
    pub parents: Vec<String>,
    pub components: Vec<Component>,
}

#[derive(Serialize)]
struct ManifestBody<'a> {
    schema: u32,
    commit: &'a str,
    tree: &'a str,
    parents: &'a [String],
    components: &'a [Component],
}

impl Manifest {
    /// 包 id = 清单主体（不含自身）的 BLAKE3；任何字段改动都会让 id 变。
    pub fn recompute_package_id(&self) -> Result<Hash, HandoffError> {
        let body = ManifestBody {
            schema: self.schema,
            commit: &self.commit,
            tree: &self.tree,
            parents: &self.parents,
            components: &self.components,
        };
        Ok(Hash::of(&serde_json::to_vec(&body)?))
    }
}

/// 冲突面：多父提交里被不止一个父改到的路径 + 本次认领。
/// 单父/根提交的 `shared_changed_paths` 为空；它不是"合并结果"，是"接手时必须先看的面"。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conflicts {
    pub parents: Vec<String>,
    pub shared_changed_paths: Vec<String>,
    pub claims: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct BuildReport {
    pub package_id: Hash,
    pub commit: Hash,
    pub components: usize,
    pub out: PathBuf,
}

#[derive(Clone, Debug)]
pub struct VerifyReport {
    pub package_id: Hash,
    pub commit: Hash,
    pub components: usize,
    pub objects: usize,
}

/// 装配好的包：清单 + 各部件字节 + 包 id。目录包与单文件包都从这里写出，判据只有一份。
struct Package {
    manifest: Manifest,
    pieces: Vec<(Component, Vec<u8>)>,
    package_id: Hash,
}

/// 部件内容的来源：目录（逐件读盘）或单文件包（已在内存里解出的 rel→bytes）。
/// `verify` 的语义判据对两种来源逐字相同——单文件不是"另一套校验"。
enum PackageFiles {
    Dir(PathBuf),
    Bundle(BTreeMap<String, Vec<u8>>),
}

impl PackageFiles {
    fn read(&self, rel: &str) -> Result<Vec<u8>, HandoffError> {
        let cleaned = safe_rel(rel)?;
        match self {
            Self::Dir(root) => fs::read(root.join(cleaned))
                .map_err(|err| HandoffError::Missing(format!("{rel}: {err}"))),
            Self::Bundle(map) => map
                .get(rel)
                .cloned()
                .ok_or_else(|| HandoffError::Missing(rel.to_string())),
        }
    }
}

fn safe_rel(rel: &str) -> Result<PathBuf, HandoffError> {
    let cleaned = rel.replace('\\', "/");
    if cleaned.is_empty()
        || cleaned.starts_with('/')
        || cleaned
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(HandoffError::UnsafePath(rel.to_string()));
    }
    Ok(PathBuf::from(cleaned))
}

fn write_bytes(package: &Path, rel: &str, bytes: &[u8]) -> Result<(), HandoffError> {
    let path = package.join(safe_rel(rel)?);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    Ok(())
}

struct Piece<'a> {
    name: String,
    kind: &'a str,
    object: Hash,
    rel: String,
    bytes: &'a [u8],
    source: String,
}

fn collect_component(pieces: &mut Vec<(Component, Vec<u8>)>, piece: Piece<'_>) {
    pieces.push((
        Component {
            name: piece.name,
            kind: piece.kind.to_string(),
            object: piece.object.to_hex(),
            path: piece.rel,
            bytes: piece.bytes.len() as u64,
            source: piece.source,
        },
        piece.bytes.to_vec(),
    ));
}

fn decode_tree(bytes: &[u8], label: &str) -> Result<BTreeMap<String, Hash>, HandoffError> {
    serde_json::from_slice(bytes).map_err(|err| HandoffError::Manifest(format!("{label}: {err}")))
}

/// 两棵树的路径级 diff（与 `worktree::diff` 同口径：按内容 id 比，排序稳定）。
fn diff_trees(left: &BTreeMap<String, Hash>, right: &BTreeMap<String, Hash>) -> Vec<Change> {
    let mut out = Vec::new();
    for (path, id) in right {
        match left.get(path) {
            None => out.push(Change {
                kind: Kind::Added,
                path: path.clone(),
            }),
            Some(old) if old != id => out.push(Change {
                kind: Kind::Modified,
                path: path.clone(),
            }),
            Some(_) => {}
        }
    }
    for path in left.keys() {
        if !right.contains_key(path) {
            out.push(Change {
                kind: Kind::Deleted,
                path: path.clone(),
            });
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

fn conflicts_of(
    commit: &Commit,
    parent_trees: &[BTreeMap<String, Hash>],
    commit_tree: &BTreeMap<String, Hash>,
) -> Conflicts {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for parent in parent_trees {
        for change in diff_trees(parent, commit_tree) {
            *counts.entry(change.path).or_default() += 1;
        }
    }
    let mut shared: Vec<String> = counts
        .into_iter()
        .filter(|(_, count)| *count >= 2)
        .map(|(path, _)| path)
        .collect();
    shared.sort();
    Conflicts {
        parents: commit.parents.iter().map(|id| id.to_hex()).collect(),
        shared_changed_paths: shared,
        claims: commit.claims.clone(),
    }
}

fn find_one<'a>(manifest: &'a Manifest, kind: &str) -> Result<&'a Component, HandoffError> {
    let mut found = manifest.components.iter().filter(|c| c.kind == kind);
    let first = found
        .next()
        .ok_or_else(|| HandoffError::Manifest(format!("缺少 kind={kind} 的部件")))?;
    if found.next().is_some() {
        return Err(HandoffError::Manifest(format!(
            "kind={kind} 的部件不止一个"
        )));
    }
    Ok(first)
}

fn find_named<'a>(manifest: &'a Manifest, name: &str) -> Result<&'a Component, HandoffError> {
    manifest
        .components
        .iter()
        .find(|c| c.name == name)
        .ok_or_else(|| HandoffError::Manifest(format!("缺少部件 {name}")))
}

fn read_component(files: &PackageFiles, component: &Component) -> Result<Vec<u8>, HandoffError> {
    files.read(&component.path).map_err(|err| match err {
        HandoffError::Missing(_) => {
            HandoffError::Missing(format!("{}（{}）", component.name, component.path))
        }
        other => other,
    })
}

/// 装配：从对象库读出所有部件与清单（不写盘）。目录包与单文件包共用这一份。
fn assemble(repo: &Repo, commit_id: &Hash) -> Result<Package, HandoffError> {
    let commit = repo.commit_at(commit_id)?;
    let commit_bytes = commit.encode()?;
    let actual_commit = Hash::of(&commit_bytes);
    if actual_commit != *commit_id {
        return Err(HandoffError::Commit(format!(
            "提交内容 hash 与 id 不一致: {} != {}",
            actual_commit.short(),
            commit_id.short()
        )));
    }
    let mut pieces: Vec<(Component, Vec<u8>)> = Vec::new();

    // commit + tree
    collect_component(
        &mut pieces,
        Piece {
            name: "commit".to_string(),
            kind: "commit",
            object: actual_commit,
            rel: format!("objects/{}.json", actual_commit.to_hex()),
            bytes: &commit_bytes,
            source: "commit 对象".to_string(),
        },
    );
    let tree_bytes = repo.store().get_chunk(&commit.tree)?;
    let tree_entries = decode_tree(&tree_bytes, "tree 对象")?;
    collect_component(
        &mut pieces,
        Piece {
            name: "tree".to_string(),
            kind: "tree",
            object: commit.tree,
            rel: format!("objects/{}.json", commit.tree.to_hex()),
            bytes: &tree_bytes,
            source: "commit.tree 对象".to_string(),
        },
    );

    // parents：commit + tree 都进包，verify 不依赖对象库也能重算 diff/冲突面。
    let mut parent_trees: Vec<BTreeMap<String, Hash>> = Vec::new();
    let mut parent_tree_ids: Vec<Hash> = Vec::new();
    for (index, parent) in commit.parents.iter().enumerate() {
        let parent_commit = repo.commit_at(parent)?;
        let parent_bytes = parent_commit.encode()?;
        let actual_parent = Hash::of(&parent_bytes);
        if actual_parent != *parent {
            return Err(HandoffError::Commit(format!(
                "父提交 {index} 内容 hash 与 id 不一致"
            )));
        }
        collect_component(
            &mut pieces,
            Piece {
                name: format!("parent-commit:{index}"),
                kind: "parent-commit",
                object: actual_parent,
                rel: format!("objects/{}.json", actual_parent.to_hex()),
                bytes: &parent_bytes,
                source: format!("父提交 {index}"),
            },
        );
        let parent_tree_bytes = repo.store().get_chunk(&parent_commit.tree)?;
        let parent_entries = decode_tree(&parent_tree_bytes, &format!("父提交 {index} 的树"))?;
        parent_tree_ids.push(parent_commit.tree);
        collect_component(
            &mut pieces,
            Piece {
                name: format!("parent-tree:{index}"),
                kind: "parent-tree",
                object: parent_commit.tree,
                rel: format!("objects/{}.json", parent_commit.tree.to_hex()),
                bytes: &parent_tree_bytes,
                source: format!("父提交 {index} 的树"),
            },
        );
        parent_trees.push(parent_entries);
    }

    // intent / claims
    let intent_bytes = serde_json::to_vec(&commit.intent)?;
    let intent_id = Hash::of(&intent_bytes);
    collect_component(
        &mut pieces,
        Piece {
            name: "intent".to_string(),
            kind: "intent",
            object: intent_id,
            rel: "intent.json".to_string(),
            bytes: &intent_bytes,
            source: "commit.intent".to_string(),
        },
    );
    let claims_bytes = serde_json::to_vec(&commit.claims)?;
    let claims_id = Hash::of(&claims_bytes);
    collect_component(
        &mut pieces,
        Piece {
            name: "claims".to_string(),
            kind: "claims",
            object: claims_id,
            rel: "claims.json".to_string(),
            bytes: &claims_bytes,
            source: "commit.claims".to_string(),
        },
    );

    // diff / conflicts
    let left = parent_trees.first().cloned().unwrap_or_default();
    let changes = diff_trees(&left, &tree_entries);
    let diff_bytes = serde_json::to_vec(&changes)?;
    let diff_id = Hash::of(&diff_bytes);
    collect_component(
        &mut pieces,
        Piece {
            name: "diff".to_string(),
            kind: "diff",
            object: diff_id,
            rel: "diff.json".to_string(),
            bytes: &diff_bytes,
            source: "commit 相对第一个父的路径级 diff".to_string(),
        },
    );
    let conflicts = conflicts_of(&commit, &parent_trees, &tree_entries);
    let conflicts_bytes = serde_json::to_vec(&conflicts)?;
    let conflicts_id = Hash::of(&conflicts_bytes);
    collect_component(
        &mut pieces,
        Piece {
            name: "conflicts".to_string(),
            kind: "conflicts",
            object: conflicts_id,
            rel: "conflicts.json".to_string(),
            bytes: &conflicts_bytes,
            source: "多父改动交集 + 认领".to_string(),
        },
    );

    // 改动文件：文件映射（树里那个 id）+ 内容各一份。
    // 文件映射 id 是树引用；内容 hash 是人读/复核用的派生物。
    for change in &changes {
        let (id, source) = match change.kind {
            Kind::Added | Kind::Modified => (tree_entries.get(&change.path), "commit tree"),
            Kind::Deleted => (left.get(&change.path), "parent tree"),
        };
        let id = id.ok_or_else(|| {
            HandoffError::Dangling(format!("{} 在 {source} 里找不到对象", change.path))
        })?;
        let map_bytes = repo.store().get_chunk(id)?;
        let prefix = if change.kind == Kind::Deleted {
            "file-map-old"
        } else {
            "file-map"
        };
        collect_component(
            &mut pieces,
            Piece {
                name: format!("{prefix}:{}", change.path),
                kind: "file-map",
                object: *id,
                rel: format!("objects/{}.json", id.to_hex()),
                bytes: &map_bytes,
                source: format!("{source} {} 的文件映射", change.path),
            },
        );
        let content = repo.store().get_file(id)?;
        let content_id = Hash::of(&content);
        let prefix = if change.kind == Kind::Deleted {
            "file-old"
        } else {
            "file"
        };
        collect_component(
            &mut pieces,
            Piece {
                name: format!("{prefix}:{}", change.path),
                kind: "file",
                object: content_id,
                rel: format!("objects/{}.bin", content_id.to_hex()),
                bytes: &content,
                source: format!("{source} {} 的内容（文件映射 {}）", change.path, id.short()),
            },
        );
    }

    let schema = SCHEMA;
    let commit_hex = commit_id.to_hex();
    let tree_hex = commit.tree.to_hex();
    let parents: Vec<String> = commit.parents.iter().map(|id| id.to_hex()).collect();
    let components: Vec<Component> = pieces.iter().map(|(c, _)| c.clone()).collect();
    let body = ManifestBody {
        schema,
        commit: &commit_hex,
        tree: &tree_hex,
        parents: &parents,
        components: &components,
    };
    let package_id = Hash::of(&serde_json::to_vec(&body)?);
    let manifest = Manifest {
        schema,
        package_id: package_id.to_hex(),
        commit: commit_hex,
        tree: tree_hex,
        parents,
        components,
    };
    Ok(Package {
        manifest,
        pieces,
        package_id,
    })
}

/// 建目录包：写出所有部件与 `manifest.json`。
pub fn build(repo: &Repo, commit_id: &Hash, out: &Path) -> Result<BuildReport, HandoffError> {
    let package = assemble(repo, commit_id)?;
    fs::create_dir_all(out.join("objects"))?;
    for (component, bytes) in &package.pieces {
        write_bytes(out, &component.path, bytes)?;
    }
    fs::write(
        out.join("manifest.json"),
        serde_json::to_vec_pretty(&package.manifest)?,
    )?;
    Ok(BuildReport {
        package_id: package.package_id,
        commit: *commit_id,
        components: package.manifest.components.len(),
        out: out.to_path_buf(),
    })
}

/// 建单文件包（`TVHP`）：与目录包同一份装配，只是写成一个文件。
pub fn build_bundle(
    repo: &Repo,
    commit_id: &Hash,
    out: &Path,
) -> Result<BuildReport, HandoffError> {
    let package = assemble(repo, commit_id)?;
    handoff_bundle::write_file(out, &package.manifest, &package.pieces)?;
    Ok(BuildReport {
        package_id: package.package_id,
        commit: *commit_id,
        components: package.manifest.components.len(),
        out: out.to_path_buf(),
    })
}

/// 复核：包内自洽 + （可选）对象库引用都在。目录与单文件自动识别，判据同一套。
pub fn verify(package: &Path, repo: Option<&Repo>) -> Result<VerifyReport, HandoffError> {
    let files = if package.is_dir() {
        PackageFiles::Dir(package.to_path_buf())
    } else {
        PackageFiles::Bundle(handoff_bundle::read_file(package)?)
    };
    verify_files(&files, repo)
}

fn verify_files(files: &PackageFiles, repo: Option<&Repo>) -> Result<VerifyReport, HandoffError> {
    let manifest_bytes = files.read("manifest.json")?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|err| HandoffError::Manifest(format!("manifest.json: {err}")))?;
    if manifest.schema != SCHEMA {
        return Err(HandoffError::Manifest(format!(
            "schema {} != {SCHEMA}",
            manifest.schema
        )));
    }
    let expected_package = manifest.recompute_package_id()?;
    if expected_package.to_hex() != manifest.package_id {
        return Err(HandoffError::HashMismatch(format!(
            "manifest.package_id: {} != {}",
            expected_package.short(),
            manifest.package_id
        )));
    }

    let mut objects: BTreeMap<String, &Component> = BTreeMap::new();
    for component in &manifest.components {
        let bytes = read_component(files, component)?;
        if bytes.len() as u64 != component.bytes {
            return Err(HandoffError::HashMismatch(format!(
                "{}: 字节数 {} != {}",
                component.name,
                bytes.len(),
                component.bytes
            )));
        }
        let actual = Hash::of(&bytes).to_hex();
        if actual != component.object {
            return Err(HandoffError::HashMismatch(format!(
                "{}: {} != {}",
                component.name, actual, component.object
            )));
        }
        objects.insert(component.object.clone(), component);
    }

    let commit_component = find_one(&manifest, "commit")?;
    let commit_bytes = read_component(files, commit_component)?;
    let commit = Commit::decode(&commit_bytes)
        .map_err(|err| HandoffError::Commit(format!("commit 对象: {err}")))?;
    let commit_id = Hash::of(&commit_bytes);
    if commit_id.to_hex() != manifest.commit {
        return Err(HandoffError::Commit(format!(
            "提交 id 不符: {} != {}",
            commit_id.short(),
            manifest.commit
        )));
    }
    if commit.tree.to_hex() != manifest.tree {
        return Err(HandoffError::Commit(format!(
            "commit.tree 与清单不符: {} != {}",
            commit.tree.short(),
            manifest.tree
        )));
    }
    let parents: Vec<String> = commit.parents.iter().map(|id| id.to_hex()).collect();
    if parents != manifest.parents {
        return Err(HandoffError::Commit(
            "commit.parents 与清单不符".to_string(),
        ));
    }

    let tree_component = find_one(&manifest, "tree")?;
    let tree_bytes = read_component(files, tree_component)?;
    let tree_entries = decode_tree(&tree_bytes, "tree 对象")?;

    let mut parent_trees: Vec<BTreeMap<String, Hash>> = Vec::new();
    let mut parent_tree_ids: Vec<Hash> = Vec::new();
    for (index, parent) in commit.parents.iter().enumerate() {
        let parent_component = find_named(&manifest, &format!("parent-commit:{index}"))?;
        let parent_bytes = read_component(files, parent_component)?;
        let parent_commit = Commit::decode(&parent_bytes)
            .map_err(|err| HandoffError::Commit(format!("父提交 {index}: {err}")))?;
        let actual = Hash::of(&parent_bytes);
        if actual != *parent {
            return Err(HandoffError::Commit(format!(
                "父提交 {index} id 不符: {} != {}",
                actual.short(),
                parent.short()
            )));
        }
        let parent_tree_component = find_named(&manifest, &format!("parent-tree:{index}"))?;
        let parent_tree_bytes = read_component(files, parent_tree_component)?;
        let actual_tree = Hash::of(&parent_tree_bytes);
        if actual_tree != parent_commit.tree {
            return Err(HandoffError::Commit(format!("父提交 {index} 的树 id 不符")));
        }
        let entries = decode_tree(&parent_tree_bytes, &format!("父提交 {index} 的树"))?;
        parent_tree_ids.push(parent_commit.tree);
        parent_trees.push(entries);
    }

    let intent_component = find_one(&manifest, "intent")?;
    let intent: Option<Intent> = serde_json::from_slice(&read_component(files, intent_component)?)
        .map_err(|err| HandoffError::Manifest(format!("intent: {err}")))?;
    if intent != commit.intent {
        return Err(HandoffError::Manifest(
            "intent 与 commit.intent 不一致".to_string(),
        ));
    }
    let claims_component = find_one(&manifest, "claims")?;
    let claims: Vec<String> = serde_json::from_slice(&read_component(files, claims_component)?)
        .map_err(|err| HandoffError::Manifest(format!("claims: {err}")))?;
    if claims != commit.claims {
        return Err(HandoffError::Manifest(
            "claims 与 commit.claims 不一致".to_string(),
        ));
    }

    let diff_component = find_one(&manifest, "diff")?;
    let changes: Vec<Change> = serde_json::from_slice(&read_component(files, diff_component)?)
        .map_err(|err| HandoffError::Manifest(format!("diff: {err}")))?;
    let left = parent_trees.first().cloned().unwrap_or_default();
    let expected_changes = diff_trees(&left, &tree_entries);
    if changes != expected_changes {
        return Err(HandoffError::Manifest(
            "diff 与 commit/parent 树不一致".to_string(),
        ));
    }
    let conflicts_component = find_one(&manifest, "conflicts")?;
    let conflicts: Conflicts = serde_json::from_slice(&read_component(files, conflicts_component)?)
        .map_err(|err| HandoffError::Manifest(format!("conflicts: {err}")))?;
    let expected_conflicts = conflicts_of(&commit, &parent_trees, &tree_entries);
    if conflicts != expected_conflicts {
        return Err(HandoffError::Manifest(
            "conflicts 与 commit/parent 树不一致".to_string(),
        ));
    }

    let mut referenced: Vec<String> = vec![manifest.tree.clone()];
    referenced.extend(commit.parents.iter().map(|id| id.to_hex()));
    referenced.extend(parent_tree_ids.iter().map(|id| id.to_hex()));
    for change in &changes {
        let id = match change.kind {
            Kind::Added | Kind::Modified => tree_entries.get(&change.path),
            Kind::Deleted => left.get(&change.path),
        };
        let id =
            id.ok_or_else(|| HandoffError::Dangling(format!("{} 在树里找不到对象", change.path)))?;
        referenced.push(id.to_hex());
    }
    for id in referenced {
        if !objects.contains_key(&id) {
            return Err(HandoffError::Dangling(format!("{id} 不在包里")));
        }
        if let Some(repo) = repo {
            let hash = Hash::from_hex(&id)
                .ok_or_else(|| HandoffError::Dangling(format!("坏的 id: {id}")))?;
            if !repo.store().has_chunk(&hash) {
                return Err(HandoffError::Dangling(format!("{id} 不在对象库")));
            }
        }
    }
    if let Some(repo) = repo {
        repo.commit_at(&commit_id)?;
    }

    let package_id = Hash::from_hex(&manifest.package_id)
        .ok_or_else(|| HandoffError::Manifest("manifest.package_id 不是 64 位 hex".to_string()))?;
    Ok(VerifyReport {
        package_id,
        commit: commit_id,
        components: manifest.components.len(),
        objects: objects.len(),
    })
}
