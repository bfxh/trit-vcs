//! TVAB：带严格资源上限、逐件 BLAKE3 校验和尾字节拒绝的离线审计包容器。

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::checkpoint::external::ExternalAnchor;
use crate::hash::Hash;
use crate::repo::Repo;

use super::BundleError;

pub const MAGIC: &[u8; 4] = b"TVAB";
pub const SCHEMA: u32 = 1;
pub const MAX_BUNDLE_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PIECES: usize = 100_000;
pub const MAX_PIECE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_EVENTS: usize = 1_000_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PieceRef {
    pub name: String,
    pub hash: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: u32,
    pub event_count: usize,
    pub state_digest: String,
    pub anchor: ExternalAnchor,
    pub pieces: Vec<PieceRef>,
}

#[derive(Debug)]
pub(crate) struct Piece {
    pub(crate) reference: PieceRef,
    pub(crate) bytes: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct Decoded {
    pub(crate) manifest: Manifest,
    pub(crate) manifest_bytes: Vec<u8>,
    pub(crate) pieces: Vec<Piece>,
    pub(crate) bytes: u64,
}

pub(crate) fn write_new_file(
    path: &Path,
    manifest: &Manifest,
    pieces: &[Piece],
) -> Result<u64, BundleError> {
    validate(manifest, pieces)?;
    let (temp_path, mut file) = create_sibling(path)?;
    let result = (|| -> Result<u64, BundleError> {
        write_all(&mut file, manifest, pieces)?;
        file.sync_all()?;
        let bytes = file.metadata()?.len();
        drop(file);
        publish_new(&temp_path, path)?;
        Ok(bytes)
    })();
    if result.is_err() {
        cleanup_partial(&temp_path);
    }
    result
}

fn create_sibling(path: &Path) -> Result<(PathBuf, fs::File), BundleError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| BundleError::invalid("audit_bundle_bad", "导出路径没有文件名"))?;
    for _ in 0..8 {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random)
            .map_err(|err| BundleError::invalid("audit_bundle_io", err.to_string()))?;
        let mut temp_name = OsString::from(".");
        temp_name.push(name);
        temp_name.push(format!(".tvab-{}.tmp", Hash::of(&random).to_hex()));
        let temp_path = parent.join(temp_name);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
            Ok(file) => return Ok((temp_path, file)),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(BundleError::invalid(
                    "audit_bundle_io",
                    format!("创建同目录临时文件 {} 失败：{err}", temp_path.display()),
                ));
            }
        }
    }
    Err(BundleError::invalid(
        "audit_bundle_io",
        "无法创建唯一同目录临时文件",
    ))
}

fn publish_new(temp_path: &Path, path: &Path) -> Result<(), BundleError> {
    // hard_link 是跨平台的 create-new 发布；rename 在 POSIX 会覆盖目标。
    match fs::hard_link(temp_path, path) {
        Ok(()) => {
            cleanup_partial(temp_path);
            Ok(())
        }
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Err(BundleError::invalid(
            "audit_bundle_exists",
            format!("{} 已存在；拒绝覆盖", path.display()),
        )),
        Err(err) => Err(BundleError::invalid(
            "audit_bundle_io",
            format!("发布 TVAB 到 {} 失败：{err}", path.display()),
        )),
    }
}

fn cleanup_partial(path: &Path) {
    if let Err(err) = fs::remove_file(path) {
        eprintln!("TVAB 临时文件 {} 清理失败：{err}", path.display());
    }
}

pub(crate) fn open_regular_file(path: &Path) -> Result<fs::File, BundleError> {
    let before = fs::symlink_metadata(path)?;
    if !before.file_type().is_file() {
        return Err(BundleError::invalid(
            "audit_bundle_bad",
            format!("{} 不是普通文件", path.display()),
        ));
    }
    let file = fs::File::open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(BundleError::invalid(
            "audit_bundle_bad",
            format!("{} 打开后不是普通文件", path.display()),
        ));
    }
    Ok(file)
}

pub(crate) fn write_all<W: Write>(
    out: &mut W,
    manifest: &Manifest,
    pieces: &[Piece],
) -> Result<(), BundleError> {
    validate(manifest, pieces)?;
    let manifest_bytes = serde_json::to_vec(manifest)?;
    if manifest_bytes.len() > MAX_MANIFEST_BYTES {
        return Err(BundleError::invalid(
            "audit_bundle_too_large",
            format!("manifest 长度 {} 超过上限", manifest_bytes.len()),
        ));
    }
    let manifest_len = u32::try_from(manifest_bytes.len()).map_err(|_| {
        BundleError::invalid("audit_bundle_too_large", "manifest 超过 u32 长度上限")
    })?;
    let piece_count = u32::try_from(pieces.len())
        .map_err(|_| BundleError::invalid("audit_bundle_too_large", "部件数超过 u32 上限"))?;
    let payload_bytes = pieces.iter().try_fold(0u64, |total, piece| {
        total.checked_add(piece.bytes.len() as u64)
    });
    let package_bytes = payload_bytes
        .and_then(|payload| payload.checked_add(16 + manifest_bytes.len() as u64))
        .and_then(|bytes| bytes.checked_add(pieces.len() as u64 * 36));
    if package_bytes.is_none_or(|bytes| bytes > MAX_BUNDLE_BYTES) {
        return Err(BundleError::invalid(
            "audit_bundle_too_large",
            "TVAB 序列化总大小超过上限",
        ));
    }
    out.write_all(MAGIC)?;
    out.write_all(&SCHEMA.to_le_bytes())?;
    out.write_all(&manifest_len.to_le_bytes())?;
    out.write_all(&manifest_bytes)?;
    out.write_all(&piece_count.to_le_bytes())?;
    for piece in pieces {
        let hash = parse_hash(&piece.reference.hash)?;
        let len = u32::try_from(piece.bytes.len()).map_err(|_| {
            BundleError::invalid("audit_bundle_too_large", "单个部件超过 u32 长度上限")
        })?;
        out.write_all(hash.as_bytes())?;
        out.write_all(&len.to_le_bytes())?;
        out.write_all(&piece.bytes)?;
    }
    Ok(())
}

pub(crate) fn read_file(path: &Path) -> Result<Decoded, BundleError> {
    let mut file = open_regular_file(path)?;
    let size = file.metadata()?.len();
    if size > MAX_BUNDLE_BYTES {
        return Err(BundleError::invalid(
            "audit_bundle_too_large",
            format!("包大小 {size} 超过 {} 字节", MAX_BUNDLE_BYTES),
        ));
    }
    read_all(&mut file)
}

pub(crate) fn read_all<R: Read>(input: &mut R) -> Result<Decoded, BundleError> {
    let mut magic = [0u8; 4];
    read_exact(input, &mut magic)?;
    if &magic != MAGIC {
        return Err(BundleError::invalid(
            "audit_bundle_bad",
            "不是 TVAB 审计包（magic 不对）",
        ));
    }
    let schema = read_u32(input)?;
    if schema != SCHEMA {
        return Err(BundleError::invalid(
            "audit_bundle_bad",
            format!("不支持的 TVAB schema：{schema}"),
        ));
    }
    let manifest_len = read_u32(input)? as usize;
    if manifest_len > MAX_MANIFEST_BYTES {
        return Err(BundleError::invalid(
            "audit_bundle_too_large",
            format!("manifest 长度 {manifest_len} 超过上限"),
        ));
    }
    let mut manifest_bytes = vec![0u8; manifest_len];
    read_exact(input, &mut manifest_bytes)?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;
    validate_manifest(&manifest)?;
    let piece_count = read_u32(input)? as usize;
    if piece_count != manifest.pieces.len() {
        return Err(BundleError::invalid(
            "audit_bundle_bad",
            format!(
                "容器部件数 {piece_count} 与 manifest {} 不符",
                manifest.pieces.len()
            ),
        ));
    }
    let mut pieces = Vec::with_capacity(piece_count);
    let mut total = 16u64 + manifest_len as u64;
    for reference in &manifest.pieces {
        let expected_hash = parse_hash(&reference.hash)?;
        let mut id_bytes = [0u8; 32];
        read_exact(input, &mut id_bytes)?;
        let header_hash = Hash::from_bytes(id_bytes);
        if header_hash != expected_hash {
            return Err(BundleError::invalid(
                "audit_bundle_hash_mismatch",
                format!("部件 {} 的头部摘要与 manifest 不符", reference.name),
            ));
        }
        let len = read_u32(input)? as usize;
        if len > MAX_PIECE_BYTES {
            return Err(BundleError::invalid(
                "audit_bundle_too_large",
                format!("部件 {} 长度 {len} 超过上限", reference.name),
            ));
        }
        if reference.bytes != len as u64 {
            return Err(BundleError::invalid(
                "audit_bundle_bad",
                format!("部件 {} 的长度与 manifest 不符", reference.name),
            ));
        }
        total = total
            .checked_add(36 + len as u64)
            .ok_or_else(|| BundleError::invalid("audit_bundle_too_large", "部件总长度溢出"))?;
        if total > MAX_BUNDLE_BYTES {
            return Err(BundleError::invalid(
                "audit_bundle_too_large",
                format!("TVAB 总长度 {total} 超过上限"),
            ));
        }
        let mut bytes = vec![0u8; len];
        read_exact(input, &mut bytes)?;
        let actual = Hash::of(&bytes);
        if actual != expected_hash {
            return Err(BundleError::invalid(
                "audit_bundle_hash_mismatch",
                format!(
                    "部件 {} 内容摘要不符：期望 {}，实际 {}",
                    reference.name,
                    expected_hash.short(),
                    actual.short()
                ),
            ));
        }
        pieces.push(Piece {
            reference: reference.clone(),
            bytes,
        });
    }
    let mut trailing = [0u8; 1];
    if input.read(&mut trailing)? != 0 {
        return Err(BundleError::invalid(
            "audit_bundle_trailing",
            "TVAB 容器末尾还有未声明字节",
        ));
    }
    Ok(Decoded {
        manifest,
        manifest_bytes,
        pieces,
        bytes: total,
    })
}

pub(crate) fn validate(manifest: &Manifest, pieces: &[Piece]) -> Result<(), BundleError> {
    validate_manifest(manifest)?;
    if pieces.len() != manifest.pieces.len() {
        return Err(BundleError::invalid(
            "audit_bundle_bad",
            "待写部件数与 manifest 不符",
        ));
    }
    let mut total = 0u64;
    for (piece, reference) in pieces.iter().zip(&manifest.pieces) {
        if &piece.reference != reference {
            return Err(BundleError::invalid(
                "audit_bundle_bad",
                format!("部件 {} 与 manifest 引用不符", reference.name),
            ));
        }
        if piece.bytes.len() > MAX_PIECE_BYTES {
            return Err(BundleError::invalid(
                "audit_bundle_too_large",
                format!("部件 {} 超过单件上限", reference.name),
            ));
        }
        total = total
            .checked_add(piece.bytes.len() as u64)
            .ok_or_else(|| BundleError::invalid("audit_bundle_too_large", "部件总长度溢出"))?;
        if total > MAX_BUNDLE_BYTES {
            return Err(BundleError::invalid(
                "audit_bundle_too_large",
                format!("部件总长度 {total} 超过上限"),
            ));
        }
        let expected = parse_hash(&reference.hash)?;
        if Hash::of(&piece.bytes) != expected {
            return Err(BundleError::invalid(
                "audit_bundle_hash_mismatch",
                format!("部件 {} 内容摘要不符", reference.name),
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_manifest(manifest: &Manifest) -> Result<(), BundleError> {
    if manifest.schema != SCHEMA {
        return Err(BundleError::invalid(
            "audit_bundle_bad",
            format!("manifest schema 应为 {SCHEMA}"),
        ));
    }
    if manifest.event_count > MAX_EVENTS {
        return Err(BundleError::invalid(
            "audit_bundle_too_large",
            format!("事件数 {} 超过上限", manifest.event_count),
        ));
    }
    if parse_hash(&manifest.state_digest).is_err() {
        return Err(BundleError::invalid(
            "audit_bundle_bad",
            "manifest.state_digest 不是合法 BLAKE3 摘要",
        ));
    }
    if manifest.pieces.len() > MAX_PIECES {
        return Err(BundleError::invalid(
            "audit_bundle_too_large",
            format!("部件数 {} 超过上限", manifest.pieces.len()),
        ));
    }
    let mut names = BTreeSet::new();
    let mut journals = 0usize;
    for piece in &manifest.pieces {
        if !names.insert(piece.name.clone()) {
            return Err(BundleError::invalid(
                "audit_bundle_bad",
                format!("manifest 有重复部件名：{}", piece.name),
            ));
        }
        if piece.name == "journal.jsonl" {
            journals += 1;
        }
        let hash = parse_hash(&piece.hash)?;
        validate_piece_name(&piece.name, &hash)?;
    }
    if journals != 1 {
        return Err(BundleError::invalid(
            "audit_bundle_incomplete",
            "manifest 必须恰好包含一个 journal.jsonl",
        ));
    }
    if !manifest
        .pieces
        .windows(2)
        .all(|pair| pair[0].name < pair[1].name)
    {
        return Err(BundleError::invalid(
            "audit_bundle_bad",
            "manifest 部件必须按名字严格升序",
        ));
    }
    Ok(())
}

pub(crate) fn validate_piece_name(name: &str, hash: &Hash) -> Result<(), BundleError> {
    let valid = match name {
        "journal.jsonl" | "HEAD" | "index.json" | "policy.json" | "claims.json" | "keys.json" => {
            true
        }
        _ if name.starts_with("refs/") => Repo::validate_ref(&name["refs/".len()..]).is_ok(),
        _ if name.starts_with("object:") => Hash::from_hex(&name["object:".len()..]) == Some(*hash),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(BundleError::invalid(
            "audit_bundle_bad",
            format!("部件名 {name:?} 不在 TVAB 允许的封闭集合内"),
        ))
    }
}

pub(crate) fn parse_hash(text: &str) -> Result<Hash, BundleError> {
    Hash::from_hex(text).ok_or_else(|| {
        BundleError::invalid("audit_bundle_bad", format!("不是合法 BLAKE3 摘要：{text}"))
    })
}

fn read_exact<R: Read>(input: &mut R, buf: &mut [u8]) -> Result<(), BundleError> {
    input.read_exact(buf).map_err(|err| {
        if err.kind() == io::ErrorKind::UnexpectedEof {
            BundleError::invalid("audit_bundle_truncated", "TVAB 容器被截断")
        } else {
            BundleError::Io(err)
        }
    })
}

fn read_u32<R: Read>(input: &mut R) -> Result<u32, BundleError> {
    let mut bytes = [0u8; 4];
    read_exact(input, &mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> (Manifest, Vec<Piece>) {
        let journal = b"{}\n".to_vec();
        let object = b"object".to_vec();
        let pieces = vec![
            Piece {
                reference: PieceRef {
                    name: "journal.jsonl".to_string(),
                    hash: Hash::of(&journal).to_hex(),
                    bytes: journal.len() as u64,
                },
                bytes: journal,
            },
            Piece {
                reference: PieceRef {
                    name: format!("object:{}", Hash::of(&object).to_hex()),
                    hash: Hash::of(&object).to_hex(),
                    bytes: object.len() as u64,
                },
                bytes: object,
            },
        ];
        let manifest = Manifest {
            schema: SCHEMA,
            event_count: 0,
            state_digest: Hash::of(b"state").to_hex(),
            anchor: ExternalAnchor {
                schema: "trit-external-anchor-v1".to_string(),
                checkpoint: Hash::of(b"checkpoint"),
                height: 0,
                head: None,
                merkle_root: Hash::of(b"root"),
                previous: None,
                key_id: "ed25519:test".to_string(),
                algorithm: "ed25519".to_string(),
                signature: "00".to_string(),
                signed_at_ms: 1,
            },
            pieces: pieces.iter().map(|piece| piece.reference.clone()).collect(),
        };
        (manifest, pieces)
    }

    fn encoded() -> Vec<u8> {
        let (manifest, pieces) = sample();
        let mut out = Vec::new();
        write_all(&mut out, &manifest, &pieces).unwrap();
        out
    }

    fn temp_dir() -> PathBuf {
        for _ in 0..8 {
            let mut random = [0u8; 16];
            getrandom::fill(&mut random).unwrap();
            let path =
                std::env::temp_dir().join(format!("trit-vcs-tvab-test-{}", Hash::of(&random)));
            match fs::create_dir(&path) {
                Ok(()) => return path,
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(err) => panic!("创建测试目录失败：{err}"),
            }
        }
        panic!("无法创建唯一测试目录");
    }

    #[test]
    fn roundtrip_preserves_manifest_pieces_and_exact_size() {
        let bytes = encoded();
        let decoded = read_all(&mut bytes.as_slice()).unwrap();
        assert_eq!(decoded.manifest, sample().0);
        assert_eq!(decoded.pieces[1].bytes, b"object");
        assert_eq!(decoded.bytes, bytes.len() as u64);
    }

    #[test]
    fn publication_never_replaces_and_leaves_no_temporary_file() {
        let dir = temp_dir();
        let out = dir.join("bundle.tvab");
        let (manifest, pieces) = sample();
        let bytes = write_new_file(&out, &manifest, &pieces).unwrap();
        assert_eq!(bytes, fs::metadata(&out).unwrap().len());
        fs::write(&out, b"keep-me").unwrap();
        let err = write_new_file(&out, &manifest, &pieces).unwrap_err();
        assert_eq!(err.kind(), "audit_bundle_exists");
        assert_eq!(fs::read(&out).unwrap(), b"keep-me");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_directory_as_input_before_reading() {
        let dir = temp_dir();
        let err = read_file(&dir).unwrap_err();
        assert_eq!(err.kind(), "audit_bundle_bad");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_bad_magic_schema_truncation_and_trailing_bytes() {
        let mut bad_magic = encoded();
        bad_magic[0] = b'X';
        assert_eq!(
            read_all(&mut bad_magic.as_slice()).unwrap_err().kind(),
            "audit_bundle_bad"
        );

        let mut bad_schema = encoded();
        bad_schema[4..8].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(
            read_all(&mut bad_schema.as_slice()).unwrap_err().kind(),
            "audit_bundle_bad"
        );

        let truncated = encoded();
        assert_eq!(
            read_all(&mut &truncated[..truncated.len() - 1])
                .unwrap_err()
                .kind(),
            "audit_bundle_truncated"
        );

        let mut trailing = encoded();
        trailing.push(0);
        assert_eq!(
            read_all(&mut trailing.as_slice()).unwrap_err().kind(),
            "audit_bundle_trailing"
        );
    }

    #[test]
    fn rejects_oversized_manifest_before_allocation() {
        let mut bytes = encoded();
        bytes[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            read_all(&mut bytes.as_slice()).unwrap_err().kind(),
            "audit_bundle_too_large"
        );
    }

    #[test]
    fn rejects_corrupt_piece_and_duplicate_or_unsafe_names() {
        let mut corrupt = encoded();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0xff;
        assert_eq!(
            read_all(&mut corrupt.as_slice()).unwrap_err().kind(),
            "audit_bundle_hash_mismatch"
        );

        let (mut manifest, mut pieces) = sample();
        manifest.pieces[1].name = "refs/../escape".to_string();
        pieces[1].reference.name = manifest.pieces[1].name.clone();
        assert_eq!(
            validate(&manifest, &pieces).unwrap_err().kind(),
            "audit_bundle_bad"
        );

        let (mut manifest, pieces) = sample();
        manifest.pieces[1].name = manifest.pieces[0].name.clone();
        assert_eq!(
            validate(&manifest, &pieces).unwrap_err().kind(),
            "audit_bundle_bad"
        );
    }
}
