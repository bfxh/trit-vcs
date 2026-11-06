//! 交接包的单文件形态（`TVHP`）：与 `bundle.rs` 的 `TVBD` 同族的内容寻址容器。
//!
//! magic 故意与 `TVBD` 不同 ⇒ 传输 `import` 不会误收交接包，`handoff-verify` 也不会误收传输包。
//! 布局：`TVHP`、schema(u32)、manifest 长度(u32)、manifest JSON、部件数(u32)，
//! 后接一串部件 `{32 字节 id, u32 长度, 原始内容}`（与清单逐条同序）。
//! 收端**逐块重算 BLAKE3**，对不上就拒；语义判据（包 id / diff / 冲突面 / 悬空）交给 `handoff::verify`，
//! 单文件与目录包共用那一套，不在这里另立。

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use crate::handoff::{Component, HandoffError, Manifest};
use crate::hash::Hash;

pub const MAGIC: &[u8; 4] = b"TVHP";
pub const SCHEMA: u32 = 1;

/// 把已装配的清单 + 部件写成一个文件。
pub fn write_file(
    out: &Path,
    manifest: &Manifest,
    pieces: &[(Component, Vec<u8>)],
) -> Result<(), HandoffError> {
    let mut file = fs::File::create(out)?;
    write_all(&mut file, manifest, pieces)
}

/// 写进任意 `Write`（便于测试与将来接网络面）。
pub fn write_all<W: Write>(
    out: &mut W,
    manifest: &Manifest,
    pieces: &[(Component, Vec<u8>)],
) -> Result<(), HandoffError> {
    let manifest_bytes = serde_json::to_vec(manifest)?;
    out.write_all(MAGIC)?;
    out.write_all(&SCHEMA.to_le_bytes())?;
    out.write_all(&(manifest_bytes.len() as u32).to_le_bytes())?;
    out.write_all(&manifest_bytes)?;
    out.write_all(&(pieces.len() as u32).to_le_bytes())?;
    for (component, bytes) in pieces {
        let id = Hash::from_hex(&component.object).ok_or_else(|| {
            HandoffError::Manifest(format!("部件 {} 的 object 不是合法 id", component.name))
        })?;
        out.write_all(id.as_bytes())?;
        out.write_all(&(bytes.len() as u32).to_le_bytes())?;
        out.write_all(bytes)?;
    }
    Ok(())
}

/// 读单文件 → rel→bytes（含 `manifest.json`）。文件不存在按缺件判红。
pub fn read_file(path: &Path) -> Result<BTreeMap<String, Vec<u8>>, HandoffError> {
    let bytes = fs::read(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            HandoffError::Missing(format!("{}: 包文件不存在", path.display()))
        } else {
            HandoffError::Io(err)
        }
    })?;
    read_all(&mut bytes.as_slice())
}

/// 从任意 `Read` 解出容器；逐块重算 hash，部件数必须与清单逐条对上。
pub fn read_all<R: Read>(input: &mut R) -> Result<BTreeMap<String, Vec<u8>>, HandoffError> {
    let mut magic = [0u8; 4];
    read_exact(input, &mut magic)?;
    if &magic != MAGIC {
        return Err(HandoffError::Manifest(
            "不是交接包单文件（magic 不对，期望 TVHP）".to_string(),
        ));
    }
    let schema = read_u32(input)?;
    if schema != SCHEMA {
        return Err(HandoffError::Manifest(format!(
            "不支持的交接包 schema：{schema}"
        )));
    }
    let manifest_len = read_u32(input)? as usize;
    let mut manifest_bytes = vec![0u8; manifest_len];
    read_exact(input, &mut manifest_bytes)?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|err| HandoffError::Manifest(format!("manifest: {err}")))?;
    let blob_count = read_u32(input)? as usize;
    if blob_count != manifest.components.len() {
        return Err(HandoffError::Manifest(format!(
            "部件数 {blob_count} 与清单 {} 不符",
            manifest.components.len()
        )));
    }
    let mut map = BTreeMap::new();
    map.insert("manifest.json".to_string(), manifest_bytes);
    for component in &manifest.components {
        let mut id_bytes = [0u8; 32];
        read_exact(input, &mut id_bytes)?;
        let id = Hash::from_bytes(id_bytes);
        let len = read_u32(input)? as usize;
        let mut payload = vec![0u8; len];
        read_exact(input, &mut payload)?;
        let actual = Hash::of(&payload);
        if actual != id {
            return Err(HandoffError::HashMismatch(format!(
                "部件 {}: 内容与 id 不符 {} != {}",
                component.name,
                actual.short(),
                id.short()
            )));
        }
        map.insert(component.path.clone(), payload);
    }
    Ok(map)
}

fn read_exact<R: Read>(input: &mut R, buf: &mut [u8]) -> Result<(), HandoffError> {
    input.read_exact(buf).map_err(|err| {
        if err.kind() == std::io::ErrorKind::UnexpectedEof {
            HandoffError::Missing("交接包单文件被截断".to_string())
        } else {
            HandoffError::Io(err)
        }
    })
}

fn read_u32<R: Read>(input: &mut R) -> Result<u32, HandoffError> {
    let mut buf = [0u8; 4];
    read_exact(input, &mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> (Manifest, Vec<(Component, Vec<u8>)>) {
        let mut pieces = Vec::new();
        for (name, kind, path, body) in [
            ("commit", "commit", "objects/c.json", &b"{\"x\":1}"[..]),
            ("file:a", "file", "objects/a.bin", &b"hello"[..]),
        ] {
            let id = Hash::of(body);
            pieces.push((
                Component {
                    name: name.to_string(),
                    kind: kind.to_string(),
                    object: id.to_hex(),
                    path: path.to_string(),
                    bytes: body.len() as u64,
                    source: "test".to_string(),
                },
                body.to_vec(),
            ));
        }
        let components: Vec<Component> = pieces.iter().map(|(c, _)| c.clone()).collect();
        let manifest = Manifest {
            schema: SCHEMA,
            package_id: Hash::of(b"pkg").to_hex(),
            commit: Hash::of(b"c").to_hex(),
            tree: Hash::of(b"t").to_hex(),
            parents: Vec::new(),
            components,
        };
        (manifest, pieces)
    }

    fn encoded() -> Vec<u8> {
        let (manifest, pieces) = sample();
        let mut out = Vec::new();
        write_all(&mut out, &manifest, &pieces).unwrap();
        out
    }

    #[test]
    fn round_trip_preserves_manifest_and_bytes() {
        let bytes = encoded();
        let map = read_all(&mut bytes.as_slice()).unwrap();
        assert_eq!(map.len(), 3, "manifest + 两个部件");
        assert_eq!(map.get("objects/a.bin").unwrap(), b"hello");
        assert_eq!(map.get("objects/c.json").unwrap(), b"{\"x\":1}");
        let manifest: Manifest = serde_json::from_slice(&map["manifest.json"]).unwrap();
        assert_eq!(manifest.components.len(), 2);
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut bytes = encoded();
        bytes[0] ^= 0xFF;
        assert!(matches!(
            read_all(&mut bytes.as_slice()).unwrap_err(),
            HandoffError::Manifest(_)
        ));
    }

    #[test]
    fn transport_tvbd_magic_is_not_a_handoff_package() {
        // 传输包（TVBD）即便其余字节合法，也不能被当成交接包收。
        let mut bytes = encoded();
        bytes[0..4].copy_from_slice(b"TVBD");
        let err = read_all(&mut bytes.as_slice()).unwrap_err();
        assert!(matches!(err, HandoffError::Manifest(_)), "{err:?}");
    }

    #[test]
    fn unsupported_schema_is_rejected() {
        let mut bytes = encoded();
        bytes[4..8].copy_from_slice(&2u32.to_le_bytes());
        assert!(matches!(
            read_all(&mut bytes.as_slice()).unwrap_err(),
            HandoffError::Manifest(_)
        ));
    }

    #[test]
    fn truncated_container_is_rejected() {
        let mut bytes = encoded();
        bytes.truncate(bytes.len() / 2);
        assert!(matches!(
            read_all(&mut bytes.as_slice()).unwrap_err(),
            HandoffError::Missing(_)
        ));
    }

    #[test]
    fn corrupt_payload_is_rejected_before_use() {
        let mut bytes = encoded();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        assert!(matches!(
            read_all(&mut bytes.as_slice()).unwrap_err(),
            HandoffError::HashMismatch(_)
        ));
    }

    #[test]
    fn blob_count_must_match_manifest() {
        let mut bytes = encoded();
        let manifest_len = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        let count_at = 12 + manifest_len;
        bytes[count_at..count_at + 4].copy_from_slice(&99u32.to_le_bytes());
        assert!(matches!(
            read_all(&mut bytes.as_slice()).unwrap_err(),
            HandoffError::Manifest(_)
        ));
    }
}
