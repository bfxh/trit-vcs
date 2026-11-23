//! 网络传输的对象流（`TVOB`）：一串 `{id, 长度, 原始内容}`，收端逐块重算 BLAKE3。
//!
//! 与本地包 `TVBD` 的区别：包是按**树**组织的（带树清单、只能传树闭包）；
//! 网络要传的是**任意对象集**（提交 + 父链 + 树 + 文件映射 + 块），所以这里只定义
//! "一组对象"的线与边界，不掺业务语义。语义（publish/pull、快进判定）在 `remote`。
//!
//! 边界：
//! - 对象数、单个对象大小都有硬上限（默认 100 万 / 32 MiB），解码先看声明再看内容；
//! - 尾部多字节、少读一个对象都算坏流（`TrailingBytes` / `CountMismatch`），不静默截；
//! - 收端**先校验后入库**：内容与 id 对不上就拒写，坏一个字节也不会污染对象库。

use std::io::{Read, Write};

use crate::hash::Hash;
use crate::store::{Store, StoreError};

pub const MAGIC: &[u8; 4] = b"TVOB";
pub const SCHEMA: u32 = 1;
/// magic(4) + schema(4) + 对象数(4)。
pub const HEADER_LEN: u64 = 12;
/// 一条对象记录的固定开销：id(32) + 长度(4)。
pub const RECORD_LEN: u64 = 36;

#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("对象库: {0}")]
    Store(#[from] StoreError),
    #[error("不是 trit-vcs 对象流（magic 不对）")]
    BadMagic,
    #[error("不支持的对象流 schema：{0}")]
    UnsupportedSchema(u32),
    #[error("对象流被截断")]
    Truncated,
    #[error("对象流里的内容与 id 对不上：期望 {expected}，实际 {actual}")]
    Corrupt { expected: String, actual: String },
    #[error("对象数超过上限：{0}")]
    TooManyObjects(u32),
    #[error("单个对象超过上限：{0} 字节")]
    ObjectTooLarge(usize),
    #[error("对象流还差 {0} 个对象没读完")]
    CountMismatch(u32),
    #[error("对象流尾部还有多余字节")]
    TrailingBytes,
    #[error("对象流里没有对象 {0}")]
    MissingObject(String),
    #[error("对象 {0} 不是提交（publish 的 tip 指向了别的东西）")]
    NotACommit(String),
}

/// 解码上限：坏流不能拿声明数字把收端的内存吃光。
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_objects: u32,
    /// 单个对象的原始字节上限。
    pub max_object: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_objects: 1_000_000,
            max_object: 32 * 1024 * 1024,
        }
    }
}

/// 一组要发的对象：`objects` 从对象库读，`inline` 是"发送端现造、本库没有"的对象
/// （部分拉取时的过滤树清单）。两部分都必须是内容寻址的，收端一视同仁地重算。
#[derive(Clone, Debug, Default)]
pub struct Body {
    pub objects: Vec<Hash>,
    pub inline: Vec<(Hash, Vec<u8>)>,
}

impl Body {
    pub fn count(&self) -> u32 {
        (self.objects.len() + self.inline.len()) as u32
    }

    /// 线上字节数（要先算出来才能写 `Content-Length`）。
    pub fn byte_len(&self, store: &Store) -> Result<u64, WireError> {
        let mut total = HEADER_LEN;
        for id in &self.objects {
            let bytes = store.get_chunk(id)?;
            total += RECORD_LEN + bytes.len() as u64;
        }
        for (_, bytes) in &self.inline {
            total += RECORD_LEN + bytes.len() as u64;
        }
        Ok(total)
    }

    /// 把这一组对象写成对象流。
    pub fn write<W: Write>(&self, store: &Store, out: W) -> Result<u64, WireError> {
        let mut writer = Writer::begin(out, self.count())?;
        for id in &self.objects {
            let bytes = store.get_chunk(id)?;
            writer.object(*id, &bytes)?;
        }
        for (id, bytes) in &self.inline {
            writer.object(*id, bytes)?;
        }
        writer.finish()
    }

    /// 只查"在不在"，不读内容：入库前的完整性闸门（读时仍会逐块校验）。
    pub fn ensure_present(&self, store: &Store) -> Result<(), WireError> {
        for id in &self.objects {
            if !store.has_chunk(id) {
                return Err(WireError::MissingObject(id.to_hex()));
            }
        }
        for (id, _) in &self.inline {
            if !store.has_chunk(id) {
                return Err(WireError::MissingObject(id.to_hex()));
            }
        }
        Ok(())
    }
}

/// 写端：先声明对象数，再逐条写；少写一条或多写一条都在 `finish` 里判红。
pub struct Writer<W: Write> {
    out: W,
    declared: u32,
    written: u32,
    bytes: u64,
}

impl<W: Write> Writer<W> {
    pub fn begin(mut out: W, count: u32) -> Result<Self, WireError> {
        out.write_all(MAGIC)?;
        out.write_all(&SCHEMA.to_le_bytes())?;
        out.write_all(&count.to_le_bytes())?;
        Ok(Self {
            out,
            declared: count,
            written: 0,
            bytes: HEADER_LEN,
        })
    }

    /// 写一条对象；内容与 id 对不上就在发送端先炸，不把坏数据发出去。
    pub fn object(&mut self, id: Hash, bytes: &[u8]) -> Result<(), WireError> {
        let actual = Hash::of(bytes);
        if actual != id {
            return Err(WireError::Corrupt {
                expected: id.to_hex(),
                actual: actual.to_hex(),
            });
        }
        if bytes.len() > u32::MAX as usize {
            return Err(WireError::ObjectTooLarge(bytes.len()));
        }
        self.out.write_all(id.as_bytes())?;
        self.out.write_all(&(bytes.len() as u32).to_le_bytes())?;
        self.out.write_all(bytes)?;
        self.written = self.written.saturating_add(1);
        self.bytes += RECORD_LEN + bytes.len() as u64;
        Ok(())
    }

    pub fn finish(self) -> Result<u64, WireError> {
        if self.written != self.declared {
            return Err(WireError::CountMismatch(
                self.declared.saturating_sub(self.written),
            ));
        }
        Ok(self.bytes)
    }
}

impl<R: Read> std::fmt::Debug for Reader<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "wire::Reader(剩 {} 个对象)", self.remaining)
    }
}

/// 读端：逐条读、逐条校验、逐条入库（已有的块跳过）。
pub struct Reader<R: Read> {
    input: R,
    remaining: u32,
    limits: Limits,
    read: u64,
}

impl<R: Read> Reader<R> {
    pub fn open(mut input: R, limits: Limits) -> Result<Self, WireError> {
        let mut magic = [0u8; 4];
        read_exact(&mut input, &mut magic, WireError::Truncated)?;
        if &magic != MAGIC {
            return Err(WireError::BadMagic);
        }
        let schema = read_u32(&mut input)?;
        if schema != SCHEMA {
            return Err(WireError::UnsupportedSchema(schema));
        }
        let count = read_u32(&mut input)?;
        if count > limits.max_objects {
            return Err(WireError::TooManyObjects(count));
        }
        Ok(Self {
            input,
            remaining: count,
            limits,
            read: HEADER_LEN,
        })
    }

    pub fn remaining(&self) -> u32 {
        self.remaining
    }

    pub fn read_bytes(&self) -> u64 {
        self.read
    }

    /// 读下一条并入库；`None` 表示声明里的对象已经读完。
    pub fn next(&mut self, store: &Store) -> Result<Option<Hash>, WireError> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let mut id_bytes = [0u8; 32];
        read_exact(&mut self.input, &mut id_bytes, WireError::Truncated)?;
        let id = Hash::from_bytes(id_bytes);
        let len = read_u32(&mut self.input)? as usize;
        if len > self.limits.max_object {
            return Err(WireError::ObjectTooLarge(len));
        }
        let mut payload = vec![0u8; len];
        read_exact(&mut self.input, &mut payload, WireError::Truncated)?;
        let actual = Hash::of(&payload);
        if actual != id {
            return Err(WireError::Corrupt {
                expected: id.to_hex(),
                actual: actual.to_hex(),
            });
        }
        if !store.has_chunk(&id) {
            store.put_chunk(&payload)?;
        }
        self.remaining -= 1;
        self.read += RECORD_LEN + len as u64;
        Ok(Some(id))
    }

    /// 收尾：声明数与实际数必须一致，且后面不许再有多余字节。
    pub fn finish(mut self) -> Result<(), WireError> {
        if self.remaining != 0 {
            return Err(WireError::CountMismatch(self.remaining));
        }
        let mut probe = [0u8; 1];
        match self.input.read(&mut probe) {
            Ok(0) => Ok(()),
            Ok(_) => Err(WireError::TrailingBytes),
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => Ok(()),
            Err(err) => Err(WireError::Io(err)),
        }
    }
}

fn read_exact<R: Read>(input: &mut R, buf: &mut [u8], eof: WireError) -> Result<(), WireError> {
    input.read_exact(buf).map_err(|err| {
        if err.kind() == std::io::ErrorKind::UnexpectedEof {
            eof
        } else {
            WireError::Io(err)
        }
    })
}

fn read_u32<R: Read>(input: &mut R) -> Result<u32, WireError> {
    let mut buf = [0u8; 4];
    read_exact(input, &mut buf, WireError::Truncated)?;
    Ok(u32::from_le_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::ClaimSpec;
    use crate::repo::{CommitRequest, Repo};

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("trit-vcs-wire-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn seeded(name: &str) -> (std::path::PathBuf, Repo, Hash) {
        let root = temp(name);
        let mut repo = Repo::init(&root).unwrap();
        let files = std::collections::BTreeMap::from([(
            "a.txt".to_string(),
            b"wire body\nwire body\n".to_vec(),
        )]);
        repo.stage(&files, 1_000).unwrap();
        let commit = repo
            .commit(CommitRequest {
                message: "wire".to_string(),
                session: "qoder:wire".to_string(),
                claims: vec![ClaimSpec {
                    id: "w1".to_string(),
                    owner: "qoder:wire".to_string(),
                    paths: vec!["a.txt".to_string()],
                    acquired_at: 1,
                    expires_at: u64::MAX / 2,
                }],
                now_secs: 1_000,
                ..Default::default()
            })
            .unwrap()
            .id;
        (root, repo, commit)
    }

    #[test]
    fn roundtrip_streams_every_object() {
        let (root, src, commit) = seeded("roundtrip");
        let objects = crate::bundle::commit_closure(src.store(), commit).unwrap();
        let body = Body {
            objects: objects.clone(),
            inline: Vec::new(),
        };
        let mut out = Vec::new();
        let written = body.write(src.store(), &mut out).unwrap();
        assert_eq!(written, body.byte_len(src.store()).unwrap());

        let dst = Repo::init(root.join("dst")).unwrap();
        let mut reader = Reader::open(out.as_slice(), Limits::default()).unwrap();
        let mut seen = Vec::new();
        while let Some(id) = reader.next(dst.store()).unwrap() {
            seen.push(id);
        }
        reader.finish().unwrap();
        assert_eq!(seen, objects, "对象顺序必须与发送端一致");
        assert!(dst.store().has_chunk(&commit));
    }

    #[test]
    fn truncated_and_tampered_streams_are_loud() {
        let (root, src, commit) = seeded("bad");
        let body = Body {
            objects: crate::bundle::commit_closure(src.store(), commit).unwrap(),
            inline: Vec::new(),
        };
        let mut out = Vec::new();
        body.write(src.store(), &mut out).unwrap();
        let dst = Repo::init(root.join("dst")).unwrap();

        let cut = out.len() / 2;
        let err = Reader::open(&out[..cut], Limits::default())
            .and_then(|mut reader| {
                while reader.next(dst.store())?.is_some() {}
                Ok(())
            })
            .unwrap_err();
        assert!(matches!(
            err,
            WireError::Truncated | WireError::CountMismatch(_)
        ));

        let last = out.len() - 1;
        let mut tampered = out.clone();
        tampered[last] ^= 0xFF;
        let mut reader = Reader::open(tampered.as_slice(), Limits::default()).unwrap();
        let err = loop {
            match reader.next(dst.store()) {
                Ok(Some(_)) => continue,
                Ok(None) => break reader.finish().unwrap_err(),
                Err(err) => break err,
            }
        };
        assert!(
            matches!(err, WireError::Corrupt { .. } | WireError::TrailingBytes),
            "{err}"
        );
    }

    #[test]
    fn declared_bounds_are_enforced_before_allocating() {
        let root = temp("bounds");
        let dst = Repo::init(&root).unwrap();
        let mut header = Vec::new();
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(&SCHEMA.to_le_bytes());
        header.extend_from_slice(&(u32::MAX).to_le_bytes());
        let err = Reader::open(header.as_slice(), Limits::default()).unwrap_err();
        assert!(matches!(err, WireError::TooManyObjects(_)), "{err}");

        let mut one = Vec::new();
        one.extend_from_slice(MAGIC);
        one.extend_from_slice(&SCHEMA.to_le_bytes());
        one.extend_from_slice(&1u32.to_le_bytes());
        one.extend_from_slice(&[0u8; 32]);
        one.extend_from_slice(&(u32::MAX).to_le_bytes());
        let mut reader = Reader::open(one.as_slice(), Limits::default()).unwrap();
        let err = reader.next(dst.store()).unwrap_err();
        assert!(matches!(err, WireError::ObjectTooLarge(_)), "{err}");
        assert_eq!(dst.store().stats().unwrap().objects, 0);
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let (root, src, commit) = seeded("trailing");
        let body = Body {
            objects: crate::bundle::commit_closure(src.store(), commit).unwrap(),
            inline: Vec::new(),
        };
        let mut out = Vec::new();
        body.write(src.store(), &mut out).unwrap();
        out.push(b'x');
        let dst = Repo::init(root.join("dst")).unwrap();
        let mut reader = Reader::open(out.as_slice(), Limits::default()).unwrap();
        while reader.next(dst.store()).unwrap().is_some() {}
        assert!(matches!(
            reader.finish().unwrap_err(),
            WireError::TrailingBytes
        ));
    }

    #[test]
    fn inline_objects_are_verified_too() {
        let (root, src, commit) = seeded("inline");
        let tree = src.commit_at(&commit).unwrap().tree;
        let manifest = crate::bundle::manifest(src.store(), tree, Some("a.txt")).unwrap();
        let body = Body {
            objects: Vec::new(),
            inline: vec![(manifest.id, manifest.bytes.clone())],
        };
        assert_eq!(
            body.byte_len(src.store()).unwrap(),
            HEADER_LEN + RECORD_LEN + manifest.bytes.len() as u64
        );
        let mut out = Vec::new();
        body.write(src.store(), &mut out).unwrap();
        let dst = Repo::init(root.join("dst")).unwrap();
        let mut reader = Reader::open(out.as_slice(), Limits::default()).unwrap();
        assert_eq!(reader.next(dst.store()).unwrap(), Some(manifest.id));

        let bad = Body {
            objects: Vec::new(),
            inline: vec![(manifest.id, b"different".to_vec())],
        };
        let mut out = Vec::new();
        assert!(matches!(
            bad.write(src.store(), &mut out).unwrap_err(),
            WireError::Corrupt { .. }
        ));
    }

    #[test]
    fn wrong_magic_and_schema_are_rejected() {
        let root = temp("magic");
        let _ = Repo::init(&root).unwrap();

        let mut bad_magic = Vec::new();
        bad_magic.extend_from_slice(b"TVBA");
        bad_magic.extend_from_slice(&SCHEMA.to_le_bytes());
        bad_magic.extend_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            Reader::open(bad_magic.as_slice(), Limits::default()).unwrap_err(),
            WireError::BadMagic
        ));

        let mut bad_schema = Vec::new();
        bad_schema.extend_from_slice(MAGIC);
        bad_schema.extend_from_slice(&99u32.to_le_bytes());
        bad_schema.extend_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            Reader::open(bad_schema.as_slice(), Limits::default()).unwrap_err(),
            WireError::UnsupportedSchema(99)
        ));
    }
}
