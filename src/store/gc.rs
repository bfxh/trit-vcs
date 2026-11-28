//! 对象库尾部水位：只回收某个操作期间追加的字节，不碰历史对象。
//!
//! 对象库只追加、不原地改；因此“操作开始后新增的块和索引行”一定在旧水位之后。
//! 这不是进程内 `Drop`：进程被 `SIGKILL` 或断电时 `Drop` 不会执行，水位必须持久化在
//! 事务快照里，由下一次持锁写恢复。

use std::fs::{self, OpenOptions};

use serde::{Deserialize, Serialize};

use super::{Store, StoreError};

/// 操作开始时的对象库尾部位置；回滚只截断这两个长度之后的新增字节。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ObjectWatermark {
    pub pack_len: u64,
    pub index_len: u64,
}

/// 一次对象写入的 RAII 尾部租约；成功时 `commit`，失败/早退时 `Drop` 回滚。
pub(super) struct TailGuard<'a> {
    store: &'a Store,
    watermark: ObjectWatermark,
    committed: bool,
}

impl TailGuard<'_> {
    pub(super) fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for TailGuard<'_> {
    fn drop(&mut self) {
        if !self.committed {
            // 原始错误优先返回；回收失败由后续打开/审计再暴露，不能在这里覆盖它。
            let _ = self.store.truncate_to(self.watermark);
        }
    }
}

impl Store {
    /// 给一次 `put_chunk` 加写前水位租约：正常写完要显式 `commit`，否则 `Drop`
    /// 把这次追加的 pack/index 尾部截回旧水位。它只覆盖“进程还活着”的失败路径；
    /// `SIGKILL`/断电由事务快照里的持久水位兜底。
    pub(super) fn tail_guard(&self) -> Result<TailGuard<'_>, StoreError> {
        Ok(TailGuard {
            store: self,
            watermark: self.watermark()?,
            committed: false,
        })
    }

    /// 记下当前 pack/index 的尾部位置。
    pub(crate) fn watermark(&self) -> Result<ObjectWatermark, StoreError> {
        Ok(ObjectWatermark {
            pack_len: fs::metadata(self.pack_path()).map(|m| m.len()).unwrap_or(0),
            index_len: fs::metadata(self.index_path())
                .map(|m| m.len())
                .unwrap_or(0),
        })
    }

    /// 把对象库尾部截回某个操作开始前的水位。
    ///
    /// 只允许截短：水位比当前长说明对象库已经被外力删短，报 `BadWatermark` 而不是把
    /// 文件反向撑回去。截完重新 `load`，让内存索引与盘上一致。
    pub(crate) fn truncate_to(&self, watermark: ObjectWatermark) -> Result<(), StoreError> {
        let mut changed = false;
        for (label, path, target) in [
            ("pack", self.pack_path(), watermark.pack_len),
            ("index", self.index_path(), watermark.index_len),
        ] {
            let current = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            if current < target {
                return Err(StoreError::BadWatermark(format!(
                    "{label} 当前 {current} 字节，短于快照的 {target} 字节"
                )));
            }
            if current > target {
                let file = OpenOptions::new().write(true).open(&path)?;
                file.set_len(target)?;
                file.sync_all()?;
                changed = true;
            }
        }
        if changed {
            self.load()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Hash;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("trit-{name}-{}-{stamp}", std::process::id()))
    }

    #[test]
    #[allow(clippy::permissions_set_readonly_false)] // 临时索引文件只需恢复可写，不涉及生产权限
    fn failed_index_append_rolls_back_pack_tail() {
        let root = temp("store-tail");
        let store = Store::open(&root).unwrap();
        let index = store.index_path();
        fs::File::create(&index).unwrap();
        let mut permissions = fs::metadata(&index).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&index, permissions.clone()).unwrap();
        assert!(store.put_chunk(b"tail").is_err());

        let pack_len = fs::metadata(store.pack_path())
            .map(|m| m.len())
            .unwrap_or(0);
        assert_eq!(pack_len, 0, "索引写失败必须把 pack 尾块截掉");
        assert!(!store.has(&Hash::of(b"tail")));

        permissions.set_readonly(false);
        fs::set_permissions(&index, permissions).unwrap();
        fs::remove_file(&index).unwrap();
        let (hash, is_new) = store.put_chunk(b"tail").unwrap();
        assert!(is_new);
        assert!(store.has(&hash));
        drop(store);
        let _ = fs::remove_dir_all(&root);
    }
}
