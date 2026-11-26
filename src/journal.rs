//! 哈希链事件日志：追加式，每条事件带前一条的哈希。
//!
//! 为什么这条比 Git 强：Git 的 reflog 是**本地、可改写、`gc` 会丢**的东西；
//! 这里的每条记录（提交、认领、门禁结论、回执）串成链，改中间一条会让后面全部对不上。
//! `verify` 就是那条尺子。

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::hash::Hash;

/// 追加时的单写者锁：锁文件是 `journal.lock`，与事件日志同目录。
/// 抢不到就重试一小会儿，仍抢不到报 `Locked`；不静默并发写坏链。
#[cfg(not(test))]
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);
// 测试并行跑大量 fsync，慢盘上 5 秒会把并发用例打成假红；生产仍是 5 秒。
#[cfg(test)]
const LOCK_TIMEOUT: Duration = Duration::from_secs(30);
const LOCK_RETRY: Duration = Duration::from_millis(5);
const OPEN_RETRIES: u32 = 400;
const OPEN_RETRY_DELAY: Duration = Duration::from_millis(10);

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub seq: u64,
    pub at_ms: u64,
    pub kind: String,
    pub payload: Value,
    pub prev: Option<Hash>,
    pub hash: Hash,
}

#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("日志行不是合法 JSON（第 {line} 条）：{detail}")]
    BadLine { line: usize, detail: String },
    #[error("链断了（第 {line} 条）：记录的 hash 与内容对不上")]
    Broken { line: usize },
    #[error("prev 指错了（第 {line} 条）：期望 {expected:?}，实际 {actual:?}")]
    WrongPrev {
        line: usize,
        expected: Option<String>,
        actual: Option<String>,
    },
    #[error("seq 不连续（第 {line} 条）：期望 {expected}，实际 {actual}")]
    SeqGap {
        line: usize,
        expected: u64,
        actual: u64,
    },
    #[error("事件日志被另一个写入者占着：{0}（确认没进程在写后再删锁文件）")]
    Locked(PathBuf),
}

pub(crate) fn event_hash(
    seq: u64,
    at_ms: u64,
    kind: &str,
    payload: &Value,
    prev: Option<&Hash>,
) -> Hash {
    let prev_hex = prev.map(|h| h.to_hex()).unwrap_or_else(|| "-".to_string());
    let body = format!(
        "{seq}\n{at_ms}\n{kind}\n{}\n{prev_hex}",
        serde_json::to_string(payload).unwrap_or_default()
    );
    Hash::of(body.as_bytes())
}

#[derive(Debug)]
pub struct Journal {
    path: PathBuf,
    events: Vec<Event>,
    /// 上次读/写后的文件字节数：追加前用它判断别的进程有没有先写过。
    last_len: u64,
}

impl Journal {
    /// 打开并**先验一遍链**：链断了直接拒绝工作，不在坏账上继续追加。
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, JournalError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let events = Self::read(&path)?;
        let last_len = fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0);
        Ok(Self {
            path,
            events,
            last_len,
        })
    }

    /// 审计专用：文件坏了也要拿到一个空壳，让 audit 能把“坏在哪”报出来，
    /// 而不是在打开仓库时就只剩一句 io 错误。
    pub fn empty(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            events: Vec::new(),
            last_len: 0,
        }
    }

    fn read(path: &Path) -> Result<Vec<Event>, JournalError> {
        if !path.is_file() {
            return Ok(Vec::new());
        }
        let text = fs::read_to_string(path)?;
        let mut events: Vec<Event> = Vec::new();
        for (index, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let line_no = index + 1;
            let event: Event = serde_json::from_str(line).map_err(|e| JournalError::BadLine {
                line: line_no,
                detail: e.to_string(),
            })?;
            let expected_hash = event_hash(
                event.seq,
                event.at_ms,
                &event.kind,
                &event.payload,
                event.prev.as_ref(),
            );
            if expected_hash != event.hash {
                return Err(JournalError::Broken { line: line_no });
            }
            let expected_prev = events.last().map(|e| e.hash);
            if event.prev != expected_prev && !(events.is_empty() && event.prev.is_none()) {
                return Err(JournalError::WrongPrev {
                    line: line_no,
                    expected: expected_prev.map(|h| h.to_hex()),
                    actual: event.prev.map(|h| h.to_hex()),
                });
            }
            let expected_seq = events.len() as u64;
            if event.seq != expected_seq {
                return Err(JournalError::SeqGap {
                    line: line_no,
                    expected: expected_seq,
                    actual: event.seq,
                });
            }
            events.push(event);
        }
        Ok(events)
    }

    pub fn events(&self) -> &[Event] {
        &self.events
    }

    pub fn head(&self) -> Option<Hash> {
        self.events.last().map(|e| e.hash)
    }

    pub fn append(
        &mut self,
        kind: &str,
        payload: Value,
        at_ms: u64,
    ) -> Result<Event, JournalError> {
        let _lock = JournalLock::acquire(&self.path)?;
        // 拿到锁后先看文件有没有被别人追加/截断：有就把内存里的链换成盘上的链，
        // 否则两个进程会拿着同一个 seq 各写一条，链当场分叉。
        let len = fs::metadata(&self.path).map(|meta| meta.len()).unwrap_or(0);
        if len != self.last_len {
            self.events = Self::read(&self.path)?;
            self.last_len = len;
        }
        let seq = self.events.len() as u64;
        let prev = self.head();
        let hash = event_hash(seq, at_ms, kind, &payload, prev.as_ref());
        let event = Event {
            seq,
            at_ms,
            kind: kind.to_string(),
            payload,
            prev,
            hash,
        };
        let line = serde_json::to_string(&event).map_err(|e| JournalError::BadLine {
            line: seq as usize + 1,
            detail: e.to_string(),
        })?;
        let mut file = open_append_with_retry(&self.path)?;
        writeln!(file, "{line}").map_err(JournalError::Io)?;
        file.sync_data().map_err(JournalError::Io)?;
        drop(file);
        self.last_len = fs::metadata(&self.path).map(|meta| meta.len()).unwrap_or(0);
        self.events.push(event.clone());
        Ok(event)
    }

    /// 只验不追加：返回事件条数。
    pub fn verify(path: impl AsRef<Path>) -> Result<usize, JournalError> {
        Ok(Self::read(path.as_ref())?.len())
    }
}

struct JournalLock {
    path: PathBuf,
}

/// Windows 上杀毒/索引器偶尔会短暂占住刚写的日志，`append` 打开时给 `AccessDenied`。
/// 这不是锁冲突（锁只管 `journal.lock`），给几百毫秒退避，避免把并发写变成假失败。
fn open_append_with_retry(path: &Path) -> Result<fs::File, JournalError> {
    let mut attempts = 0;
    loop {
        match OpenOptions::new().create(true).append(true).open(path) {
            Ok(file) => return Ok(file),
            Err(err)
                if err.kind() == std::io::ErrorKind::PermissionDenied
                    && attempts < OPEN_RETRIES =>
            {
                attempts += 1;
                std::thread::sleep(OPEN_RETRY_DELAY);
            }
            Err(err) => return Err(JournalError::Io(err)),
        }
    }
}

impl JournalLock {
    fn acquire(journal: &Path) -> Result<Self, JournalError> {
        let path = journal.with_extension("lock");
        let started = std::time::Instant::now();
        loop {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(_) => return Ok(Self { path }),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    if lock_timed_out(started) {
                        return Err(JournalError::Locked(path));
                    }
                    std::thread::sleep(LOCK_RETRY);
                }
                // Windows 上锁文件的 create_new 也会被扫描器短暂拒绝；这不是"有人持锁"，
                // 不能立刻判失败，否则并发追加会被杀毒软件打成假红。
                Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                    if lock_timed_out(started) {
                        return Err(JournalError::Io(err));
                    }
                    std::thread::sleep(LOCK_RETRY);
                }
                Err(err) => return Err(JournalError::Io(err)),
            }
        }
    }
}

fn lock_timed_out(started: std::time::Instant) -> bool {
    started.elapsed() >= LOCK_TIMEOUT
}

impl Drop for JournalLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn temp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("trit-vcs-journal-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir.join("journal.jsonl")
    }

    #[test]
    fn append_and_verify() {
        let path = temp("append");
        let mut journal = Journal::open(&path).unwrap();
        journal
            .append("commit", json!({"tree": "abc"}), 1000)
            .unwrap();
        journal
            .append("claim", json!({"owner": "qoder:s1"}), 1001)
            .unwrap();
        journal
            .append("gate", json!({"verdict": "true"}), 1002)
            .unwrap();
        assert_eq!(journal.events().len(), 3);
        assert_eq!(Journal::verify(&path).unwrap(), 3);
        // 链：后一条的 prev 必须等于前一条的 hash
        let events = journal.events();
        assert_eq!(events[1].prev, Some(events[0].hash));
        assert_eq!(events[2].prev, Some(events[1].hash));
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn tampering_with_a_middle_event_is_detected() {
        let path = temp("tamper");
        let mut journal = Journal::open(&path).unwrap();
        for i in 0..3 {
            journal.append("commit", json!({"i": i}), 1000 + i).unwrap();
        }
        let text = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
        lines[1] = lines[1].replace("\"i\":1", "\"i\":9");
        fs::write(&path, lines.join("\n") + "\n").unwrap();
        assert!(matches!(
            Journal::verify(&path),
            Err(JournalError::Broken { .. })
        ));
    }

    #[test]
    fn dropping_an_event_breaks_prev_links() {
        let path = temp("drop");
        let mut journal = Journal::open(&path).unwrap();
        for i in 0..3 {
            journal.append("commit", json!({"i": i}), 1000 + i).unwrap();
        }
        let text = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        fs::write(&path, format!("{}\n{}\n", lines[0], lines[2])).unwrap();
        assert!(Journal::verify(&path).is_err(), "删掉中间一条必须现形");
    }

    #[test]
    fn refusing_to_append_on_a_broken_chain() {
        let path = temp("broken-open");
        let mut journal = Journal::open(&path).unwrap();
        journal.append("commit", json!({"i": 0}), 1000).unwrap();
        let mut text = fs::read_to_string(&path).unwrap();
        text = text.replace("\"i\":0", "\"i\":1");
        fs::write(&path, text).unwrap();
        assert!(Journal::open(&path).is_err(), "坏链上不许继续追加");
    }

    /// 模拟"写坏的写入方"：prev 指错但把自己的 hash 算对了。
    /// 哈希校验抓不到（hash 自洽），只有 prev 链接检查能抓——这条专钉那一段。
    #[test]
    fn wrong_prev_with_self_consistent_hash_is_caught() {
        let path = temp("wrong-prev");
        let first = Event {
            seq: 0,
            at_ms: 1,
            kind: "commit".to_string(),
            payload: json!({"i": 0}),
            prev: None,
            hash: event_hash(0, 1, "commit", &json!({"i": 0}), None),
        };
        let bogus_prev = Hash::of(b"somewhere-else");
        let second = Event {
            seq: 1,
            at_ms: 2,
            kind: "commit".to_string(),
            payload: json!({"i": 1}),
            prev: Some(bogus_prev),
            hash: event_hash(1, 2, "commit", &json!({"i": 1}), Some(&bogus_prev)),
        };
        let body = format!(
            "{}
{}
",
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap()
        );
        fs::write(&path, body).unwrap();
        assert!(matches!(
            Journal::verify(&path),
            Err(JournalError::WrongPrev { .. })
        ));
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn payload_order_is_stable_across_runs() {
        let a = temp("stable-a");
        let b = temp("stable-b");
        let mut ja = Journal::open(&a).unwrap();
        let mut jb = Journal::open(&b).unwrap();
        let payload = json!({"z": 1, "a": {"y": 2, "b": 3}});
        let ea = ja.append("x", payload.clone(), 7).unwrap();
        let eb = jb.append("x", payload, 7).unwrap();
        assert_eq!(ea.hash, eb.hash, "同样的 payload 必须得到同一个 hash");
        let _ = fs::remove_dir_all(a.parent().unwrap());
        let _ = fs::remove_dir_all(b.parent().unwrap());
    }

    #[test]
    fn concurrent_appends_keep_one_chain() {
        use std::sync::{Arc, Barrier};

        let path = temp("concurrent");
        let threads = 8;
        let per_thread = 20;
        let barrier = Arc::new(Barrier::new(threads));
        let mut handles = Vec::new();
        for _ in 0..threads {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                let mut journal = Journal::open(&path).unwrap();
                barrier.wait();
                for i in 0..per_thread {
                    match journal.append("concurrent", json!({"i": i}), 1_000 + i as u64) {
                        Ok(_) => {}
                        Err(err) => panic!("append failed: {err:?}"),
                    }
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        let events = Journal::verify(&path).unwrap();
        assert_eq!(events, threads * per_thread, "并发追加不能丢事件");
        let journal = Journal::open(&path).unwrap();
        for (index, event) in journal.events().iter().enumerate() {
            assert_eq!(event.seq, index as u64, "seq 必须唯一且连续");
        }
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }
}
