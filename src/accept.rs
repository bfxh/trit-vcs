//! `intent.accept` 的执行面：**默认关**，只有显式 `--verify-accept` 才跑。
//!
//! 这是"执行提交里记下来的命令"= 在本机跑陌生人的代码，所以每一条限制都有理由：
//!  · **不走 shell**：按空白切成 argv，出现 `|` `>` `<` `$` `;` `&` `` ` `` `(` `)` 直接拒
//!    （`accept_shell_meta`）。`sh -c` 会把提交内容变成任意脚本，这不是"判据"该有的能力。
//!  · **单条超时**：默认 60 秒，超时杀进程（Windows 连子进程一起 `taskkill /T`）；
//!    超时的判据算**没通过**，不算"跳过"。
//!  · **输出截断**：只留前 2 KB，另记总字节数；截断处明写，不许假装输出就这么短。
//!  · **密钥粗筛**：常见的 token 前缀在摘要里打码 —— 判据的输出会进日志/证据，密钥不能跟着走。
//!
//! 调用方还欠一条：**只对已认领范围内的改动跑**（`gate::check` 判 `Allowed`），否则一次
//! `pull` + 一次例行预检就可能在维护者机器上执行陌生人的命令。

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
pub const DEFAULT_OUTPUT_CAP: usize = 2048;

/// 一条判据的执行结果。`exit=None` 表示没跑起来（spawn 失败）或被超时杀掉。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptOutcome {
    pub command: String,
    pub exit: Option<i32>,
    pub timed_out: bool,
    pub duration_ms: u64,
    pub output_excerpt: String,
    pub output_bytes: usize,
    pub truncated: bool,
}

impl AcceptOutcome {
    pub fn passed(&self) -> bool {
        !self.timed_out && self.exit == Some(0)
    }
}

/// 一批判据的结果。空集算通过（没有判据就是没有要验的），但调用方要显式说明这一点。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptReport {
    pub outcomes: Vec<AcceptOutcome>,
}

impl AcceptReport {
    pub fn passed(&self) -> bool {
        self.outcomes.iter().all(AcceptOutcome::passed)
    }

    pub fn failed(&self) -> impl Iterator<Item = &AcceptOutcome> {
        self.outcomes.iter().filter(|outcome| !outcome.passed())
    }
}

/// 判据命令本身的问题：不是"没通过"，是"根本不该跑"。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptError {
    /// 含 shell 元字符（或为空）：拒绝执行，理由是"判据不是脚本"。
    ShellMeta { command: String, meta: char },
    /// 空命令：`--accept ""` 这种。
    Empty,
}

impl std::fmt::Display for AcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ShellMeta { command, meta } => write!(
                f,
                "判据里含 shell 元字符 `{meta}`，拒绝执行：{command}（判据是 argv，不是脚本）"
            ),
            Self::Empty => f.write_str("判据是空串"),
        }
    }
}

/// 判据不是脚本：这些字符一律拒绝（`sh -c` 会把提交内容变成任意脚本）。
fn is_shell_meta(c: char) -> bool {
    matches!(
        c,
        '|' | '>' | '<' | '$' | ';' | '&' | '`' | '(' | ')' | '\n' | '\r'
    )
}

/// 按空白切 argv；含 shell 元字符或为空 ⇒ 拒绝。
pub fn split_argv(command: &str) -> Result<Vec<String>, AcceptError> {
    if let Some(meta) = command.chars().find(|c| is_shell_meta(*c)) {
        return Err(AcceptError::ShellMeta {
            command: command.to_string(),
            meta,
        });
    }
    let argv: Vec<String> = command.split_whitespace().map(str::to_string).collect();
    if argv.is_empty() {
        return Err(AcceptError::Empty);
    }
    Ok(argv)
}

/// 常见密钥前缀打码：判据输出会进日志/证据，密钥不能跟着走。
///
/// 按"前缀 + 后继字符"抠，而不是按空白分词 —— 真实现场里密钥常写成 `TOKEN=ghp_…`
/// 或 `Authorization: token ghp_…`，按词首匹配会整条漏掉（第一版就是这么漏的）。
pub fn redact(text: &str) -> String {
    const PREFIXES: [&str; 4] = ["ghp_", "github_pat_", "sk-", "gho_"];
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    loop {
        let mut best: Option<(usize, &str)> = None;
        for prefix in PREFIXES {
            if let Some(pos) = rest.find(prefix)
                && best.is_none_or(|(found, _)| pos < found)
            {
                best = Some((pos, prefix));
            }
        }
        let Some((pos, prefix)) = best else {
            out.push_str(rest);
            return out;
        };
        out.push_str(&rest[..pos]);
        out.push_str(prefix);
        out.push_str("<已打码>");
        let body = &rest[pos + prefix.len()..];
        let end = body
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
            .unwrap_or(body.len());
        rest = &body[end..];
    }
}

/// 跑一批判据。`cwd` 是仓库根；`cap` 是每条输出保留的字节数。
///
/// 单条失败不中断后续（要不修完一条又冒出下一条，智能体得多跑几轮）；
/// 超时的那条按"没通过"算。
pub fn run(
    commands: &[String],
    cwd: &Path,
    timeout: Duration,
    cap: usize,
) -> Result<AcceptReport, AcceptError> {
    let mut outcomes = Vec::with_capacity(commands.len());
    for command in commands {
        let argv = split_argv(command)?;
        outcomes.push(run_one(command, &argv, cwd, timeout, cap));
    }
    Ok(AcceptReport { outcomes })
}

fn run_one(
    command: &str,
    argv: &[String],
    cwd: &Path,
    timeout: Duration,
    cap: usize,
) -> AcceptOutcome {
    let started = Instant::now();
    let mut child = match Command::new(&argv[0])
        .args(&argv[1..])
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            return AcceptOutcome {
                command: command.to_string(),
                exit: None,
                timed_out: false,
                duration_ms: started.elapsed().as_millis() as u64,
                output_excerpt: format!("启动失败：{err}"),
                output_bytes: 0,
                truncated: false,
            };
        }
    };

    // 输出必须边跑边抽干：管道写满（~64 KB）子进程会卡住，超时就会变成假红。
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let drain_out = stdout.map(|source| std::thread::spawn(move || drain(source, cap)));
    let drain_err = stderr.map(|source| std::thread::spawn(move || drain(source, cap)));

    let mut timed_out = false;
    let mut status = None;
    loop {
        match child.try_wait() {
            Ok(Some(exit)) => {
                status = Some(exit);
                break;
            }
            Ok(None) => {}
            Err(_) => break,
        }
        if started.elapsed() >= timeout {
            timed_out = true;
            kill_tree(child.id());
            let _ = child.wait();
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    let (mut text, mut bytes, mut truncated) = drain_out
        .map(|handle| handle.join().unwrap_or_default())
        .unwrap_or_default();
    let (err_text, err_bytes, err_truncated) = drain_err
        .map(|handle| handle.join().unwrap_or_default())
        .unwrap_or_default();
    if !err_text.trim().is_empty() {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&err_text);
    }
    bytes += err_bytes;
    truncated |= err_truncated;

    AcceptOutcome {
        command: command.to_string(),
        exit: status.and_then(|status| status.code()),
        timed_out,
        duration_ms: started.elapsed().as_millis() as u64,
        output_excerpt: redact(&text),
        output_bytes: bytes,
        truncated,
    }
}

/// 读干一条管道：只留前 `cap` 字节，其余照读照数（不读会卡住子进程）。
fn drain(mut reader: impl Read, cap: usize) -> (String, usize, bool) {
    let mut kept: Vec<u8> = Vec::new();
    let mut total = 0usize;
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                total += read;
                if kept.len() < cap {
                    let room = cap - kept.len();
                    kept.extend_from_slice(&buf[..read.min(room)]);
                }
            }
        }
    }
    (
        String::from_utf8_lossy(&kept).to_string(),
        total,
        total > kept.len(),
    )
}

/// 超时杀进程。Windows 连子进程一起杀（`/T`）；POSIX 上尽力杀进程组再杀自己。
fn kill_tree(pid: u32) {
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(unix)]
    {
        let _ = Command::new("kill")
            .args(["-KILL", &format!("-{pid}")])
            .stderr(Stdio::null())
            .status();
        let _ = Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = pid;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_rejects_shell_meta_and_empty() {
        assert_eq!(
            split_argv("cargo test -q"),
            Ok(vec![
                "cargo".to_string(),
                "test".to_string(),
                "-q".to_string()
            ])
        );
        for bad in [
            "echo a > b",
            "a | b",
            "a && b",
            "a $(id)",
            "a `id`",
            "a;b",
            "a\nb",
            "a & b",
        ] {
            assert!(
                matches!(split_argv(bad), Err(AcceptError::ShellMeta { .. })),
                "{bad} 本该被拒"
            );
        }
        assert_eq!(split_argv("   "), Err(AcceptError::Empty));
    }

    #[test]
    fn secrets_are_masked_in_excerpts() {
        let out = redact("token=ghp_abcdef123456 and sk-zzz9 plus keep_this");
        assert!(!out.contains("ghp_abcdef"), "{out}");
        assert!(!out.contains("sk-zzz9"), "{out}");
        assert!(out.contains("keep_this"), "{out}");
        assert!(redact("github_pat_11ABC").contains("<已打码>"));
    }

    #[test]
    fn passing_and_failing_commands_are_told_apart() {
        // `cargo --version` 在两个平台上都有；失败那条用一个必然不存在的参数。
        let cwd = std::env::temp_dir();
        let report = run(
            &[
                "cargo --version".to_string(),
                "cargo --definitely-not-a-flag".to_string(),
            ],
            &cwd,
            Duration::from_secs(60),
            2048,
        )
        .unwrap();
        assert_eq!(report.outcomes.len(), 2);
        assert!(report.outcomes[0].passed(), "{:?}", report.outcomes[0]);
        assert!(!report.outcomes[1].passed(), "{:?}", report.outcomes[1]);
        assert_eq!(report.failed().count(), 1);
        assert!(!report.passed());
    }

    #[test]
    fn timeout_kills_and_counts_as_failure() {
        // 平台各一条"能跑很久"的命令：argv 形态，不需要 shell。
        #[cfg(windows)]
        let command = "cmd /c ping -n 20 127.0.0.1";
        #[cfg(unix)]
        let command = "sleep 20";
        let report = run(
            &[command.to_string()],
            &std::env::temp_dir(),
            Duration::from_millis(300),
            2048,
        )
        .unwrap();
        let outcome = &report.outcomes[0];
        assert!(outcome.timed_out, "应当判超时：{outcome:?}");
        assert!(!outcome.passed(), "超时算没通过");
        assert!(
            outcome.duration_ms < 15_000,
            "超时后不能还等 20 秒：{outcome:?}"
        );
    }

    #[test]
    fn output_is_capped_and_truncation_is_declared() {
        // 用 cargo 的长输出（--list 会打很多行）压 200 字节上限。
        let report = run(
            &["cargo --list".to_string()],
            &std::env::temp_dir(),
            Duration::from_secs(60),
            200,
        )
        .unwrap();
        let outcome = &report.outcomes[0];
        assert!(outcome.output_excerpt.len() <= 200, "{:?}", outcome);
        assert!(
            outcome.output_bytes > outcome.output_excerpt.len(),
            "{outcome:?}"
        );
        assert!(outcome.truncated, "{outcome:?}");
    }
}
