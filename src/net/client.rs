//! 客户端：一个 base URL + 一个 token，每请求一条连接。
//!
//! 只支持 `http://host:port`（无 TLS，见模块文档）；不跟随重定向、不重试。

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use super::{Limits, MAX_HEAD_BYTES, NetError, normalize_base, percent_encode};
use crate::wire;

const MAX_ERROR_BODY: usize = 1024 * 1024;

/// 客户端：一个 base URL + 一个 token，方法各自一条连接。
pub struct Client {
    base: String,
    token: String,
    timeout: Duration,
}

impl Client {
    pub fn new(base: &str, token: &str) -> Result<Self, NetError> {
        let base = normalize_base(base)?;
        if token.len() < 16 {
            return Err(NetError::BadToken("至少 16 字节".to_string()));
        }
        Ok(Self {
            base,
            token: token.to_string(),
            timeout: Duration::from_secs(60),
        })
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    fn connect(&self) -> Result<TcpStream, NetError> {
        let authority = self
            .base
            .strip_prefix("http://")
            .expect("normalize_base 已经保证");
        let stream = TcpStream::connect(authority)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        Ok(stream)
    }

    /// `GET` 一个小 JSON（health / refs）。
    pub fn get_json(&self, path: &str) -> Result<serde_json::Value, NetError> {
        let mut stream = self.connect()?;
        let head = format!(
            "GET {path} HTTP/1.1\r\nhost: {}\r\nauthorization: Bearer {}\r\nconnection: close\r\n\r\n",
            self.authority(),
            self.token
        );
        stream.write_all(head.as_bytes())?;
        let mut reader = BufReader::new(stream);
        let response = read_response_head(&mut reader)?;
        if response.status != 200 {
            let body = read_body(&mut reader, MAX_ERROR_BODY)?;
            return Err(NetError::Status(response.status, error_message(&body)));
        }
        let body = read_body(&mut reader, MAX_ERROR_BODY)?;
        serde_json::from_slice(&body)
            .map_err(|err| NetError::Status(200, format!("响应不是 JSON：{err}")))
    }

    pub fn refs(&self) -> Result<Vec<(String, crate::hash::Hash)>, NetError> {
        let value = self.get_json("/v1/refs")?;
        let mut out = Vec::new();
        for row in value["refs"].as_array().cloned().unwrap_or_default() {
            let name = row["name"].as_str().unwrap_or_default().to_string();
            let commit = row["commit"]
                .as_str()
                .and_then(crate::hash::Hash::from_hex)
                .ok_or_else(|| NetError::Status(200, "refs 里有不合法的提交 id".to_string()))?;
            out.push((name, commit));
        }
        Ok(out)
    }

    /// 把 `body` 发到 `ref`；服务端返回 publish 读数。
    pub fn publish(
        &self,
        name: &str,
        tip: &crate::hash::Hash,
        body: &wire::Body,
        store: &crate::store::Store,
    ) -> Result<serde_json::Value, NetError> {
        let length = body
            .byte_len(store)
            .map_err(|err| NetError::Wire(err.to_string()))?;
        let mut stream = self.connect()?;
        let path = format!("/v1/publish?ref={}", percent_encode(name));
        let head = format!(
            "POST {path} HTTP/1.1\r\nhost: {}\r\nauthorization: Bearer {}\r\n\
             x-trit-tip: {}\r\ncontent-length: {length}\r\nconnection: close\r\n\r\n",
            self.authority(),
            self.token,
            tip.to_hex()
        );
        stream.write_all(head.as_bytes())?;
        // 服务端在读完 body 之前就可能判 401/413 并关连接：Windows 上这时继续写会拿到
        // 10054。写失败不等于没有回执——先试着读响应，能读到就以响应为准。
        let write_error = body
            .write(store, &mut stream)
            .err()
            .map(|err| NetError::Wire(err.to_string()));
        let mut reader = BufReader::new(stream);
        let response = match read_response_head(&mut reader) {
            Ok(response) => response,
            Err(read_error) => return Err(write_error.unwrap_or(read_error)),
        };
        let body = read_body(&mut reader, MAX_ERROR_BODY)?;
        if response.status != 200 {
            return Err(NetError::Status(response.status, error_message(&body)));
        }
        if let Some(err) = write_error {
            return Err(err);
        }
        serde_json::from_slice(&body)
            .map_err(|err| NetError::Status(200, format!("响应不是 JSON：{err}")))
    }

    /// 拉 `ref`（可限定前缀），边读边入库；返回回执头。
    pub fn pull(
        &self,
        name: &str,
        prefix: Option<&str>,
        store: &crate::store::Store,
        limits: Limits,
    ) -> Result<PullReply, NetError> {
        let mut path = format!("/v1/pull?ref={}", percent_encode(name));
        if let Some(prefix) = prefix {
            path.push_str(&format!("&prefix={}", percent_encode(prefix)));
        }
        let mut stream = self.connect()?;
        let head = format!(
            "GET {path} HTTP/1.1\r\nhost: {}\r\nauthorization: Bearer {}\r\nconnection: close\r\n\r\n",
            self.authority(),
            self.token
        );
        stream.write_all(head.as_bytes())?;
        let mut reader = BufReader::new(stream);
        let response = read_response_head(&mut reader)?;
        if response.status != 200 {
            let body = read_body(&mut reader, MAX_ERROR_BODY)?;
            return Err(NetError::Status(response.status, error_message(&body)));
        }
        let tip = response
            .header("x-trit-tip")
            .and_then(crate::hash::Hash::from_hex)
            .ok_or_else(|| NetError::Status(200, "响应缺 X-Trit-Tip".to_string()))?;
        let manifest = response
            .header("x-trit-manifest")
            .and_then(crate::hash::Hash::from_hex)
            .ok_or_else(|| NetError::Status(200, "响应缺 X-Trit-Manifest".to_string()))?;
        let files = response
            .header("x-trit-files")
            .and_then(|raw| raw.parse::<usize>().ok())
            .ok_or_else(|| NetError::Status(200, "响应缺 X-Trit-Files".to_string()))?;
        let objects = response
            .header("x-trit-objects")
            .and_then(|raw| raw.parse::<u32>().ok())
            .ok_or_else(|| NetError::Status(200, "响应缺 X-Trit-Objects".to_string()))?;
        let declared = response
            .header("content-length")
            .and_then(|raw| raw.parse::<u64>().ok())
            .ok_or_else(|| NetError::Status(200, "响应缺 Content-Length".to_string()))?;
        let mut wire_reader = wire::Reader::open(&mut reader, limits)
            .map_err(|err| NetError::Wire(err.to_string()))?;
        let mut received = 0usize;
        loop {
            match wire_reader.next(store) {
                Ok(Some(_)) => received += 1,
                Ok(None) => break,
                Err(err) => return Err(NetError::Wire(err.to_string())),
            }
        }
        wire_reader
            .finish()
            .map_err(|err| NetError::Wire(err.to_string()))?;
        if received != objects as usize {
            return Err(NetError::Status(
                200,
                format!("对象数与回执不符：声明 {objects}，收到 {received}"),
            ));
        }
        Ok(PullReply {
            tip,
            manifest,
            files,
            objects: objects as usize,
            declared,
            received,
        })
    }

    fn authority(&self) -> &str {
        self.base.strip_prefix("http://").unwrap_or(&self.base)
    }
}

#[derive(Clone, Debug)]
pub struct PullReply {
    pub tip: crate::hash::Hash,
    pub manifest: crate::hash::Hash,
    pub files: usize,
    pub objects: usize,
    pub declared: u64,
    pub received: usize,
}

struct ResponseHead {
    status: u16,
    headers: BTreeMap<String, String>,
}

impl ResponseHead {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

fn read_response_head<R: BufRead>(reader: &mut R) -> Result<ResponseHead, NetError> {
    let mut first = String::new();
    reader.read_line(&mut first)?;
    let mut parts = first.split_whitespace();
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err(NetError::BadResponse);
    }
    let status = parts
        .next()
        .and_then(|raw| raw.parse::<u16>().ok())
        .ok_or(NetError::BadResponse)?;
    let mut headers = BTreeMap::new();
    let mut bytes = first.len();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        bytes += line.len();
        if bytes > MAX_HEAD_BYTES + 4096 {
            return Err(NetError::BadResponse);
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        let Some((name, value)) = trimmed.split_once(':') else {
            return Err(NetError::BadResponse);
        };
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }
    Ok(ResponseHead { status, headers })
}

fn read_body<R: Read>(reader: &mut R, max: usize) -> Result<Vec<u8>, NetError> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        if out.len() + read > max {
            return Err(NetError::BodyTooLarge((out.len() + read) as u64));
        }
        out.extend_from_slice(&chunk[..read]);
    }
    Ok(out)
}

fn error_message(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value["message"].as_str().map(str::to_string))
        .unwrap_or_else(|| String::from_utf8_lossy(body).to_string())
}
