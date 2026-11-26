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

    /// 读服务端视图；`from` 是本地 pin 的高度与前缀根，服务端据此附一致性证明。
    pub fn view(
        &self,
        name: &str,
        from: Option<(usize, crate::hash::Hash)>,
    ) -> Result<ViewReply, NetError> {
        crate::repo::Repo::validate_ref(name)
            .map_err(|err| NetError::BadView(format!("ref 名不合法：{err}")))?;
        let mut path = format!("/v1/view?ref={}", percent_encode(name));
        if let Some((height, root)) = from {
            path.push_str(&format!(
                "&from_height={height}&from_root={}",
                percent_encode(&root.to_hex())
            ));
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
        let body = read_body(&mut reader, MAX_ERROR_BODY)?;
        let value: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|err| NetError::BadView(format!("视图不是 JSON：{err}")))?;
        let request_id = response
            .header("x-trit-request-id")
            .filter(|raw| crate::hash::Hash::from_hex(raw).is_some())
            .ok_or(NetError::BadResponse)?
            .to_string();
        if value.get("ok").and_then(serde_json::Value::as_bool) != Some(true)
            || value.get("ref").and_then(serde_json::Value::as_str) != Some(name)
        {
            return Err(NetError::BadView(
                "视图缺 ok/ref 或 ref 与请求不符".to_string(),
            ));
        }
        let snapshot = crate::view::Snapshot::from_json(&serde_json::json!({
            "schema": value.get("schema"),
            "height": value.get("height"),
            "head": value.get("head"),
            "root": value.get("root"),
            "tip": value.get("tip"),
        }))
        .map_err(|err| NetError::BadView(err.to_string()))?;
        let consistency = match value.get("consistency") {
            None | Some(serde_json::Value::Null) => None,
            Some(proof) => Some(
                serde_json::from_value::<crate::checkpoint::consistency::ConsistencyProof>(
                    proof.clone(),
                )
                .map_err(|err| NetError::BadView(format!("一致性证明解不开：{err}")))?,
            ),
        };
        Ok(ViewReply {
            snapshot,
            consistency,
            request_id,
        })
    }

    /// 把 `body` 发到 `ref`；服务端返回 publish 读数。
    pub fn publish(
        &self,
        name: &str,
        tip: &crate::hash::Hash,
        body: &wire::Body,
        store: &crate::store::Store,
        op_id: &str,
    ) -> Result<PublishReply, NetError> {
        validate_op_id(op_id)?;
        let length = body
            .byte_len(store)
            .map_err(|err| NetError::Wire(err.to_string()))?;
        let mut stream = self.connect()?;
        let path = format!("/v1/publish?ref={}", percent_encode(name));
        let head = format!(
            "POST {path} HTTP/1.1\r\nhost: {}\r\nauthorization: Bearer {}\r\n\
             x-trit-tip: {}\r\nx-trit-op-id: {op_id}\r\ncontent-length: {length}\r\nconnection: close\r\n\r\n",
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
        serde_json::from_slice::<serde_json::Value>(&body)
            .map_err(|err| NetError::Status(200, format!("响应不是 JSON：{err}")))?;
        let request_id = response
            .header("x-trit-request-id")
            .filter(|raw| crate::hash::Hash::from_hex(raw).is_some())
            .ok_or(NetError::BadResponse)?
            .to_string();
        if response.header("x-trit-op-id") != Some(op_id) {
            return Err(NetError::BadResponse);
        }
        Ok(PublishReply { request_id })
    }

    /// 拉 `ref`（可限定前缀），边读边入库；返回回执头。
    pub fn pull(
        &self,
        name: &str,
        prefix: Option<&str>,
        store: &crate::store::Store,
        limits: Limits,
        op_id: &str,
    ) -> Result<PullReply, NetError> {
        validate_op_id(op_id)?;
        let mut path = format!("/v1/pull?ref={}", percent_encode(name));
        if let Some(prefix) = prefix {
            path.push_str(&format!("&prefix={}", percent_encode(prefix)));
        }
        path.push_str(&format!("&op_id={}", percent_encode(op_id)));
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
        let request_id = response
            .header("x-trit-request-id")
            .filter(|raw| crate::hash::Hash::from_hex(raw).is_some())
            .ok_or(NetError::BadResponse)?
            .to_string();
        if response.header("x-trit-op-id") != Some(op_id) {
            return Err(NetError::BadResponse);
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
            request_id,
        })
    }

    fn authority(&self) -> &str {
        self.base.strip_prefix("http://").unwrap_or(&self.base)
    }
}

#[derive(Clone, Debug)]
pub struct PublishReply {
    pub request_id: String,
}

/// 服务端视图：快照 + 可选的旧→新一致性证明 + 关联号。
#[derive(Clone, Debug)]
pub struct ViewReply {
    pub snapshot: crate::view::Snapshot,
    pub consistency: Option<crate::checkpoint::consistency::ConsistencyProof>,
    pub request_id: String,
}

#[derive(Clone, Debug)]
pub struct PullReply {
    pub tip: crate::hash::Hash,
    pub manifest: crate::hash::Hash,
    pub files: usize,
    pub objects: usize,
    pub declared: u64,
    pub received: usize,
    pub request_id: String,
}

fn validate_op_id(op_id: &str) -> Result<(), NetError> {
    if !crate::sync::valid_op_id(op_id) {
        return Err(NetError::BadOpId);
    }
    Ok(())
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
