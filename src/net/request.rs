//! HTTP 请求解析与请求关联字段；每个合法请求在入口生成独立 request id。

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::net::TcpStream;

use super::{MAX_HEAD_BYTES, MAX_HEADERS, NetError, auth};

pub(super) struct Request {
    pub(super) method: String,
    pub(super) path: String,
    pub(super) query: BTreeMap<String, String>,
    pub(super) headers: BTreeMap<String, String>,
    pub(super) length: u64,
    pub(super) request_id: String,
    pub(super) actor: Option<String>,
    pub(super) op_id: Option<String>,
}

impl Request {
    pub(super) fn correlation_headers(&self) -> Vec<(&str, &str)> {
        let mut headers = vec![("X-Trit-Request-Id", self.request_id.as_str())];
        if let Some(op_id) = self.valid_op_id() {
            headers.push(("X-Trit-Op-Id", op_id));
        }
        headers
    }

    pub(super) fn valid_op_id(&self) -> Option<&str> {
        self.op_id
            .as_deref()
            .filter(|raw| crate::sync::valid_op_id(raw))
    }

    pub(super) fn require_op_id(&self) -> Result<Option<String>, NetError> {
        match &self.op_id {
            None => Ok(None),
            Some(op_id) if crate::sync::valid_op_id(op_id) => Ok(Some(op_id.clone())),
            Some(_) => Err(NetError::BadOpId),
        }
    }
}

pub(super) fn read_request(reader: &mut BufReader<TcpStream>) -> Result<Option<Request>, NetError> {
    let mut head_bytes = 0usize;
    let mut first = String::new();
    if reader.read_line(&mut first)? == 0 {
        return Ok(None);
    }
    head_bytes += first.len();
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();
    let version = parts.next().unwrap_or_default().to_string();
    if method.is_empty() || target.is_empty() {
        return Err(NetError::BadRequestLine(first.trim().to_string()));
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(NetError::BadVersion(version));
    }
    let (path, query) = split_target(&target);
    let mut headers = BTreeMap::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        head_bytes += line.len();
        if head_bytes > MAX_HEAD_BYTES {
            return Err(NetError::HeadTooLarge);
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        let Some((name, value)) = trimmed.split_once(':') else {
            return Err(NetError::BadRequestLine(trimmed.to_string()));
        };
        let name = name.trim().to_ascii_lowercase();
        if headers.contains_key(&name) {
            return Err(NetError::BadRequestLine(format!("重复的头：{name}")));
        }
        if headers.len() >= MAX_HEADERS {
            return Err(NetError::TooManyHeaders);
        }
        headers.insert(name, value.trim().to_string());
    }
    if let Some(encoding) = headers.get("transfer-encoding") {
        return Err(NetError::BadTransferEncoding(encoding.clone()));
    }
    let length = match headers.get("content-length") {
        Some(raw) => raw
            .parse::<u64>()
            .map_err(|_| NetError::BadRequestLine(format!("Content-Length 不合法：{raw}")))?,
        None if method == "POST" => return Err(NetError::MissingLength),
        None => 0,
    };
    let op_id = if method == "POST" {
        headers.get("x-trit-op-id").cloned()
    } else {
        query.get("op_id").cloned()
    };
    Ok(Some(Request {
        method,
        path,
        query,
        headers,
        length,
        request_id: auth::request_id(),
        actor: None,
        op_id,
    }))
}

pub(super) fn split_target(target: &str) -> (String, BTreeMap<String, String>) {
    let (path, raw_query) = match target.split_once('?') {
        Some((path, query)) => (path, query),
        None => (target, ""),
    };
    let mut query = BTreeMap::new();
    for pair in raw_query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = match pair.split_once('=') {
            Some((key, value)) => (key, value),
            None => (pair, ""),
        };
        query.insert(percent_decode(key), percent_decode(value));
    }
    (path.to_string(), query)
}

pub(super) fn percent_decode(raw: &str) -> String {
    let mut out = Vec::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hex = &raw[index + 1..index + 3];
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    out.push(byte);
                    index += 3;
                    continue;
                }
                out.push(bytes[index]);
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}
