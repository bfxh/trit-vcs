//! 提前拒绝的统一出口：先排空小 body，再回 JSON；大 body 不为了回执读进内存。

use std::io::{BufReader, Read};
use std::net::TcpStream;

use super::{NetError, Request, respond_json};

/// 提前拒绝时最多排空多少请求体。超过就直关闭：宁可让客户端看到 RST，
/// 也不为了回一条 JSON 把 256 MiB body 读进内存/带宽。
const DRAIN_LIMIT: u64 = 1024 * 1024;

/// 读掉一小段请求体，避免"服务端没读完就关连接"在 Windows 上变成 RST（连回执一起丢）。
pub(super) fn drain_body<R: Read>(reader: R, length: u64) {
    if length == 0 || length > DRAIN_LIMIT {
        return;
    }
    let mut limited = reader.take(length);
    let _ = std::io::copy(&mut limited, &mut std::io::sink());
}

/// 提前拒绝的统一出口：先排空（有上限），再回 JSON。
pub(super) fn reject_json(
    reader: &mut BufReader<TcpStream>,
    request: &Request,
    status: u16,
    kind: &str,
    message: &str,
    extra: &[(&str, &str)],
) -> Result<(), NetError> {
    drain_body(&mut *reader, request.length);
    respond_json(reader.get_mut(), status, kind, message, extra)
}
