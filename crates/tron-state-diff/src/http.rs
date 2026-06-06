//! A minimal blocking HTTP/1.1 client — just enough to POST a JSON body to
//! a node's `/wallet/*` endpoint and read the response.
//!
//! Deliberately dependency-free (matches the rest of the workspace, which
//! hand-rolls its wire protocols). We only ever talk plain HTTP to a LAN
//! full node, so there's no TLS, no redirects, no keep-alive: every request
//! sends `Connection: close` and reads the socket to EOF. Both java-tron
//! (Spring) and this node (axum) return buffered JSON with a `Content-Length`
//! for these endpoints, but we also de-chunk a `Transfer-Encoding: chunked`
//! body defensively.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// POST `body` as `application/json` to `base_url` + `path`. Returns the raw
/// response body bytes on a 2xx, or an error string.
pub fn post_json(
    base_url: &str,
    path: &str,
    body: &str,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let (host, port) = parse_host_port(base_url)?;
    let addr = format!("{host}:{port}");
    let sock = addr
        .to_socket_addrs()
        .map_err(|e| format!("resolve {addr}: {e}"))?
        .next()
        .ok_or_else(|| format!("no socket address for {addr}"))?;
    let mut stream =
        TcpStream::connect_timeout(&sock, timeout).map_err(|e| format!("connect {addr}: {e}"))?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();

    let req = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: application/json\r\n\
         Accept: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n{body}",
        len = body.len(),
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("write {addr}{path}: {e}"))?;
    stream.flush().ok();

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| format!("read {addr}{path}: {e}"))?;
    parse_response(&raw)
}

/// Split `http://host:port` (or bare `host:port`) into `(host, port)`.
/// Defaults to port 80. A trailing path on the base URL is rejected — the
/// caller passes the path separately.
fn parse_host_port(base_url: &str) -> Result<(String, u16), String> {
    let rest = base_url
        .strip_prefix("http://")
        .or_else(|| base_url.strip_prefix("HTTP://"))
        .unwrap_or(base_url);
    if rest.starts_with("https://") || base_url.starts_with("https://") {
        return Err(format!("{base_url}: https is not supported (plain HTTP only)"));
    }
    // Strip any accidental trailing path/slash — we only want host:port.
    let authority = rest.split('/').next().unwrap_or(rest);
    match authority.rsplit_once(':') {
        Some((h, p)) => {
            let port = p
                .parse::<u16>()
                .map_err(|_| format!("{base_url}: bad port {p:?}"))?;
            Ok((h.to_string(), port))
        }
        None => Ok((authority.to_string(), 80)),
    }
}

/// Parse a raw HTTP response: check the status line is 2xx, split headers
/// from body, and de-chunk if needed.
fn parse_response(raw: &[u8]) -> Result<Vec<u8>, String> {
    let sep = find_subslice(raw, b"\r\n\r\n")
        .ok_or_else(|| "malformed response: no header/body separator".to_string())?;
    let header_bytes = &raw[..sep];
    let body = &raw[sep + 4..];

    let header_text = String::from_utf8_lossy(header_bytes);
    let mut lines = header_text.split("\r\n");
    let status = lines.next().unwrap_or("");
    // "HTTP/1.1 200 OK" → the status code is the second token.
    let code = status
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| format!("malformed status line: {status:?}"))?;
    if !(200..300).contains(&code) {
        let snippet = String::from_utf8_lossy(body);
        let snippet = snippet.chars().take(200).collect::<String>();
        return Err(format!("HTTP {code}: {snippet}"));
    }

    let chunked = lines.any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("transfer-encoding:") && l.contains("chunked")
    });
    if chunked {
        dechunk(body)
    } else {
        Ok(body.to_vec())
    }
}

/// Decode an HTTP/1.1 chunked body. Each chunk: `<hexlen>\r\n<data>\r\n`,
/// terminated by a `0\r\n` chunk.
fn dechunk(mut body: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(body.len());
    loop {
        let nl = find_subslice(body, b"\r\n").ok_or("chunked: missing size CRLF")?;
        let size_line = std::str::from_utf8(&body[..nl]).map_err(|_| "chunked: bad size line")?;
        // Chunk size may carry extensions after ';' — ignore them.
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| format!("chunked: bad size {size_hex:?}"))?;
        body = &body[nl + 2..];
        if size == 0 {
            break;
        }
        if body.len() < size {
            return Err("chunked: truncated chunk".into());
        }
        out.extend_from_slice(&body[..size]);
        // Skip the data and its trailing CRLF.
        body = &body[size..];
        if body.starts_with(b"\r\n") {
            body = &body[2..];
        }
    }
    Ok(out)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_host_port_variants() {
        assert_eq!(parse_host_port("http://127.0.0.1:8090").unwrap(), ("127.0.0.1".into(), 8090));
        assert_eq!(parse_host_port("192.168.0.36:8090").unwrap(), ("192.168.0.36".into(), 8090));
        assert_eq!(parse_host_port("http://example.test").unwrap(), ("example.test".into(), 80));
        assert_eq!(
            parse_host_port("http://127.0.0.1:8090/").unwrap(),
            ("127.0.0.1".into(), 8090)
        );
        assert!(parse_host_port("https://x:1").is_err());
    }

    #[test]
    fn parse_response_content_length_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n{\"balance\":1}";
        assert_eq!(parse_response(raw).unwrap(), b"{\"balance\":1}");
    }

    #[test]
    fn parse_response_propagates_http_error() {
        let raw = b"HTTP/1.1 400 Bad Request\r\n\r\nnope";
        let err = parse_response(raw).unwrap_err();
        assert!(err.contains("400") && err.contains("nope"), "{err}");
    }

    #[test]
    fn parse_response_dechunks() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        assert_eq!(parse_response(raw).unwrap(), b"hello world");
    }
}
