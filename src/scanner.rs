//! gRPC scanner v0.3 — uses h2 crate for proper HPACK decoding.
//!
//! v0.2 bug: raw byte-scan for b"grpc-status" missed HPACK Huffman-encoded headers,
//! causing 4,351 HTTP/2-success hosts to report grpc_detected=false.
//! Fix: h2::client::handshake decodes HPACK automatically; we check header values
//! as plain strings, bypassing the Huffman issue entirely.

use bytes::Bytes;
use h2::client;
use hickory_resolver::TokioAsyncResolver;
use http::Request;
use serde::Serialize;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::tls::create_permissive_tls_connector;

const REFLECTION_PATH: &str =
    "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo";

#[derive(Debug, Serialize, Clone)]
pub struct ScanResult {
    pub domain: String,
    pub port: u16,
    pub ip: String,
    pub timestamp: String,
    pub dns_success: bool,
    pub tcp_success: bool,
    pub http2_success: bool,
    pub grpc_detected: bool,
    pub grpc_response: String,
    pub reflection_enabled: bool,
    pub services_count: u32,
    pub services_list: String,
    pub tls_enabled: bool,
    pub tls_version: String,
    pub tls_cipher: String,
    pub cert_issuer: String,
    pub cert_expires: String,
    pub requires_auth: bool,
    pub auth_type: String,
    pub dns_time_ms: u64,
    pub tcp_time_ms: u64,
    pub grpc_time_ms: u64,
    pub total_time_ms: u64,
    pub error: String,
}

impl Default for ScanResult {
    fn default() -> Self {
        Self {
            domain: String::new(),
            port: 0,
            ip: String::new(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            dns_success: false,
            tcp_success: false,
            http2_success: false,
            grpc_detected: false,
            grpc_response: String::new(),
            reflection_enabled: false,
            services_count: 0,
            services_list: String::new(),
            tls_enabled: false,
            tls_version: String::new(),
            tls_cipher: String::new(),
            cert_issuer: String::new(),
            cert_expires: String::new(),
            requires_auth: false,
            auth_type: String::new(),
            dns_time_ms: 0,
            tcp_time_ms: 0,
            grpc_time_ms: 0,
            total_time_ms: 0,
            error: String::new(),
        }
    }
}

pub struct GrpcScanner {
    timeout: Duration,
    tls_connector: TlsConnector,
}

impl GrpcScanner {
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            tls_connector: create_permissive_tls_connector(),
        }
    }

    pub async fn scan(
        &self,
        domain: &str,
        port: u16,
        resolver: &TokioAsyncResolver,
    ) -> ScanResult {
        let start = Instant::now();
        let mut result = ScanResult {
            domain: domain.to_string(),
            port,
            ..Default::default()
        };

        // DNS
        let dns_start = Instant::now();
        let ip = match self.resolve_dns(domain, resolver).await {
            Ok(ip) => {
                result.dns_success = true;
                result.ip = ip.clone();
                ip
            }
            Err(e) => {
                result.error = format!("DNS: {}", e);
                result.dns_time_ms = dns_start.elapsed().as_millis() as u64;
                result.total_time_ms = start.elapsed().as_millis() as u64;
                return result;
            }
        };
        result.dns_time_ms = dns_start.elapsed().as_millis() as u64;

        // TCP
        let tcp_start = Instant::now();
        let stream = match self.connect_tcp(&ip, port).await {
            Ok(s) => {
                result.tcp_success = true;
                s
            }
            Err(e) => {
                result.error = format!("TCP: {}", e);
                result.tcp_time_ms = tcp_start.elapsed().as_millis() as u64;
                result.total_time_ms = start.elapsed().as_millis() as u64;
                return result;
            }
        };
        result.tcp_time_ms = tcp_start.elapsed().as_millis() as u64;

        let grpc_start = Instant::now();
        if port == 443 {
            if let Err(e) = self.scan_tls(stream, domain, &mut result).await {
                result.error = format!("TLS: {}", e);
            }
        } else {
            // Try h2c (plain HTTP/2) first; fall back to TLS
            if self.scan_plain(stream, domain, &mut result).await.is_err() {
                if let Ok(stream2) = self.connect_tcp(&ip, port).await {
                    if let Err(e) = self.scan_tls(stream2, domain, &mut result).await {
                        result.error = format!("TLS: {}", e);
                    }
                }
            }
        }

        result.grpc_time_ms = grpc_start.elapsed().as_millis() as u64;
        result.total_time_ms = start.elapsed().as_millis() as u64;
        result
    }

    async fn resolve_dns(&self, domain: &str, resolver: &TokioAsyncResolver)
        -> Result<String, String>
    {
        let lookup = timeout(self.timeout, resolver.lookup_ip(domain))
            .await
            .map_err(|_| "timeout")?
            .map_err(|e| e.to_string())?;
        lookup
            .iter()
            .next()
            .map(|ip| ip.to_string())
            .ok_or_else(|| "no IP".to_string())
    }

    async fn connect_tcp(&self, ip: &str, port: u16) -> Result<TcpStream, String> {
        timeout(self.timeout, TcpStream::connect(format!("{}:{}", ip, port)))
            .await
            .map_err(|_| "timeout")?
            .map_err(|e| e.to_string())
    }

    async fn scan_tls(
        &self,
        stream: TcpStream,
        domain: &str,
        result: &mut ScanResult,
    ) -> Result<(), String> {
        let server_name = rustls::pki_types::ServerName::try_from(domain.to_string())
            .map_err(|_| "invalid server name")?;

        let tls = timeout(self.timeout, self.tls_connector.connect(server_name, stream))
            .await
            .map_err(|_| "TLS timeout")?
            .map_err(|e| e.to_string())?;

        result.tls_enabled = true;

        // Extract TLS metadata
        {
            let (_, conn) = tls.get_ref();
            if let Some(v) = conn.protocol_version() {
                result.tls_version = format!("{:?}", v);
            }
            if let Some(s) = conn.negotiated_cipher_suite() {
                result.tls_cipher = format!("{:?}", s.suite());
            }
            if let Some(certs) = conn.peer_certificates() {
                if let Some(cert) = certs.first() {
                    if let Ok((_, parsed)) =
                        x509_parser::parse_x509_certificate(cert.as_ref())
                    {
                        let issuer = parsed.issuer();
                        let issuer_str = issuer
                            .iter_common_name()
                            .next()
                            .and_then(|cn| cn.as_str().ok())
                            .or_else(|| {
                                issuer
                                    .iter_organization()
                                    .next()
                                    .and_then(|o| o.as_str().ok())
                            })
                            .unwrap_or("Unknown");
                        result.cert_issuer = issuer_str.to_string();
                        result.cert_expires = parsed
                            .validity()
                            .not_after
                            .to_rfc2822()
                            .unwrap_or_default();
                    }
                }
            }
        }

        // h2 handshake — handles HTTP/2 preface, SETTINGS, and HPACK
        let (send_request, conn) = timeout(self.timeout, client::handshake(tls))
            .await
            .map_err(|_| "h2 handshake timeout")?
            .map_err(|e| e.to_string())?;

        result.http2_success = true;
        tokio::spawn(async move { let _ = conn.await; });

        self.probe_grpc(send_request, domain, "https", result).await
    }

    async fn scan_plain(
        &self,
        stream: TcpStream,
        domain: &str,
        result: &mut ScanResult,
    ) -> Result<(), String> {
        // h2c: HTTP/2 over cleartext TCP
        let (send_request, conn) = timeout(self.timeout, client::handshake(stream))
            .await
            .map_err(|_| "h2c handshake timeout")?
            .map_err(|e| e.to_string())?;

        result.http2_success = true;
        tokio::spawn(async move { let _ = conn.await; });

        self.probe_grpc(send_request, domain, "http", result).await
    }

    async fn probe_grpc(
        &self,
        send_request: client::SendRequest<Bytes>,
        domain: &str,
        scheme: &str,
        result: &mut ScanResult,
    ) -> Result<(), String> {
        // ready() waits for connection capacity; takes self, returns Self
        let mut send_request = send_request.ready().await.map_err(|e| e.to_string())?;

        let request = Request::builder()
            .method("POST")
            .uri(format!("{}://{}{}", scheme, domain, REFLECTION_PATH))
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .header("grpc-accept-encoding", "identity")
            .header("user-agent", "grpc-go/1.59.0")
            .body(())
            .map_err(|e| e.to_string())?;

        let (response_future, mut send_stream) =
            send_request.send_request(request, false).map_err(|e| e.to_string())?;

        // ListServicesRequest protobuf: field 4 (list_services) = ""
        let proto_msg: &[u8] = &[0x22, 0x00];
        let mut grpc_frame = vec![0x00u8, 0x00, 0x00, 0x00, proto_msg.len() as u8];
        grpc_frame.extend_from_slice(proto_msg);
        send_stream
            .send_data(Bytes::from(grpc_frame), true)
            .map_err(|e| e.to_string())?;

        // Await response headers (HPACK-decoded by h2 — no Huffman issue)
        let response = timeout(self.timeout, response_future)
            .await
            .map_err(|_| "response timeout")?
            .map_err(|e| e.to_string())?;

        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if content_type.starts_with("application/grpc") {
            result.grpc_detected = true;
            result.grpc_response = content_type.to_string();
        }

        // Read body frames
        let mut body = response.into_body();
        let mut data_buf = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);

        loop {
            let remaining = deadline
                .saturating_duration_since(tokio::time::Instant::now())
                .max(Duration::from_millis(50));
            match timeout(remaining, body.data()).await {
                Ok(Some(Ok(chunk))) => {
                    let _ = body.flow_control().release_capacity(chunk.len());
                    data_buf.extend_from_slice(&chunk);
                    if data_buf.len() > 65536 {
                        break;
                    }
                }
                _ => break,
            }
        }

        // Check trailers — grpc-status is always a trailer in gRPC protocol
        if let Ok(Ok(Some(trailers))) =
            timeout(Duration::from_secs(2), body.trailers()).await
        {
            if trailers.contains_key("grpc-status") {
                result.grpc_detected = true;
                if let Some(status) =
                    trailers.get("grpc-status").and_then(|v| v.to_str().ok())
                {
                    result.grpc_response =
                        format!("grpc-status:{}", status);
                    // 7=PERMISSION_DENIED, 16=UNAUTHENTICATED
                    if status == "16" || status == "7" {
                        result.requires_auth = true;
                        result.auth_type = "grpc-token".to_string();
                    }
                }
            }
        }

        // Parse reflection response for service enumeration
        if result.grpc_detected && !data_buf.is_empty() {
            if let Some(services) = parse_grpc_data_frame(&data_buf) {
                if !services.is_empty() {
                    result.reflection_enabled = true;
                    result.services_count = services.len() as u32;
                    result.services_list = services.join(";");
                }
            }
        }

        Ok(())
    }
}

// ── Protobuf parsing (unchanged from v0.2) ────────────────────────────────────

fn parse_grpc_data_frame(data: &[u8]) -> Option<Vec<String>> {
    if data.len() < 5 {
        return None;
    }
    if data[0] != 0x00 {
        return None; // compressed — skip
    }
    let msg_len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
    if msg_len == 0 || 5 + msg_len > data.len() {
        return None;
    }
    parse_list_services_response(&data[5..5 + msg_len])
}

fn parse_list_services_response(msg: &[u8]) -> Option<Vec<String>> {
    let mut services = Vec::new();
    let mut pos = 0;

    while pos < msg.len() {
        let tag = msg[pos];
        pos += 1;
        let field_number = tag >> 3;
        let wire_type = tag & 0x07;

        match wire_type {
            2 => {
                let (vlen, vbytes) = parse_varint(&msg[pos..])?;
                pos += vbytes;
                let field_len = vlen as usize;
                if pos + field_len > msg.len() {
                    break;
                }
                let field_data = &msg[pos..pos + field_len];
                pos += field_len;
                if field_number == 1 {
                    if let Some(name) = extract_service_name(field_data) {
                        if is_valid_grpc_service_name(&name) {
                            services.push(name);
                        }
                    }
                }
            }
            0 => {
                let (_, vbytes) = parse_varint(&msg[pos..]).unwrap_or((0, 1));
                pos += vbytes;
            }
            1 => {
                pos += 8;
            }
            5 => {
                pos += 4;
            }
            _ => break,
        }
    }

    if services.is_empty() {
        None
    } else {
        Some(services)
    }
}

fn extract_service_name(data: &[u8]) -> Option<String> {
    let mut pos = 0;
    while pos < data.len() {
        let tag = data[pos];
        pos += 1;
        let field_number = tag >> 3;
        let wire_type = tag & 0x07;
        match wire_type {
            2 => {
                let (vlen, vbytes) = parse_varint(&data[pos..])?;
                pos += vbytes;
                let len = vlen as usize;
                if pos + len > data.len() {
                    break;
                }
                if field_number == 1 {
                    return std::str::from_utf8(&data[pos..pos + len])
                        .ok()
                        .map(|s| s.to_string());
                }
                pos += len;
            }
            _ => break,
        }
    }
    None
}

fn parse_varint(data: &[u8]) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    for (i, &byte) in data.iter().enumerate() {
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    None
}

fn is_valid_grpc_service_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 128 {
        return false;
    }
    if !name.contains('.') || name.starts_with('.') || name.ends_with('.') {
        return false;
    }
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() < 2 || parts.len() > 8 {
        return false;
    }
    for part in &parts {
        if part.is_empty() {
            return false;
        }
        if !part.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return false;
        }
    }
    match parts[0].chars().next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    if parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit())) {
        return false;
    }
    true
}
