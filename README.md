# grpc-probe

Internet-wide gRPC security scanner with HPACK-aware detection.

Companion code for:
> Biplab Kumar Das. "HPACK Huffman Encoding Causes an 89× Undercount in Internet-Wide gRPC Detection." *IEEE Networking Letters*, submitted September 2026.

## The Problem

Naive gRPC scanners search for `grpc-status` or `application/grpc` as raw ASCII bytes in HTTP/2 traffic. This misses every server using HPACK Huffman encoding — the **default** in every major HTTP/2 implementation. The result: a **89× undercount**.

```rust
// v0.2 — misses Huffman-encoded headers (wrong)
data.windows(11).any(|w| w == b"grpc-status")

// v0.3 — decodes HPACK before inspecting (correct)
response.headers().get("grpc-status")
```

## Results (Tranco top-100K, September 2026)

| Metric | Count |
|--------|-------|
| Domains scanned | 100,000 |
| Total probes (4 ports) | 400,000 |
| gRPC endpoint-port combinations | **620** |
| Unique domains with gRPC | **606 (0.61%)** |
| Reflection enabled | **0** |
| Naive byte-scan would detect | 7 |
| Improvement | **89×** |

Port breakdown: 443 (570), 50051 (31), 8080 (11), 9090 (8).

## Requirements

- Rust 1.75+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)

## Quick Start

```bash
git clone https://github.com/biplabku/grpc-probe.git
cd grpc-probe

# Run full scan (100K domains, ~5 hours on residential broadband)
bash run_scan.sh

# Results saved to data/grpc_v3_YYYYMMDD.csv
```

The script builds the binary, then scans `data/tranco_100k.txt` across ports 443, 50051, 8080, and 9090 with 150 concurrent workers and an 8-second timeout. Supports `--resume` if interrupted.

## Manual Usage

```bash
cd src
cargo build --release

./target/release/grpc-probe \
  --input ../data/tranco_100k.txt \
  --output results.csv \
  --workers 150 \
  --timeout 8 \
  --ports "443,50051,8080,9090"
```

## Output Format

CSV with columns: `domain, port, tcp_ok, tls_version, cipher, cert_issuer, h2_ok, grpc_detected, content_type, reflection_enabled, grpc_status, signal, tls_used`

## How Detection Works

1. DNS resolve (Cloudflare 1.1.1.1, AAAA first)
2. TCP connect (8s timeout)
3. TLS handshake with ALPN `h2` (permissive cert verification for coverage)
4. HTTP/2 via the [`h2`](https://crates.io/crates/h2) Rust crate — decodes HPACK automatically
5. Send `ListServices` ServerReflection probe
6. Inspect **decoded** `content-type` or `grpc-status` trailer

For non-443 ports, cleartext h2c is tried first; TLS on failure.

Both detection signals (`content-type: application/grpc` and `grpc-status` trailer) are defined exclusively in the [gRPC specification](https://grpc.io/docs/what-is-grpc/) and cannot be emitted by non-gRPC HTTP/2 servers.

## License

MIT

## Author

Biplab Kumar Das — [dasbiplabtu@gmail.com](mailto:dasbiplabtu@gmail.com)
