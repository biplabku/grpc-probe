#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"
DATA_DIR="$SCRIPT_DIR/data"
DATE=$(date +%Y%m%d)
DOMAINS_FILE="$DATA_DIR/tranco_100k.txt"
OUTPUT="$DATA_DIR/grpc_v3_${DATE}.csv"

echo "╔══════════════════════════════════════════════════════════╗"
echo "║     gRPC Security Census - v0.3 (HPACK fix)             ║"
echo "║     Fix: uses h2 crate, catches Huffman-encoded headers  ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo

# ── Prereq check ─────────────────────────────────────────────────
if ! command -v cargo &>/dev/null; then
    echo "ERROR: Rust/Cargo not found."
    echo "Install from: https://rustup.rs"
    echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi
echo "Rust: $(rustc --version)"
echo "Cargo: $(cargo --version)"
echo

# ── Build ────────────────────────────────────────────────────────
echo "[1/2] Building grpc-probe v0.3..."
cd "$SRC_DIR"
cargo build --release 2>&1 | grep -E "^(error|warning\[|Compiling grpc|Finished)" || true

BINARY="$SRC_DIR/target/release/grpc-probe"
if [ ! -f "$BINARY" ]; then
    echo "ERROR: Build failed. Run 'cargo build --release' in $SRC_DIR for details."
    exit 1
fi
echo "Build OK → $BINARY"
echo

# ── Scan ─────────────────────────────────────────────────────────
DOMAIN_COUNT=$(wc -l < "$DOMAINS_FILE" | tr -d ' ')
echo "[2/2] Scanning $DOMAIN_COUNT domains on ports 443,50051,8080,9090"

RESUME_FLAG=""
if [ -f "$OUTPUT" ]; then
    DONE=$(tail -n +2 "$OUTPUT" 2>/dev/null | wc -l | tr -d ' ')
    echo "      Resuming — $DONE rows already done."
    RESUME_FLAG="--resume"
else
    echo "      Output → $OUTPUT"
fi
echo "      Workers: 150 | Timeout: 8s"
echo

"$BINARY" \
    --input "$DOMAINS_FILE" \
    --output "$OUTPUT" \
    --workers 150 \
    --timeout 8 \
    --ports "443,50051,8080,9090" \
    $RESUME_FLAG

echo
echo "══════════════════════════════════════════════════════════"

TOTAL=$(tail -n +2 "$OUTPUT" 2>/dev/null | wc -l | tr -d ' ')
FOUND=$(awk -F',' 'NR>1 && $8=="true"' "$OUTPUT" 2>/dev/null | wc -l | tr -d ' ')
REFL=$(awk -F',' 'NR>1 && $10=="true"' "$OUTPUT" 2>/dev/null | wc -l | tr -d ' ')

echo "Total scans:     $TOTAL"
echo "gRPC endpoints:  $FOUND"
echo "Reflection on:   $REFL"

if [ "$FOUND" -gt 0 ]; then
    echo
    echo "Confirmed gRPC endpoints:"
    awk -F',' 'NR>1 && $8=="true" {
        printf "  %-42s port:%-6s tls:%-6s refl:%s\n", $1, $2, $13, $10
    }' "$OUTPUT" | head -100
fi

echo
echo "Results saved: $OUTPUT"
