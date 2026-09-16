#!/usr/bin/env bash
# Run every detector test script against a live gateway.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== flood ==="
bash "$SCRIPT_DIR/flood.sh"
echo
echo "=== sqli ==="
bash "$SCRIPT_DIR/sqli.sh"
echo
echo "=== traversal / enumeration ==="
bash "$SCRIPT_DIR/traversal.sh"
echo
echo "=== brute force ==="
bash "$SCRIPT_DIR/brute_force.sh"
echo
echo "=== object enumeration (BOLA) ==="
bash "$SCRIPT_DIR/object_enumeration.sh"
echo
echo "All signal scripts finished. Detectors log alerts on the gateway; they must not return 429."
