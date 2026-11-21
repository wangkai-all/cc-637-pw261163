#!/usr/bin/env bash
# Convenience launcher for the Merkle snapshot diff web tool.
set -euo pipefail
cd "$(dirname "$0")"
exec python3 -m merkle.app --data "${DATA_DIR:-./data}" --host 127.0.0.1 --port "${PORT:-8000}"
