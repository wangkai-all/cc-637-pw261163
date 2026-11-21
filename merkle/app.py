#!/usr/bin/env python3
"""Entry point: python -m merkle.app --data ./data --port 8000"""
from __future__ import annotations

import argparse
import sys

from .server import create_server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Merkle snapshot diff web tool")
    parser.add_argument("--data", default="./data",
                        help="persistent data directory (default ./data)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    httpd = create_server(args.data, args.host, args.port)
    print(f"Merkle diff tool on http://{args.host}:{args.port}  (data: {args.data})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
