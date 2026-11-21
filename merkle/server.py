"""HTTP API + static file serving for the Merkle diff tool (stdlib only)."""
from __future__ import annotations

import json
import os
import re
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import check as check_mod
from .builder import BuildInterrupted, build_snapshot, resume_snapshot
from .canonical import CanonicalError, DuplicateKeyError
from .differ import diff_snapshots
from .store import (CorruptionError, Store, dumps_api_json, dumps_json,
                    loads_json)
from .sync import (SyncRejected, SyncVerificationFailed, apply_sync_package,
                   create_sync_package)

MAX_UPLOAD = 50 * 1024 * 1024
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "..", "web")


class MerkleHandler(BaseHTTPRequestHandler):
    store: Store = None  # type: ignore[assignment]

    # --- helpers ----------------------------------------------------------
    def _send(self, status: int, obj) -> None:
        body = dumps_api_json(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_UPLOAD:
            raise CanonicalError("upload too large (50MB limit)")
        return self.rfile.read(length)

    def _json_body(self) -> dict:
        raw = self._read_body()
        try:
            return loads_json(raw)
        except Exception as exc:
            raise CanonicalError(f"invalid JSON body: {exc}")

    def log_message(self, fmt, *args):  # quieter console
        pass

    # --- routing ----------------------------------------------------------
    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        path, query = parsed.path, parse_qs(parsed.query)
        try:
            if path == "/api/snapshots":
                return self._send(HTTPStatus.OK,
                                  self.store.list_snapshots())
            if path == "/api/diff":
                return self._handle_diff(query)
            if path == "/api/check":
                return self._handle_check(query)
            if path == "/api/diff/download":
                return self._handle_download(query)
            if path == "/api/sync/package":
                return self._handle_sync_package(query)
            return self._serve_static(path)
        except CorruptionError as exc:
            return self._send(HTTPStatus.CONFLICT,
                              {"error": str(exc), "scope": exc.scope})
        except CanonicalError as exc:
            return self._send(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except FileNotFoundError as exc:
            return self._send(HTTPStatus.NOT_FOUND, {"error": str(exc)})

    def do_POST(self):  # noqa: N802
        path = urlparse(self.path).path
        try:
            if path == "/api/build":
                return self._handle_build()
            if path == "/api/resume":
                return self._handle_resume()
            if path == "/api/corrupt":
                return self._handle_corrupt()
            if path == "/api/sync/apply":
                return self._handle_sync_apply()
            return self._send(HTTPStatus.NOT_FOUND,
                              {"error": f"no POST route {path}"})
        except DuplicateKeyError as exc:
            return self._send(HTTPStatus.CONFLICT,
                              {"error": str(exc),
                               "duplicates": exc.duplicates})
        except BuildInterrupted as exc:
            return self._send(HTTPStatus.ACCEPTED, {
                "interrupted": True,
                "nodes_completed": exc.after_nodes,
                "message": str(exc)})
        except SyncRejected as exc:
            return self._send(HTTPStatus.CONFLICT,
                              {"error": str(exc), "rejected": True})
        except SyncVerificationFailed as exc:
            return self._send(HTTPStatus.EXPECTATION_FAILED,
                              {"error": str(exc), "verification_failed": True})
        except CorruptionError as exc:
            return self._send(HTTPStatus.CONFLICT,
                              {"error": str(exc), "scope": exc.scope})
        except CanonicalError as exc:
            return self._send(HTTPStatus.BAD_REQUEST, {"error": str(exc)})

    # --- GET handlers -----------------------------------------------------
    def _handle_diff(self, query):
        base = query.get("base", [""])[0]
        target = query.get("target", [""])[0]
        if not base or not target:
            raise CanonicalError("both base and target are required")
        return self._send(HTTPStatus.OK, diff_snapshots(self.store, base, target))

    def _handle_check(self, query):
        name = query.get("name", [""])[0]
        if not name:
            raise CanonicalError("name is required")
        return self._send(HTTPStatus.OK,
                          check_mod.check_snapshot(self.store, name))

    def _handle_download(self, query):
        base = query.get("base", [""])[0]
        target = query.get("target", [""])[0]
        result = diff_snapshots(self.store, base, target)
        body = dumps_api_json({
            "base": result["base"], "target": result["target"],
            "base_root": result["base_root"],
            "target_root": result["target_root"],
            "verified": result["verified"],
            "full_scan": result["full_scan"],
            "tree_walk_measured": result["tree_walk"],
            "counts": result["counts"],
            "changes": result["changes"],
            "corruptions": result["corruptions"],
        }).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Disposition",
                         f'attachment; filename="diff-{base}-vs-{target}.json"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_sync_package(self, query):
        base = query.get("base", [""])[0]
        target = query.get("target", [""])[0]
        diff = diff_snapshots(self.store, base, target)
        package = create_sync_package(self.store, base, target, diff)
        body = dumps_json(package).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Disposition",
                         f'attachment; filename="sync-{base}-to-{target}.json"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # --- POST handlers ----------------------------------------------------
    def _handle_build(self):
        body = self._json_body()
        name = body.get("name", "")
        content_b64 = body.get("content", "")
        import base64
        try:
            payload = base64.b64decode(content_b64, validate=True)
        except Exception as exc:
            raise CanonicalError(f"invalid base64 content: {exc}")
        fmt = body.get("format", "json")
        if fmt not in ("json", "csv"):
            raise CanonicalError("format must be json or csv")
        if self.store.exists(name):
            raise CanonicalError(f"snapshot {name!r} already exists")
        fail_after = body.get("fail_after_nodes")
        manifest = build_snapshot(
            self.store, name, payload, fmt,
            key_fields=body.get("key_fields") or None,
            declared_types=body.get("types") or None,
            fail_after_nodes=fail_after)
        return self._send(HTTPStatus.CREATED, manifest)

    def _handle_resume(self):
        body = self._json_body()
        name = body.get("name", "")
        fail_after = body.get("fail_after_nodes")
        manifest = resume_snapshot(self.store, name,
                                   fail_after_nodes=fail_after)
        return self._send(HTTPStatus.OK, manifest)

    def _handle_corrupt(self):
        body = self._json_body()
        result = check_mod.inject_corruption(
            self.store, body["name"], body["kind"], body.get("target"))
        return self._send(HTTPStatus.OK, result)

    def _handle_sync_apply(self):
        body = self._json_body()
        result = apply_sync_package(
            self.store, body["receiver"], body["package"],
            body["new_snapshot"])
        return self._send(HTTPStatus.CREATED, result)

    # --- static files -----------------------------------------------------
    def _serve_static(self, path: str):
        if path == "/":
            path = "/index.html"
        safe = os.path.normpath(path).lstrip("/")
        full = os.path.normpath(os.path.join(STATIC_DIR, safe))
        if not full.startswith(os.path.normpath(STATIC_DIR)) or \
                not os.path.isfile(full):
            return self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
        ext = os.path.splitext(full)[1]
        ctype = {".html": "text/html; charset=utf-8",
                 ".js": "application/javascript; charset=utf-8",
                 ".css": "text/css; charset=utf-8"}.get(ext, "application/octet-stream")
        with open(full, "rb") as fh:
            data = fh.read()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def create_server(data_dir: str, host: str = "127.0.0.1",
                  port: int = 8000) -> ThreadingHTTPServer:
    store = Store(data_dir)
    MerkleHandler.store = store
    httpd = ThreadingHTTPServer((host, port), MerkleHandler)
    return httpd
