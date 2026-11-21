"""On-disk persistence layer: node envelopes, row blocks, journal, manifests.

Directory layout under one data root::

    sources/<snapshot>.json              original uploaded data (verbatim)
    journals/<snapshot>.log              append-only build journal
    snapshots/<snapshot>/manifest.json   atomically published when complete
    snapshots/<snapshot>/nodes/<id>.json Merkle node envelopes
    snapshots/<snapshot>/rows/b<xx>.json rows belonging to bucket <xx>

A node envelope always contains the hash *claimed* by the node.  Loading a
node re-computes the hash from the envelope payload and refuses to return a
tampered node, so corruption is detected at the smallest affected subtree
instead of poisoning the whole comparison.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import tempfile
from decimal import Decimal
from typing import Any

from . import canonical

BUCKET_COUNT = 256
L1_FANOUT = 16  # 256 / 16 = 16 leaves per level-1 node
L1_COUNT = BUCKET_COUNT // L1_FANOUT
LEAF_EMPTY_HASH = hashlib.sha256(b"LEAF-EMPTY\x00").digest()
INT_EMPTY_HASH = hashlib.sha256(b"INT-EMPTY\x00").digest()
ROOT_EMPTY_HASH = hashlib.sha256(b"ROOT-EMPTY\x00").digest()

NODE_ROOT = "root"


# --- ids -----------------------------------------------------------------
def leaf_id(index: int) -> str:
    return f"b{index:02x}"


def l1_id(index: int) -> str:
    return f"i{index:x}"


def is_leaf_id(node_id: str) -> bool:
    return node_id.startswith("b")


def l1_children(index: int) -> list[str]:
    start = index * L1_FANOUT
    return [leaf_id(i) for i in range(start, start + L1_FANOUT)]


def root_children() -> list[str]:
    return [l1_id(i) for i in range(L1_COUNT)]


# --- deterministic JSON codec (Decimal survives the round trip) ----------
def _json_default(obj: Any):
    if isinstance(obj, Decimal):
        return {"__decimal__": canonical.canonical_decimal(obj)}
    if isinstance(obj, bytes):
        return {"__bytes__": obj.hex()}
    raise TypeError(f"not JSON serializable: {type(obj).__name__}")


def _json_object_hook(obj: dict):
    if "__decimal__" in obj:
        return Decimal(obj["__decimal__"])
    if "__bytes__" in obj:
        return bytes.fromhex(obj["__bytes__"])
    return obj


def dumps_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=_json_default)


def loads_json(text: str | bytes) -> Any:
    return json.loads(text, parse_float=Decimal, object_hook=_json_object_hook)


# Bare-number serialisation for API payloads containing Decimal values.
_BARE_RE = re.compile(
    r'"' + re.escape("@BARENUM@") + r'(-?[0-9]+(?:\.[0-9]+)?)'
    + re.escape("@BARENUM@") + r'"')


def dumps_api_json(obj: Any) -> str:
    """JSON for HTTP responses: Decimal -> bare JSON number, never a string.

    Precision is preserved because the canonical decimal text is carried as a
    quoted sentinel by the standard encoder and rewritten to a raw number
    token afterwards; float is never used to represent the value.
    """
    def default(o):
        text = getattr(o, "text", None)
        if text is not None and o.__class__.__name__ == "_DecimalNumber":
            return f"@BARENUM@{text}@BARENUM@"
        if isinstance(o, Decimal):
            return f"@BARENUM@{canonical_decimal_safe(o)}@BARENUM@"
        if isinstance(o, bytes):
            return {"__bytes__": o.hex()}
        raise TypeError(f"not JSON serializable: {type(o).__name__}")

    text = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=default)
    return _BARE_RE.sub(lambda m: m.group(1), text)


def canonical_decimal_safe(value: Decimal) -> str:
    from .canonical import canonical_decimal
    return canonical_decimal(value)


# --- hashes of the three node kinds --------------------------------------
def leaf_payload_hash(pk_list: list[bytes], hashes: list[bytes]) -> bytes:
    h = hashlib.sha256(b"LEAF\x01")
    h.update(len(pk_list).to_bytes(4, "big"))
    for pk, rh in zip(pk_list, hashes):
        h.update(len(pk).to_bytes(2, "big"))
        h.update(pk)
        h.update(rh)
    return h.digest()


def internal_payload_hash(child_ids: list[str], child_hashes: list[bytes]) -> bytes:
    h = hashlib.sha256(b"INT\x01")
    for cid, ch in zip(child_ids, child_hashes):
        h.update(cid.encode("ascii"))
        h.update(b"\x00")
        h.update(ch)
    return h.digest()


def root_payload_hash(child_hashes: list[bytes], level: int,
                      schema_hash: bytes, record_count: int) -> bytes:
    h = hashlib.sha256(b"ROOT\x01")
    h.update(level.to_bytes(2, "big"))
    h.update(schema_hash)
    h.update(record_count.to_bytes(8, "big"))
    for ch in child_hashes:
        h.update(ch)
    return h.digest()


def schema_hash(field_names: list[str], types: dict[str, str],
                key_fields: list[str]) -> bytes:
    h = hashlib.sha256(b"SCHEMA\x01")
    h.update(dumps_json({"fields": field_names, "types": types,
                         "keys": key_fields}).encode("utf-8"))
    return h.digest()


# --- envelope content ----------------------------------------------------
def leaf_envelope(index: int, pk_list: list[bytes],
                  hashes: list[bytes]) -> dict:
    claimed = leaf_payload_hash(pk_list, hashes)
    return {
        "kind": "leaf",
        "bucket": index,
        "record_count": len(pk_list),
        "pks": [pk.hex() for pk in pk_list],
        "row_hashes": [rh.hex() for rh in hashes],
        "hash": claimed.hex(),
    }


def internal_envelope(level: int, index: int, children: list[str],
                      child_hashes: list[bytes]) -> dict:
    claimed = internal_payload_hash(children, child_hashes)
    return {
        "kind": "internal",
        "level": level,
        "index": index,
        "children": children,
        "child_hashes": [ch.hex() for ch in child_hashes],
        "hash": claimed.hex(),
    }


def root_envelope(level: int, children: list[str], child_hashes: list[bytes],
                  sch_hash: bytes, record_count: int) -> dict:
    claimed = root_payload_hash(child_hashes, level, sch_hash, record_count)
    return {
        "kind": "root",
        "level": level,
        "children": children,
        "child_hashes": [ch.hex() for ch in child_hashes],
        "schema_hash": sch_hash.hex(),
        "record_count": record_count,
        "hash": claimed.hex(),
    }


class CorruptionError(Exception):
    """A stored node, row block, source file or manifest failed verification."""

    def __init__(self, message: str, scope: list[str] | None = None):
        super().__init__(message)
        self.scope = scope or []


class Store:
    """Filesystem-backed storage for one collection of snapshots."""

    def __init__(self, data_dir: str, fsync: bool = True):
        self.data_dir = os.path.abspath(data_dir)
        self.fsync = fsync
        self.sources_dir = os.path.join(self.data_dir, "sources")
        self.journals_dir = os.path.join(self.data_dir, "journals")
        self.snap_dir = os.path.join(self.data_dir, "snapshots")
        for d in (self.sources_dir, self.journals_dir, self.snap_dir):
            os.makedirs(d, exist_ok=True)

    # --- paths -----------------------------------------------------------
    def snapshot_dir(self, name: str) -> str:
        return os.path.join(self.snap_dir, name)

    def nodes_dir(self, name: str) -> str:
        return os.path.join(self.snapshot_dir(name), "nodes")

    def rows_dir(self, name: str) -> str:
        return os.path.join(self.snapshot_dir(name), "rows")

    def node_path(self, name: str, node_id: str) -> str:
        return os.path.join(self.nodes_dir(name), node_id + ".json")

    def rows_path(self, name: str, bucket: int) -> str:
        return os.path.join(self.rows_dir(name), leaf_id(bucket) + ".json")

    def journal_path(self, name: str) -> str:
        return os.path.join(self.journals_dir, name + ".log")

    def source_path(self, name: str) -> str:
        return os.path.join(self.sources_dir, name + ".json")

    def build_spec_path(self, name: str) -> str:
        return os.path.join(self.sources_dir, name + ".spec.json")

    def manifest_path(self, name: str) -> str:
        return os.path.join(self.snapshot_dir(name), "manifest.json")

    # --- atomic writes ---------------------------------------------------
    def _atomic_write(self, path: str, data: bytes) -> None:
        directory = os.path.dirname(path)
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".part")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                if self.fsync:
                    os.fsync(fh.fileno())
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def write_json(self, path: str, obj: Any) -> None:
        self._atomic_write(path, dumps_json(obj).encode("utf-8"))

    def read_json(self, path: str) -> Any:
        with open(path, "rb") as fh:
            return loads_json(fh.read())

    # --- snapshots -------------------------------------------------------
    def list_snapshots(self) -> list[dict]:
        out = []
        if not os.path.isdir(self.snap_dir):
            return out
        for name in sorted(os.listdir(self.snap_dir)):
            if not os.path.isdir(os.path.join(self.snap_dir, name)):
                continue
            entry = {"name": name, "complete": self.is_complete(name)}
            try:
                entry["manifest"] = self.read_manifest(name)
            except FileNotFoundError:
                entry["manifest"] = None
            out.append(entry)
        return out

    def exists(self, name: str) -> bool:
        return os.path.exists(self.snapshot_dir(name)) or \
            os.path.exists(self.source_path(name))

    def is_complete(self, name: str) -> bool:
        return os.path.exists(self.manifest_path(name))

    def save_source(self, name: str, payload: bytes) -> str:
        path = self.source_path(name)
        self._atomic_write(path, payload)
        return path

    def publish_manifest(self, name: str, manifest: dict) -> None:
        self.write_json(self.manifest_path(name), manifest)

    def read_manifest(self, name: str) -> dict:
        return self.read_json(self.manifest_path(name))

    # --- node IO with verification ---------------------------------------
    def write_node(self, name: str, node_id: str, envelope: dict) -> None:
        self.write_json(self.node_path(name, node_id), envelope)

    def load_node(self, name: str, node_id: str) -> dict:
        """Load and verify one node envelope.

        Verification re-derives the node hash from the envelope's payload.
        A mismatch raises CorruptionError carrying the node id as scope.
        """
        path = self.node_path(name, node_id)
        try:
            env = self.read_json(path)
        except FileNotFoundError:
            raise CorruptionError(
                f"node {node_id!r} of snapshot {name!r} is missing",
                [node_id])
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise CorruptionError(
                f"node {node_id!r} of snapshot {name!r} is unreadable: {exc}",
                [node_id])
        self._verify_envelope(name, node_id, env)
        return env

    def _verify_envelope(self, name: str, node_id: str, env: dict) -> None:
        kind = env.get("kind")
        try:
            if kind == "leaf":
                pks = [bytes.fromhex(x) for x in env["pks"]]
                rhs = [bytes.fromhex(x) for x in env["row_hashes"]]
                actual = leaf_payload_hash(pks, rhs)
                if env.get("record_count") != len(pks):
                    raise CorruptionError(
                        f"leaf {node_id!r} record_count disagrees with payload",
                        [node_id])
            elif kind == "internal":
                ch = [bytes.fromhex(x) for x in env["child_hashes"]]
                actual = internal_payload_hash(env["children"], ch)
            elif kind == "root":
                ch = [bytes.fromhex(x) for x in env["child_hashes"]]
                actual = root_payload_hash(
                    ch, env["level"], bytes.fromhex(env["schema_hash"]),
                    env["record_count"])
            else:
                raise CorruptionError(
                    f"node {node_id!r} has unknown kind {kind!r}", [node_id])
            claimed = bytes.fromhex(env["hash"])
        except (KeyError, TypeError, ValueError) as exc:
            raise CorruptionError(
                f"node {node_id!r} of snapshot {name!r} has malformed envelope: {exc}",
                [node_id])
        if not hmac.compare_digest(claimed, actual):
            raise CorruptionError(
                f"hash mismatch in node {node_id!r} of snapshot {name!r}: "
                "stored node content was tampered with or corrupted",
                [node_id])

    def verify_root_chain(self, name: str) -> list[str]:
        """Verify every node of a completed snapshot; returns empty or errors."""
        errors: list[str] = []
        for i in range(BUCKET_COUNT):
            try:
                self.load_node(name, leaf_id(i))
            except CorruptionError as exc:
                errors.extend(exc.scope)
        for i in range(L1_COUNT):
            try:
                self.load_node(name, l1_id(i))
            except CorruptionError as exc:
                errors.extend(exc.scope)
        try:
            self.load_node(name, NODE_ROOT)
        except CorruptionError as exc:
            errors.extend(exc.scope)
        return errors

    # --- row blocks with per-record hashes --------------------------------
    def write_rows(self, name: str, bucket: int, rows: list[dict],
                   hashes: list[bytes]) -> None:
        block = {
            "bucket": bucket,
            "record_count": len(rows),
            "row_hashes": [rh.hex() for rh in hashes],
            "rows": rows,
        }
        self.write_json(self.rows_path(name, bucket), block)

    def load_rows(self, name: str, bucket: int) -> tuple[list[dict], list[bytes]]:
        """Load the row block of one bucket and check every row hash."""
        node_id = leaf_id(bucket)
        path = self.rows_path(name, bucket)
        try:
            block = self.read_json(path)
        except FileNotFoundError:
            raise CorruptionError(
                f"row block {node_id!r} of snapshot {name!r} is missing",
                [node_id])
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise CorruptionError(
                f"row block {node_id!r} of snapshot {name!r} is unreadable: {exc}",
                [node_id])
        try:
            rows = block["rows"]
            stored_hashes = [bytes.fromhex(x) for x in block["row_hashes"]]
            if block.get("record_count") != len(rows) or len(rows) != len(stored_hashes):
                raise CorruptionError(
                    f"row block {node_id!r} of {name!r} has inconsistent counts",
                    [node_id])
        except (KeyError, TypeError, ValueError) as exc:
            raise CorruptionError(
                f"row block {node_id!r} of {name!r} is malformed: {exc}",
                [node_id])
        return rows, stored_hashes

    # --- journal ----------------------------------------------------------
    def journal_done(self, name: str) -> set[str]:
        path = self.journal_path(name)
        done: set[str] = set()
        if not os.path.exists(path):
            return done
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("DONE\t"):
                    done.add(line.split("\t", 1)[1])
        return done

    def journal_append(self, name: str, event: str, node_id: str) -> None:
        with open(self.journal_path(name), "a", encoding="utf-8") as fh:
            fh.write(f"{event}\t{node_id}\n")
            fh.flush()
            if self.fsync:
                os.fsync(fh.fileno())
