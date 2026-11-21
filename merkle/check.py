"""Whole-snapshot integrity checks and controlled corruption injection.

The check walks every stored node (not just the root) and reports the smallest
affected scope, so a corrupted bucket shows up as one bucket instead of
"the whole table changed".  Corruption injection is the test/demo hook used
to prove the scoping behaviour on the web page.
"""
from __future__ import annotations

import hashlib
import json
import os

from . import canonical
from .builder import _canonicalise_rows, _decode_rows
from .store import (BUCKET_COUNT, CorruptionError, Store, leaf_id, l1_id,
                    NODE_ROOT)


def check_snapshot(store: Store, name: str) -> dict:
    report = {
        "snapshot": name, "complete": store.is_complete(name),
        "ok": True, "issues": [], "nodes_verified": 0,
        "rows_verified": 0, "affected_scopes": [],
    }
    if not store.exists(name):
        report["ok"] = False
        report["issues"].append("snapshot does not exist")
        return report

    # 1. node envelopes (hash of payload re-derived for every node)
    envelope_hash: dict[str, str] = {}
    for idx in range(BUCKET_COUNT):
        nid = leaf_id(idx)
        try:
            env = store.load_node(name, nid)
            envelope_hash[nid] = env["hash"]
            report["nodes_verified"] += 1
        except CorruptionError as exc:
            report["ok"] = False
            report["issues"].append(str(exc))
            report["affected_scopes"].extend(exc.scope)
    for idx in range(16):
        nid = l1_id(idx)
        try:
            env = store.load_node(name, nid)
            envelope_hash[nid] = env["hash"]
            report["nodes_verified"] += 1
        except CorruptionError as exc:
            report["ok"] = False
            report["issues"].append(str(exc))
            report["affected_scopes"].extend(exc.scope)
    try:
        env = store.load_node(name, NODE_ROOT)
        envelope_hash[NODE_ROOT] = env["hash"]
        report["nodes_verified"] += 1
    except CorruptionError as exc:
        report["ok"] = False
        report["issues"].append(str(exc))
        report["affected_scopes"].extend(exc.scope)

    # 2. parent/child linkage: stored child hashes must equal child envelopes
    for idx in range(16):
        nid = l1_id(idx)
        if nid not in envelope_hash:
            continue
        env = store.read_json(store.node_path(name, nid))
        for cid, ch_hex in zip(env["children"], env["child_hashes"]):
            if cid in envelope_hash and envelope_hash[cid] != ch_hex:
                report["ok"] = False
                report["issues"].append(
                    f"internal node {nid} references stale hash of child {cid}")
                report["affected_scopes"].append(nid)
    if NODE_ROOT in envelope_hash:
        env = store.read_json(store.node_path(name, NODE_ROOT))
        for cid, ch_hex in zip(env["children"], env["child_hashes"]):
            if cid in envelope_hash and envelope_hash[cid] != ch_hex:
                report["ok"] = False
                report["issues"].append(
                    f"root references stale hash of child {cid}")
                report["affected_scopes"].append(NODE_ROOT)

    # 3. row blocks: existence, per-row re-hash, and leaf-envelope agreement
    for idx in range(BUCKET_COUNT):
        nid = leaf_id(idx)
        node_path = store.node_path(name, nid)
        if not os.path.exists(node_path):
            continue
        try:
            leaf_env = store.read_json(node_path)
            rows, block_hashes = store.load_rows(name, idx)
        except CorruptionError as exc:
            report["ok"] = False
            report["issues"].append(str(exc))
            report["affected_scopes"].extend(exc.scope)
            continue
        if [h.hex() for h in block_hashes] != leaf_env["row_hashes"]:
            report["ok"] = False
            report["issues"].append(
                f"row block of {nid} disagrees with leaf envelope hashes")
            report["affected_scopes"].append(nid)
            continue
        # Recompute every row hash from the stored row content.  This catches
        # a tampered row whose block hash entry was left stale (or copied) --
        # comparing block vs envelope alone would miss it.
        manifest = store.read_manifest(name)
        bad_row = False
        for row, stored in zip(rows, block_hashes):
            if canonical.row_hash(manifest["field_names"], row,
                                  manifest["types"]) != stored:
                report["ok"] = False
                report["issues"].append(
                    f"row content hash mismatch inside {nid}")
                report["affected_scopes"].append(nid)
                bad_row = True
                break
        if not bad_row:
            report["rows_verified"] += len(rows)

    # 4. original source file and end-to-end re-derivation
    if store.is_complete(name):
        manifest = store.read_manifest(name)
        if manifest["root_hash"] != envelope_hash.get(NODE_ROOT):
            report["ok"] = False
            report["issues"].append(
                "manifest root hash disagrees with stored root node")
            report["affected_scopes"].append(NODE_ROOT)
        try:
            with open(store.source_path(name), "rb") as fh:
                payload = fh.read()
            actual = hashlib.sha256(payload).hexdigest()
            if manifest.get("source_sha256") != actual:
                report["ok"] = False
                report["issues"].append(
                    "original source file was modified after tree build")
                report["affected_scopes"].append("source")
            else:
                raw_rows, header = _decode_rows(payload, manifest["format"])
                rows = _canonicalise_rows(raw_rows, manifest["field_names"],
                                          manifest["types"], manifest["format"])
                source_hashes = {}
                for row in rows:
                    pk = canonical.primary_key_encoding(
                        manifest["key_fields"], row, manifest["types"])
                    source_hashes[pk] = canonical.row_hash(
                        manifest["field_names"], row, manifest["types"])
                for idx in range(BUCKET_COUNT):
                    leaf_env = store.read_json(store.node_path(
                        name, leaf_id(idx)))
                    for pk_hex, rh_hex in zip(leaf_env["pks"],
                                              leaf_env["row_hashes"]):
                        pk = bytes.fromhex(pk_hex)
                        if source_hashes.get(pk) != bytes.fromhex(rh_hex):
                            report["ok"] = False
                            report["issues"].append(
                                f"stored row hash in {leaf_id(idx)} does not "
                                "match re-parsed source")
                            report["affected_scopes"].append(leaf_id(idx))
        except FileNotFoundError:
            report["ok"] = False
            report["issues"].append("original source file is missing")
            report["affected_scopes"].append("source")
        except Exception as exc:
            report["ok"] = False
            report["issues"].append(f"source re-parse failed: {exc}")
            report["affected_scopes"].append("source")
    else:
        report["issues"].append(
            "snapshot is incomplete (build interrupted); resume the build "
            "before it can be used in diffs")
        done = store.journal_done(name)
        report["journal_nodes_done"] = len(done)

    report["affected_scopes"] = sorted(set(report["affected_scopes"]))
    return report


# --- corruption injection (demo/test hook) -------------------------------
def inject_corruption(store: Store, name: str, kind: str,
                      target: str | None = None) -> dict:
    """Tamper with stored bytes on purpose.

    kind:
      ``node``      flip one byte inside a node envelope's hash field
      ``row``       alter one row value inside a bucket's row block
      ``internal``  corrupt a level-1 node's claimed child hash
      ``root``      corrupt the root envelope
      ``source``    alter the persisted original source file
    """
    if kind == "source":
        path = store.source_path(name)
        with open(path, "rb") as fh:
            data = fh.read()
        if not data:
            raise ValueError("empty source file")
        flipped = bytearray(data)
        # flip a byte inside the first row's data area, not the opening bracket
        pos = min(len(flipped) - 1, max(2, len(flipped) // 4))
        flipped[pos] = flipped[pos] ^ 0x01
        store._atomic_write(path, bytes(flipped))
        return {"injected": "source", "path": path}

    if kind == "root":
        path = store.node_path(name, NODE_ROOT)
        env = store.read_json(path)
        raw = bytearray(bytes.fromhex(env["hash"]))
        raw[0] ^= 0x01
        env["hash"] = raw.hex()
        store.write_json(path, env)
        return {"injected": "node", "node": NODE_ROOT, "path": path}

    if kind == "internal":
        nid = target or l1_id(0)
        path = store.node_path(name, nid)
        env = store.read_json(path)
        raw = bytearray(bytes.fromhex(env["child_hashes"][0]))
        raw[0] ^= 0x01
        env["child_hashes"][0] = raw.hex()
        store.write_json(path, env)
        return {"injected": "node", "node": nid, "path": path}

    if kind == "node":
        nid = target or leaf_id(0)
        path = store.node_path(name, nid)
        env = store.read_json(path)
        raw = bytearray(bytes.fromhex(env["hash"]))
        raw[0] ^= 0x01
        env["hash"] = raw.hex()
        store.write_json(path, env)
        return {"injected": "node", "node": nid, "path": path}

    if kind == "row":
        bucket = int(target, 16) if target else 0
        path = store.rows_path(name, bucket)
        block = store.read_json(path)
        if not block["rows"]:
            raise ValueError(f"bucket {leaf_id(bucket)} is empty; nothing to corrupt")
        row = block["rows"][0]
        # mutate the first non-key string/number field deterministically
        for fname, value in list(row.items()):
            if value is None:
                row[fname] = ""
                break
            if isinstance(value, str):
                row[fname] = value + "!"
                break
            if isinstance(value, bool):
                row[fname] = not value
                break
            if isinstance(value, int):
                row[fname] = value + 1
                break
            from decimal import Decimal
            if isinstance(value, Decimal):
                row[fname] = value + Decimal("0.01")
                break
        store.write_json(path, block)
        return {"injected": "row", "node": leaf_id(bucket), "path": path}

    raise ValueError(f"unknown corruption kind {kind!r}")
