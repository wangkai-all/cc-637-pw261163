"""Merkle-guided diff engine with measured IO and row-level verification.

Two kinds of counters are kept strictly separate and both are *measured*
values, never estimates:

* ``tree_walk`` -- node envelopes actually opened and row records actually
  read while pruning the Merkle trees top-down;
* ``full_scan`` -- every row re-parsed from the original source files and
  compared row by row to independently verify the Merkle-derived answer.

Identical subtrees are skipped without touching their children.  A node or
row block that fails hash verification is reported with its smallest affected
scope (typically one bucket) instead of declaring the whole table changed.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from . import canonical
from .builder import _canonicalise_rows, _decode_rows
from .store import (BUCKET_COUNT, NODE_ROOT,
                    CorruptionError, Store, leaf_id, l1_id)


@dataclass
class Counters:
    nodes_loaded: int = 0          # node envelopes really opened from disk
    rows_loaded: int = 0           # row records really read from row blocks
    subtrees_skipped_equal: int = 0
    subtrees_descended: int = 0
    corrupt_nodes: int = 0

    def as_dict(self) -> dict:
        return {
            "nodes_loaded": self.nodes_loaded,
            "rows_loaded": self.rows_loaded,
            "subtrees_skipped_equal": self.subtrees_skipped_equal,
            "subtrees_descended": self.subtrees_descended,
            "corrupt_nodes": self.corrupt_nodes,
        }


@dataclass
class FullScan:
    base_rows_read: int = 0
    target_rows_read: int = 0
    inserted: int = 0
    deleted: int = 0
    modified: int = 0
    verified: bool = False
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "base_rows_read": self.base_rows_read,
            "target_rows_read": self.target_rows_read,
            "inserted": self.inserted,
            "deleted": self.deleted,
            "modified": self.modified,
            "verified": self.verified,
            "errors": self.errors,
        }


class _DecimalNumber:
    """Wrapper that serialises a Decimal as a bare JSON number token."""
    __slots__ = ("text",)

    def __init__(self, text: str):
        self.text = text


def jsonable(value: Any) -> Any:
    """Convert internal canonical values into JSON-safe output values.

    Decimals are wrapped in ``_DecimalNumber``; the API serialiser
    (:func:`merkle.store.dumps_api_json`) emits them as bare JSON numbers.
    """
    if isinstance(value, Decimal):
        return _DecimalNumber(canonical.canonical_decimal(value))
    if isinstance(value, dict):
        return {k: jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [jsonable(v) for v in value]
    return value


def _pk_object(row: dict, key_fields: list[str]) -> dict:
    return {k: jsonable(row[k]) for k in key_fields}


class Differ:
    def __init__(self, store: Store):
        self.store = store
        self.walk = Counters()
        self.corruptions: list[dict] = []
        self.changes: list[dict] = []
        self._manifest_cache: dict[str, dict] = {}

    def _manifest(self, snapshot: str) -> dict:
        if snapshot not in self._manifest_cache:
            self._manifest_cache[snapshot] = self.store.read_manifest(snapshot)
        return self._manifest_cache[snapshot]

    # --- safe IO wrappers -------------------------------------------------
    def _load_node(self, snapshot: str, node_id: str) -> dict | None:
        try:
            env = self.store.load_node(snapshot, node_id)
            self.walk.nodes_loaded += 1
            return env
        except CorruptionError as exc:
            self.walk.corrupt_nodes += 1
            self.corruptions.append({
                "snapshot": snapshot, "scope": exc.scope,
                "message": str(exc)})
            return None

    def _load_rows(self, snapshot: str, bucket: int) -> tuple[list[dict], list[bytes]] | None:
        try:
            rows, hashes = self.store.load_rows(snapshot, bucket)
            self.walk.rows_loaded += len(rows)
            return rows, hashes
        except CorruptionError as exc:
            self.walk.corrupt_nodes += 1
            self.corruptions.append({
                "snapshot": snapshot, "scope": exc.scope,
                "message": str(exc)})
            return None

    # --- entry point ------------------------------------------------------
    def diff(self, base_name: str, target_name: str) -> dict:
        base_manifest = self.store.read_manifest(base_name)
        target_manifest = self.store.read_manifest(target_name)
        schema_changed = base_manifest["schema_hash"] != target_manifest["schema_hash"]

        base_root = self._load_node(base_name, NODE_ROOT)
        target_root = self._load_node(target_name, NODE_ROOT)
        if base_root is None or target_root is None:
            return self._result(base_name, target_name, base_manifest,
                                target_manifest, schema_changed, None,
                                complete=False)
        self._check_root_manifest(base_name, base_manifest, base_root)
        self._check_root_manifest(target_name, target_manifest, target_root)

        root_equal = base_root["hash"] == target_root["hash"]
        if root_equal:
            # Whole-table identity: no child node is opened at all.
            self.walk.subtrees_skipped_equal += 1
            tree = self._same_root_stub(base_root)
        else:
            tree = self._walk_level(
                base_name, target_name,
                base_manifest["key_fields"], target_manifest["key_fields"],
                base_root, target_root, level=2)

        complete = not self.corruptions
        result = self._result(base_name, target_name, base_manifest,
                              target_manifest, schema_changed, tree,
                              complete=complete)
        self._full_scan_verify(base_manifest, target_manifest, result)
        return result

    def _check_root_manifest(self, snapshot: str, manifest: dict,
                             root_env: dict) -> None:
        if manifest["root_hash"] != root_env["hash"]:
            self.walk.corrupt_nodes += 1
            self.corruptions.append({
                "snapshot": snapshot, "scope": [NODE_ROOT],
                "message": "manifest root hash disagrees with root node envelope"})

    def _same_root_stub(self, root_env: dict) -> dict:
        return {
            "id": NODE_ROOT, "kind": "root", "status": "same",
            "base_hash": root_env["hash"], "target_hash": root_env["hash"],
            "loaded": True, "children": []}

    # --- recursive tree walk ---------------------------------------------
    def _walk_level(self, base: str, target: str,
                    base_keys: list[str], target_keys: list[str],
                    base_env: dict, target_env: dict, level: int) -> dict:
        node_id = NODE_ROOT if level == 2 else l1_id(base_env["index"])
        node = {
            "id": node_id,
            "kind": "root" if level == 2 else "internal",
            "status": "changed",
            "base_hash": base_env["hash"],
            "target_hash": target_env["hash"],
            "loaded": True,
            "children": [],
        }
        self.walk.subtrees_descended += 1
        base_map = dict(zip(base_env["children"],
                            (bytes.fromhex(h) for h in base_env["child_hashes"])))
        target_map = dict(zip(target_env["children"],
                              (bytes.fromhex(h) for h in target_env["child_hashes"])))
        child_ids = base_env["children"]
        for cid in child_ids:
            bh, th = base_map[cid], target_map[cid]
            if bh == th:
                # The decisive pruning step: identical child hash means the
                # whole subtree is byte-identical; its envelope is not opened.
                self.walk.subtrees_skipped_equal += 1
                node["children"].append({
                    "id": cid,
                    "kind": "internal" if level == 2 else "leaf",
                    "status": "same",
                    "base_hash": bh.hex(), "target_hash": th.hex(),
                    "loaded": False, "children": []})
                continue
            if level == 2:
                b_env = self._load_node(base, cid)
                t_env = self._load_node(target, cid)
                if b_env is None or t_env is None:
                    node["children"].append(self._corrupt_stub(cid, "internal",
                                                                bh, th))
                    continue
                # Cross-check: the loaded child must match the hash the parent
                # recorded.  A mismatch means the parent/child chain itself was
                # tampered with even though each envelope is self-consistent.
                if bytes.fromhex(b_env["hash"]) != bh or \
                        bytes.fromhex(t_env["hash"]) != th:
                    self.walk.corrupt_nodes += 1
                    self.corruptions.append({
                        "snapshot": base if bytes.fromhex(b_env["hash"]) != bh
                        else target,
                        "scope": [cid],
                        "message": f"parent/child hash linkage broken at {cid}"})
                    node["children"].append(self._corrupt_stub(cid, "internal",
                                                                bh, th))
                    continue
                node["children"].append(self._walk_level(
                    base, target, base_keys, target_keys,
                    b_env, t_env, level=1))
            else:
                bucket = int(cid[1:], 16)
                node["children"].append(self._diff_leaf(
                    base, target, bucket, base_keys, target_keys, bh, th))
        return node

    def _corrupt_stub(self, cid: str, kind: str,
                      bh: bytes, th: bytes) -> dict:
        return {
            "id": cid, "kind": kind, "status": "corrupt",
            "base_hash": bh.hex(), "target_hash": th.hex(),
            "loaded": True, "children": [],
            "note": "node failed verification; subtree excluded from diff"}

    def _diff_leaf(self, base: str, target: str, bucket: int,
                   base_keys: list[str], target_keys: list[str],
                   base_claimed: bytes, target_claimed: bytes) -> dict:
        cid = leaf_id(bucket)
        b_env = self._load_node(base, cid)
        t_env = self._load_node(target, cid)
        if b_env is None or t_env is None:
            return self._corrupt_stub(cid, "leaf", base_claimed, target_claimed)

        # Parent/child linkage check at the leaf level too.
        if bytes.fromhex(b_env["hash"]) != base_claimed or \
                bytes.fromhex(t_env["hash"]) != target_claimed:
            self.walk.corrupt_nodes += 1
            bad_snap = base if bytes.fromhex(b_env["hash"]) != base_claimed \
                else target
            self.corruptions.append({
                "snapshot": bad_snap, "scope": [cid],
                "message": f"parent/child hash linkage broken at {cid}"})
            return self._corrupt_stub(cid, "leaf",
                                      base_claimed, target_claimed)

        leaf = {
            "id": cid, "kind": "leaf", "status": "changed",
            "base_hash": b_env["hash"], "target_hash": t_env["hash"],
            "loaded": True, "bucket": bucket,
            "inserted": 0, "deleted": 0, "modified": 0, "children": []}

        b_loaded = self._load_rows(base, bucket)
        t_loaded = self._load_rows(target, bucket)
        if b_loaded is None or t_loaded is None:
            leaf["status"] = "corrupt"
            leaf["note"] = "row block failed verification; bucket excluded"
            return leaf

        b_rows, b_hashes = b_loaded
        t_rows, t_hashes = t_loaded
        # Verify each row record against the hash stored in the row block,
        # and re-check that the block still matches the leaf envelope.
        b_map = self._verified_row_map(base, bucket, b_env, b_rows, b_hashes,
                                       base_keys, leaf)
        t_map = self._verified_row_map(target, bucket, t_env, t_rows, t_hashes,
                                       target_keys, leaf)
        if b_map is None or t_map is None:
            leaf["status"] = "corrupt"
            return leaf
        for pk in sorted(set(b_map) | set(t_map)):
            in_b, in_t = pk in b_map, pk in t_map
            if in_b and not in_t:
                row, rh = b_map[pk]
                leaf["deleted"] += 1
                self.changes.append({
                    "type": "deleted", "bucket": bucket, "pk_hex": pk.hex(),
                    "pk": _pk_object(row, base_keys), "base_hash": rh.hex(),
                    "base": jsonable(row)})
            elif in_t and not in_b:
                row, rh = t_map[pk]
                leaf["inserted"] += 1
                self.changes.append({
                    "type": "inserted", "bucket": bucket, "pk_hex": pk.hex(),
                    "pk": _pk_object(row, target_keys), "target_hash": rh.hex(),
                    "target": jsonable(row)})
            else:
                b_row, b_rh = b_map[pk]
                t_row, t_rh = t_map[pk]
                if b_rh != t_rh:
                    leaf["modified"] += 1
                    self.changes.append({
                        "type": "modified", "bucket": bucket,
                        "pk_hex": pk.hex(),
                        "pk": _pk_object(t_row, target_keys),
                        "base_hash": b_rh.hex(), "target_hash": t_rh.hex(),
                        "base": jsonable(b_row), "target": jsonable(t_row)})
        return leaf

    def _verified_row_map(self, snapshot: str, bucket: int, env: dict,
                          rows: list[dict], stored_hashes: list[bytes],
                          key_fields: list[str], leaf: dict
                          ) -> dict[bytes, tuple[dict, bytes]] | None:
        manifest = self._manifest(snapshot)
        types = manifest["types"]
        field_names = manifest["field_names"]
        out: dict[bytes, tuple[dict, bytes]] = {}
        envelope_hashes = [bytes.fromhex(h) for h in env["row_hashes"]]
        envelope_pks = [bytes.fromhex(p) for p in env["pks"]]
        if stored_hashes != envelope_hashes:
            self.walk.corrupt_nodes += 1
            self.corruptions.append({
                "snapshot": snapshot, "scope": [leaf_id(bucket)],
                "message": "row block hashes disagree with leaf envelope"})
            return None
        try:
            for row, stored in zip(rows, stored_hashes):
                recomputed = canonical.row_hash(field_names, row, types)
                if recomputed != stored:
                    raise CorruptionError("row content hash mismatch",
                                          [leaf_id(bucket)])
                pk = canonical.primary_key_encoding(key_fields, row, types)
                out[pk] = (row, stored)
            if sorted(out.keys()) != envelope_pks:
                raise CorruptionError("leaf pk list disagrees with row block",
                                      [leaf_id(bucket)])
        except CorruptionError as exc:
            self.walk.corrupt_nodes += 1
            self.corruptions.append({
                "snapshot": snapshot, "scope": exc.scope,
                "message": str(exc)})
            return None
        return out

    # --- independent row-by-row verification ------------------------------
    def _full_scan_verify(self, base_manifest: dict, target_manifest: dict,
                          result: dict) -> None:
        scan = FullScan()
        try:
            b_rows = self._scan_source(base_manifest)
            t_rows = self._scan_source(target_manifest)
        except CorruptionError as exc:
            scan.errors.append(str(exc))
            result["full_scan"] = scan.as_dict()
            result["complete"] = False
            return
        scan.base_rows_read = len(b_rows)
        scan.target_rows_read = len(t_rows)

        expected: dict[bytes, str] = {}
        for pk, (row, rh) in b_rows.items():
            expected[pk] = rh.hex()
        naive_changes: list[tuple[str, bytes]] = []
        for pk, (t_row, t_rh) in t_rows.items():
            if pk not in expected:
                scan.inserted += 1
                naive_changes.append(("inserted", pk))
            elif expected[pk] != t_rh.hex():
                scan.modified += 1
                naive_changes.append(("modified", pk))
        for pk in b_rows:
            if pk not in t_rows:
                scan.deleted += 1
                naive_changes.append(("deleted", pk))

        derived = {(c["type"], c["pk_hex"]) for c in self.changes}
        naive = {(kind, pk.hex()) for kind, pk in naive_changes}
        scan.verified = (derived == naive and not self.corruptions)
        if derived != naive:
            only_naive = naive - derived
            only_derived = derived - naive
            scan.errors.append(
                f"row-by-row verification mismatch: "
                f"{len(only_naive)} missing from Merkle result, "
                f"{len(only_derived)} extra in Merkle result")
        # Also verify the stored tree against the freshly parsed source.
        self._verify_tree_against_source(base_manifest, b_rows, scan)
        self._verify_tree_against_source(target_manifest, t_rows, scan)
        if scan.errors:
            scan.verified = False
        result["full_scan"] = scan.as_dict()
        result["verified"] = scan.verified

    def _scan_source(self, manifest: dict) -> dict[bytes, tuple[dict, bytes]]:
        path = self.store.source_path(manifest["name"])
        if not os.path.exists(path):
            raise CorruptionError(
                f"source file of snapshot {manifest['name']!r} is missing",
                [NODE_ROOT])
        with open(path, "rb") as fh:
            payload = fh.read()
        actual_sha = hashlib.sha256(payload).hexdigest()
        if manifest.get("source_sha256") and \
                actual_sha != manifest["source_sha256"]:
            raise CorruptionError(
                f"source file of snapshot {manifest['name']!r} was modified "
                "after the tree was built", [NODE_ROOT])
        raw_rows, header = _decode_rows(payload, manifest["format"])
        rows = _canonicalise_rows(raw_rows, manifest["field_names"],
                                  manifest["types"], manifest["format"])
        out: dict[bytes, tuple[dict, bytes]] = {}
        for row in rows:
            pk = canonical.primary_key_encoding(
                manifest["key_fields"], row, manifest["types"])
            rh = canonical.row_hash(manifest["field_names"], row,
                                    manifest["types"])
            out[pk] = (row, rh)
        return out

    def _verify_tree_against_source(self, manifest: dict,
                                    source_rows: dict[bytes, tuple[dict, bytes]],
                                    scan: FullScan) -> None:
        name = manifest["name"]
        try:
            for idx in range(BUCKET_COUNT):
                env = self.store.load_node(name, leaf_id(idx))
                block_pks = [bytes.fromhex(p) for p in env["pks"]]
                block_hashes = [bytes.fromhex(h) for h in env["row_hashes"]]
                expected_pks = sorted(
                    pk for pk in source_rows
                    if canonical.bucket_index(pk) == idx)
                if block_pks != expected_pks:
                    scan.errors.append(
                        f"{name}: bucket {leaf_id(idx)} pk list does not match source")
                    continue
                for pk, stored_h in zip(block_pks, block_hashes):
                    if source_rows[pk][1] != stored_h:
                        scan.errors.append(
                            f"{name}: row hash mismatch in bucket {leaf_id(idx)}")
        except CorruptionError as exc:
            scan.errors.append(f"{name}: {exc} (scope={','.join(exc.scope)})")

    # --- result assembly --------------------------------------------------
    def _result(self, base: str, target: str,
                base_manifest: dict, target_manifest: dict,
                schema_changed: bool, tree: dict | None,
                complete: bool) -> dict:
        counts = {"inserted": 0, "deleted": 0, "modified": 0}
        for c in self.changes:
            counts[c["type"]] += 1
        return {
            "base": base,
            "target": target,
            "base_root": base_manifest["root_hash"],
            "target_root": target_manifest["root_hash"],
            "root_equal": base_manifest["root_hash"] == target_manifest["root_hash"],
            "schema_changed": schema_changed,
            "complete": complete,
            "verified": False,  # set by full-scan verification
            "counts": counts,
            "changes": self.changes,
            "tree": tree,
            "tree_walk": self.walk.as_dict(),
            "full_scan": None,
            "corruptions": self.corruptions,
            "base_record_count": base_manifest["record_count"],
            "target_record_count": target_manifest["record_count"],
        }


def diff_snapshots(store: Store, base_name: str, target_name: str) -> dict:
    return Differ(store).diff(base_name, target_name)
