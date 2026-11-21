"""Snapshot builder: parse input, build the fixed-shape Merkle tree, persist.

The build is a bottom-up, journaled pipeline:

1. parse the source file and reject duplicate primary keys before any tree
   work starts;
2. write 256 leaf buckets (row block + verified leaf envelope each);
3. write 16 level-1 internal nodes from completed leaves;
4. compute and publish the root only after every child exists and verifies;
5. atomically publish the manifest.

If the process exits at any point, restarting ``build_snapshot`` re-reads the
journal, skips nodes already verified on disk and continues from the next
node -- the root is never published until all 273 child nodes are complete.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
from decimal import Decimal
from typing import Any

from . import canonical
from .canonical import CanonicalError, DuplicateKeyError
from .store import (BUCKET_COUNT, L1_COUNT, L1_FANOUT, NODE_ROOT, Store,
                    internal_envelope, l1_children, l1_id, leaf_envelope,
                    leaf_id, root_children, root_envelope, schema_hash,
                    dumps_json, loads_json)

TOTAL_NODES = BUCKET_COUNT + L1_COUNT + 1  # 256 + 16 + 1 = 273


class BuildInterrupted(Exception):
    """Test hook: the simulated crash budget was exhausted mid-build."""

    def __init__(self, after_nodes: int):
        self.after_nodes = after_nodes
        super().__init__(f"build interrupted after {after_nodes} verified nodes")


# --- input parsing -------------------------------------------------------
def _decode_rows(payload: bytes, fmt: str) -> tuple[list[dict], list[str]]:
    if fmt == "json":
        # Use the store codec so __decimal__ markers produced by dumps_json
        # round-trip back to Decimal instead of leaking through as dicts.
        data = loads_json(payload.decode("utf-8"))
        if isinstance(data, dict) and "rows" in data:
            rows = data["rows"]
            outer_fields = data.get("fields")
        else:
            rows, outer_fields = data, None
        if not isinstance(rows, list):
            raise CanonicalError("JSON input must be a list of row objects")
        for r in rows:
            if not isinstance(r, dict):
                raise CanonicalError("every JSON row must be an object")
        return rows, list(outer_fields) if outer_fields else []
    if fmt == "csv":
        text = payload.decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(text))
        if reader.fieldnames is None:
            raise CanonicalError("CSV input has no header row")
        rows = [dict(r) for r in reader]
        return rows, [f for f in reader.fieldnames if f is not None]
    raise CanonicalError(f"unsupported input format {fmt!r}")


def _infer_field_names(rows: list[dict], header_fields: list[str]) -> list[str]:
    seen: list[str] = []
    seen_set: set[str] = set()
    for name in header_fields:
        if name not in seen_set:
            seen.append(name)
            seen_set.add(name)
    for row in rows:
        for key in row:
            if key not in seen_set:
                seen.append(key)
                seen_set.add(key)
    if not seen:
        raise CanonicalError("input has no fields")
    return seen


def _infer_types(rows: list[dict], field_names: list[str],
                 declared: dict[str, str] | None) -> dict[str, str]:
    types: dict[str, str] = {}
    for name in field_names:
        if declared and name in declared:
            t = declared[name]
            if t not in canonical.VALID_TYPES:
                raise CanonicalError(f"unknown type {t!r} for field {name!r}")
            types[name] = t
            continue
        found: set[str] = set()
        for row in rows:
            if name not in row or row[name] is None:
                continue
            v = row[name]
            if isinstance(v, bool):
                found.add("boolean")
            elif isinstance(v, int):
                found.add("integer")
            elif isinstance(v, Decimal):
                found.add("integer" if v == v.to_integral_value() else "number")
            elif isinstance(v, str):
                found.add("string")
            else:
                raise CanonicalError(
                    f"cannot infer type of field {name!r}: value {v!r}")
        if not found:
            types[name] = "string"
        elif found <= {"integer"}:
            types[name] = "integer"
        elif found <= {"integer", "number"}:
            types[name] = "number"
        elif found == {"boolean"}:
            types[name] = "boolean"
        elif found == {"string"}:
            types[name] = "string"
        else:
            raise CanonicalError(
                f"field {name!r} mixes incompatible inferred types: "
                f"{sorted(found)}; declare an explicit schema")
    return types


def prepare_schema(rows: list[dict], header_fields: list[str],
                   key_fields: list[str] | None,
                   declared_types: dict[str, str] | None,
                   explicit_field_order: list[str] | None = None
                   ) -> tuple[list[str], dict[str, str], list[str]]:
    if explicit_field_order:
        # A fully declared schema pins field order deterministically; any
        # extra keys seen in the data are appended after it.
        field_names = list(explicit_field_order)
        seen = set(field_names)
        for row in rows:
            for key in row:
                if key not in seen:
                    field_names.append(key)
                    seen.add(key)
    else:
        field_names = _infer_field_names(rows, header_fields)
    types = _infer_types(rows, field_names, declared_types)
    if not key_fields:
        key_fields = ["id"] if "id" in field_names else field_names[:1]
    for kf in key_fields:
        if kf not in field_names:
            raise CanonicalError(f"primary key field {kf!r} is not in the schema")
        if types[kf] == "null":
            raise CanonicalError(f"primary key field {kf!r} cannot be nullable")
    return field_names, types, key_fields


def _canonicalise_rows(rows: list[dict], field_names: list[str],
                       types: dict[str, str], fmt: str) -> list[dict]:
    out: list[dict] = []
    for pos, row in enumerate(rows):
        norm: dict[str, Any] = {}
        for name in field_names:
            if name not in row:
                norm[name] = None
                continue
            raw = row[name]
            if fmt == "csv" and isinstance(raw, str):
                norm[name] = canonical.coerce_csv_cell(raw, types[name])
            else:
                norm[name] = canonical._coerce_typed(raw, types[name]) \
                    if raw is not None else None
        out.append(norm)
    return out


def _check_duplicate_keys(rows: list[dict], key_fields: list[str],
                          types: dict[str, str]) -> None:
    seen: dict[bytes, int] = {}
    dups: list[dict] = []
    for pos, row in enumerate(rows):
        enc = canonical.primary_key_encoding(key_fields, row, types)
        if enc in seen:
            pk_text = dumps_json({k: row[k] for k in key_fields})
            dups.append({"pk_text": pk_text, "first_row": seen[enc],
                         "row": pos})
        else:
            seen[enc] = pos
    if dups:
        raise DuplicateKeyError(dups)


# --- build ---------------------------------------------------------------
def build_snapshot(store: Store, name: str, payload: bytes, fmt: str,
                   key_fields: list[str] | None = None,
                   declared_types: dict[str, str] | None = None,
                   fail_after_nodes: int | None = None,
                   explicit_field_order: list[str] | None = None) -> dict:
    """Build (or resume building) one snapshot.

    ``fail_after_nodes`` is a test hook that simulates a crash once the given
    number of nodes has been verified and journaled.  Nothing is published on
    that path; the next call resumes from the journal.
    """
    if not name or "/" in name or name in (".", ".."):
        raise CanonicalError(f"invalid snapshot name {name!r}")

    lock_path = os.path.join(store.data_dir, f".build-{name}.lock")
    try:
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        raise CanonicalError(f"another build of {name!r} is in progress")
    try:
        return _build_locked(store, name, payload, fmt, key_fields,
                             declared_types, fail_after_nodes,
                             explicit_field_order)
    finally:
        os.close(lock_fd)
        try:
            os.unlink(lock_path)
        except OSError:
            pass


def _build_locked(store: Store, name: str, payload: bytes, fmt: str,
                  key_fields, declared_types, fail_after_nodes,
                  explicit_field_order=None) -> dict:
    os.makedirs(store.nodes_dir(name), exist_ok=True)
    os.makedirs(store.rows_dir(name), exist_ok=True)
    # A journal entry is only trusted when the node envelope it names really
    # exists on disk and verifies; a stale entry from an interrupted final
    # step must not cause us to skip rebuilding that node.
    done: set[str] = set()
    for nid in store.journal_done(name):
        path = store.node_path(name, nid)
        if not os.path.exists(path):
            continue
        try:
            store.load_node(name, nid)
        except Exception:
            continue
        done.add(nid)

    raw_rows, header_fields = _decode_rows(payload, fmt)
    field_names, types, key_fields = prepare_schema(
        raw_rows, header_fields, key_fields, declared_types,
        explicit_field_order=explicit_field_order)
    rows = _canonicalise_rows(raw_rows, field_names, types, fmt)
    _check_duplicate_keys(rows, key_fields, types)

    # Persist the build inputs (schema decisions included) before any tree
    # node is written.  A resumed build reads this sidecar so type inference
    # and field order never drift between the two runs.
    build_spec = {
        "format": fmt,
        "field_names": field_names,
        "types": types,
        "key_fields": key_fields,
        "explicit_field_order": explicit_field_order,
    }
    store.write_json(store.build_spec_path(name), build_spec)
    store.save_source(name, payload)

    # partition rows into the fixed 256 primary-key buckets
    buckets: list[list[tuple[bytes, bytes, dict]]] = [[] for _ in range(BUCKET_COUNT)]
    for row in rows:
        pk = canonical.primary_key_encoding(key_fields, row, types)
        rh = canonical.row_hash(field_names, row, types)
        buckets[canonical.bucket_index(pk)].append((pk, rh, row))
    for bucket in buckets:
        bucket.sort(key=lambda item: item[0])

    sch_hash = schema_hash(field_names, types, key_fields)
    written = 0

    # phase 1: leaves ------------------------------------------------------
    for idx in range(BUCKET_COUNT):
        nid = leaf_id(idx)
        if nid in done:
            store.load_node(name, nid)  # verifies integrity, hash re-read later
            continue
        items = buckets[idx]
        pks = [pk for pk, _, _ in items]
        rhs = [rh for _, rh, _ in items]
        bucket_rows = [row for _, _, row in items]
        store.write_rows(name, idx, bucket_rows, rhs)
        env = leaf_envelope(idx, pks, rhs)
        store.write_node(name, nid, env)
        store.journal_append(name, "DONE", nid)
        done.add(nid)
        written += 1
        if fail_after_nodes is not None and written >= fail_after_nodes:
            raise BuildInterrupted(written)

    # phase 2: level-1 internal nodes -------------------------------------
    # Child hashes are always re-read from the verified on-disk leaf
    # envelopes, so an L1 node can never combine stale in-memory hashes with
    # journaled leaves after a resumed build.
    for idx in range(L1_COUNT):
        nid = l1_id(idx)
        children = l1_children(idx)
        if nid in done:
            store.load_node(name, nid)  # verifies integrity
            continue
        child_hashes = []
        for j in range(L1_FANOUT):
            leaf_idx = idx * L1_FANOUT + j
            leaf_env = store.load_node(name, leaf_id(leaf_idx))
            child_hashes.append(bytes.fromhex(leaf_env["hash"]))
        env = internal_envelope(1, idx, children, child_hashes)
        store.write_node(name, nid, env)
        store.journal_append(name, "DONE", nid)
        done.add(nid)
        written += 1
        if fail_after_nodes is not None and written >= fail_after_nodes:
            raise BuildInterrupted(written)

    # phase 3: root, only when every child is complete --------------------
    root_children_ids = root_children()
    missing = [nid for nid in root_children_ids if nid not in done]
    if missing:
        raise BuildInterrupted(0)
    if NODE_ROOT not in done:
        # same disk-derived discipline as phase 2
        child_hashes = [
            bytes.fromhex(store.load_node(name, l1_id(i))["hash"])
            for i in range(L1_COUNT)]
        root_env = root_envelope(2, root_children_ids, child_hashes,
                                 sch_hash, len(rows))
        store.write_node(name, NODE_ROOT, root_env)
        store.journal_append(name, "DONE", NODE_ROOT)
        done.add(NODE_ROOT)
        written += 1
        if fail_after_nodes is not None and written >= fail_after_nodes:
            raise BuildInterrupted(written)

    # Always re-read the verified root envelope from disk for the manifest;
    # on a resumed build the local root variable may never have been assigned.
    final_root_env = store.load_node(name, NODE_ROOT)
    manifest = {
        "name": name,
        "format": fmt,
        "field_names": field_names,
        "types": types,
        "key_fields": key_fields,
        "record_count": len(rows),
        "schema_hash": sch_hash.hex(),
        "root_hash": final_root_env["hash"],
        "source_sha256": hashlib.sha256(payload).hexdigest(),
        "tree_levels": 3,
        "bucket_count": BUCKET_COUNT,
        "total_nodes": TOTAL_NODES,
    }
    store.publish_manifest(name, manifest)
    manifest["nodes_written_this_run"] = written
    return manifest


def resume_snapshot(store: Store, name: str,
                    fail_after_nodes: int | None = None) -> dict:
    """Resume a previously interrupted build from its stored source file."""
    path = store.source_path(name)
    if not os.path.exists(path):
        raise CanonicalError(
            f"cannot resume {name!r}: source file was never persisted")
    spec_path = store.build_spec_path(name)
    if not os.path.exists(spec_path):
        raise CanonicalError(
            f"cannot resume {name!r}: build specification sidecar is missing")
    spec = store.read_json(spec_path)
    with open(path, "rb") as fh:
        payload = fh.read()
    return build_snapshot(
        store, name, payload, spec["format"],
        key_fields=spec["key_fields"],
        declared_types=spec["types"],
        fail_after_nodes=fail_after_nodes,
        explicit_field_order=spec.get("explicit_field_order"))
