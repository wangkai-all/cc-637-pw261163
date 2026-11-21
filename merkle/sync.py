"""Incremental sync packages with guarded, verifiable application.

A package carries the *base root hash* the receiver must currently hold and
the *target root hash* it must hold afterwards.  Application rules:

1. reject (HTTP 409 at the API layer) when the receiver's root hash or schema
   hash does not match the package baseline -- receiver data is never touched;
2. apply inserts/updates/deletes into a private staging snapshot;
3. build the Merkle tree for the staged result and compare its published root
   with the package's target root;
4. only on a matching root is the snapshot promoted; any failure deletes the
   staging area and leaves the receiver untouched.
"""
from __future__ import annotations

import hashlib
import os
import shutil

from . import canonical
from .builder import build_snapshot
from .store import (BUCKET_COUNT, Store, dumps_json, loads_json, leaf_id)
from decimal import Decimal


def _plain(value):
    """Strip differ._DecimalNumber wrappers; decimals become canonical
    strings inside the package so the payload stays plain, portable JSON."""
    if hasattr(value, "text") and value.__class__.__name__ == "_DecimalNumber":
        return value.text
    if isinstance(value, Decimal):
        return canonical.canonical_decimal(value)
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_plain(v) for v in value]
    return value


class SyncRejected(Exception):
    """The receiver's baseline does not match the sync package."""


class SyncVerificationFailed(Exception):
    """The applied result did not reproduce the package's target root."""


# --- package creation ----------------------------------------------------
def create_sync_package(store: Store, base_name: str,
                        target_name: str, diff: dict) -> dict:
    base_manifest = store.read_manifest(base_name)
    target_manifest = store.read_manifest(target_name)
    package = {
        "package_version": 1,
        "schema": {
            "field_names": target_manifest["field_names"],
            "types": target_manifest["types"],
            "key_fields": target_manifest["key_fields"],
            "schema_hash": target_manifest["schema_hash"],
        },
        "base_snapshot": base_name,
        "target_snapshot": target_name,
        "base_root_hash": base_manifest["root_hash"],
        "target_root_hash": target_manifest["root_hash"],
        "base_record_count": base_manifest["record_count"],
        "target_record_count": target_manifest["record_count"],
        "changes": [_plain(_package_change(store, base_name, target_name, c))
                    for c in diff["changes"]],
    }
    canonical_part = dumps_json({k: v for k, v in package.items()
                                 if k != "package_sha256"})
    package["package_sha256"] = hashlib.sha256(
        canonical_part.encode("utf-8")).hexdigest()
    return package


def _package_change(store: Store, base_name: str, target_name: str,
                    change: dict) -> dict:
    out = {"type": change["type"], "bucket": change["bucket"],
           "pk": change["pk"]}
    if change["type"] in ("inserted", "modified"):
        out["target_row"] = change["target"]
        out["target_row_hash"] = change["target_hash"]
    if change["type"] in ("deleted", "modified"):
        out["base_row_hash"] = change["base_hash"]
    return out


def verify_package(package: dict) -> None:
    """Check the self-checksum of a received sync package."""
    claimed = package.get("package_sha256")
    canonical_part = dumps_json({k: v for k, v in package.items()
                                 if k != "package_sha256"})
    actual = hashlib.sha256(canonical_part.encode("utf-8")).hexdigest()
    if claimed != actual:
        raise SyncVerificationFailed(
            "sync package checksum mismatch; refusing to apply")


# --- package application -------------------------------------------------
def apply_sync_package(store: Store, receiver_name: str, package: dict,
                       new_snapshot_name: str) -> dict:
    verify_package(package)

    receiver_manifest = store.read_manifest(receiver_name)
    # Guard 1: baseline root must match exactly.
    if receiver_manifest["root_hash"] != package["base_root_hash"]:
        raise SyncRejected(
            f"receiver root {receiver_manifest['root_hash'][:12]}... does not "
            f"match package baseline {package['base_root_hash'][:12]}...; "
            "receiver data left untouched")
    if receiver_manifest["schema_hash"] != package["schema"]["schema_hash"]:
        raise SyncRejected(
            "receiver schema hash does not match package baseline; "
            "receiver data left untouched")

    staging = f".staging-{new_snapshot_name}-{os.getpid()}"
    staging_dir = store.snapshot_dir(staging)
    try:
        merged = _apply_changes_to_rows(store, receiver_name, package)
        # dumps_json preserves Decimal via the __decimal__ marker; the builder
        # parses with loads_json which restores it exactly -- no float loss.
        payload = dumps_json(merged).encode("utf-8")
        manifest = build_snapshot(
            store, staging, payload, "json",
            key_fields=package["schema"]["key_fields"],
            declared_types=package["schema"]["types"],
            explicit_field_order=package["schema"]["field_names"])
        # Guard 2: the rebuilt tree must reproduce the advertised target root.
        if manifest["root_hash"] != package["target_root_hash"]:
            raise SyncVerificationFailed(
                f"staged root {manifest['root_hash'][:12]}... does not match "
                f"package target {package['target_root_hash'][:12]}...; "
                "receiver data left untouched")
        if manifest["record_count"] != package["target_record_count"]:
            raise SyncVerificationFailed(
                "staged record count disagrees with package target; "
                "receiver data left untouched")
        if store.exists(new_snapshot_name):
            raise SyncVerificationFailed(
                f"snapshot {new_snapshot_name!r} already exists; refusing to overwrite")
        # Publish: move the verified staging snapshot into place and persist
        # its source payload under the final name.
        os.replace(staging_dir, store.snapshot_dir(new_snapshot_name))
        store.save_source(new_snapshot_name, payload)
        final_manifest = store.read_manifest(new_snapshot_name)
        if final_manifest["root_hash"] != package["target_root_hash"]:
            raise SyncVerificationFailed(
                "post-publish root check failed; receiver data left untouched")
        return {
            "applied": True,
            "new_snapshot": new_snapshot_name,
            "root_hash": final_manifest["root_hash"],
            "record_count": final_manifest["record_count"],
            "changes_applied": len(package["changes"]),
        }
    finally:
        shutil.rmtree(staging_dir, ignore_errors=True)


def _apply_changes_to_rows(store: Store, receiver: str,
                           package: dict) -> list[dict]:
    manifest = store.read_manifest(receiver)
    key_fields = manifest["key_fields"]
    types = manifest["types"]
    field_names = manifest["field_names"]

    # Load every row block of the receiver; row hashes are verified on load.
    rows_by_pk: dict[bytes, dict] = {}
    for idx in range(BUCKET_COUNT):
        loaded = store.load_rows(receiver, idx)
        if loaded is None:
            raise SyncVerificationFailed(
                f"receiver bucket {leaf_id(idx)} unreadable")
        rows, _hashes = loaded
        for row in rows:
            pk = canonical.primary_key_encoding(key_fields, row, types)
            rows_by_pk[pk] = row

    for change in package["changes"]:
        kind = change["type"]
        if kind == "deleted":
            example_row = _coerce_pkg_row(change["pk"], key_fields, types)
        else:
            example_row = _coerce_pkg_row(change["target_row"],
                                          field_names, types)
        pk = canonical.primary_key_encoding(key_fields, example_row, types)
        if kind == "inserted":
            if pk in rows_by_pk:
                raise SyncVerificationFailed(
                    f"insert for existing key {dumps_json(change['pk'])} rejected")
            row = _coerce_pkg_row(change["target_row"], field_names, types)
            _check_row_hash(row, field_names, types,
                            change["target_row_hash"], "inserted")
            rows_by_pk[pk] = row
        elif kind == "modified":
            if pk not in rows_by_pk:
                raise SyncVerificationFailed(
                    f"update for missing key {dumps_json(change['pk'])} rejected")
            current_hash = canonical.row_hash(
                field_names, rows_by_pk[pk], types).hex()
            if current_hash != change["base_row_hash"]:
                raise SyncRejected(
                    f"base hash mismatch on key {dumps_json(change['pk'])}; "
                    "receiver diverged from package baseline")
            row = _coerce_pkg_row(change["target_row"], field_names, types)
            _check_row_hash(row, field_names, types,
                            change["target_row_hash"], "modified")
            rows_by_pk[pk] = row
        elif kind == "deleted":
            if pk not in rows_by_pk:
                raise SyncVerificationFailed(
                    f"delete for missing key {dumps_json(change['pk'])} rejected")
            current_hash = canonical.row_hash(
                field_names, rows_by_pk[pk], types).hex()
            if current_hash != change["base_row_hash"]:
                raise SyncRejected(
                    f"base hash mismatch on key {dumps_json(change['pk'])}; "
                    "receiver diverged from package baseline")
            del rows_by_pk[pk]
        else:
            raise SyncVerificationFailed(f"unknown change type {kind!r}")

    return [rows_by_pk[pk] for pk in sorted(rows_by_pk)]


def _coerce_pkg_row(row: dict, field_names: list[str],
                    types: dict[str, str]) -> dict:
    """Coerce package scalar values back to canonical internal values.

    Numbers travel as canonical decimal strings; only fields declared numeric
    are converted, so a string value such as ``"1.20"`` stays a string.
    """
    from decimal import Decimal
    out = {}
    for name in field_names:
        value = row.get(name)
        if value is None:
            out[name] = None
            continue
        declared = types[name]
        if declared == "string":
            out[name] = str(value)
        elif declared == "boolean":
            out[name] = bool(value)
        elif declared == "integer":
            out[name] = int(Decimal(str(value)))
        elif declared == "number":
            out[name] = Decimal(str(value))
        else:  # null
            out[name] = None
    return out


def _check_row_hash(row: dict, field_names: list[str], types: dict,
                    expected_hex: str, label: str) -> None:
    actual = canonical.row_hash(field_names, row, types).hex()
    if actual != expected_hex:
        raise SyncVerificationFailed(
            f"{label} row hash does not match package record; package tampered")
