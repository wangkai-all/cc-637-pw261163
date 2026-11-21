"""Deterministic sample data used by the demo and the test-suite scenarios.

Scenarios deliberately include:
* a row whose primary key lands exactly on a hash bucket boundary
  (``B-EDGE-00``);
* null vs empty-string distinctions (``note``);
* decimal representations that differ textually but must hash identically
  (``amount``: 19.9 vs 19.90);
* a delete of the very last row (``B-LAST-99``).
"""
from __future__ import annotations

import copy

from .canonical import bucket_index, primary_key_encoding

SCHEMA_TYPES = {
    "id": "string",
    "name": "string",
    "amount": "number",
    "qty": "integer",
    "active": "boolean",
    "note": "string",
}
KEY_FIELDS = ["id"]
FIELD_NAMES = ["id", "name", "amount", "qty", "active", "note"]


def base_rows(n: int = 120) -> list[dict]:
    rows = []
    for i in range(n):
        rows.append({
            "id": f"B-{i:04d}",
            "name": f"item-{i}",
            "amount": f"{(i * 1.1) % 97:.2f}",
            "qty": i * 3,
            "active": i % 2 == 0,
            "note": None if i % 5 else "",
        })
    # explicitly designed edge rows
    rows.append({"id": "B-EDGE-00", "name": "edge-boundary", "amount": "10.00",
                 "qty": 1, "active": True, "note": None})
    rows.append({"id": "B-LAST-99", "name": "last-row", "amount": "0.01",
                 "qty": 999, "active": False, "note": "to be deleted"})
    rows.append({"id": "B-NULL-01", "name": "null-demo", "amount": "3.14",
                 "qty": 2, "active": True, "note": None})
    return rows


def target_rows(base: list[dict] | None = None) -> list[dict]:
    rows = copy.deepcopy(base if base is not None else base_rows())
    # 1. textual-only decimal change: 7.70 -> 7.7 must hash identically
    #    (this row therefore must NOT appear as a modification)
    for r in rows:
        if r["id"] == "B-0007":
            r["amount"] = "7.7"
    # 2. a real modification (amount changes)
    for r in rows:
        if r["id"] == "B-0010":
            r["amount"] = "42.25"
            r["note"] = "changed note"
    # 3. null -> empty string correction (must hash differently)
    for r in rows:
        if r["id"] == "B-NULL-01":
            r["note"] = ""
    # 4. insert a new row; all other buckets stay put
    rows.append({"id": "B-NEW-500", "name": "inserted", "amount": "7.77",
                 "qty": 7, "active": True, "note": "new"})
    # 5. delete the last row
    rows = [r for r in rows if r["id"] != "B-LAST-99"]
    return rows


def bucket_of(row_id: str) -> int:
    pk = primary_key_encoding(KEY_FIELDS, {"id": row_id}, SCHEMA_TYPES)
    return bucket_index(pk)
