"""Deterministic canonical typing and hashing rules.

Every value is encoded as ``TAG:BYTE_LENGTH:PAYLOAD`` where TAG carries the
field type and BYTE_LENGTH is the length of the payload in UTF-8 bytes.  The
length prefix makes the framing unambiguous regardless of content.

Type tags
---------
N  null               payload empty              -> ``N:0:``
B  boolean            payload ``T`` / ``F``       -> ``B:1:T``
I  integer            canonical decimal digits    -> ``I:3:100``
D  decimal number     canonical decimal text      -> ``D:3:1.2``
S  string             UTF-8 bytes (may be empty)  -> ``S:0:`` for ""

Null and the empty string therefore produce different hashes.  Decimals are
canonicalised so ``1.20`` / ``1.2`` / ``1.200`` hash identically while the
declared type still distinguishes an integer column from a decimal column.
"""
from __future__ import annotations

import hashlib
from decimal import Decimal, InvalidOperation
from typing import Any, Iterable

# --- type tags -----------------------------------------------------------
TAG_NULL = "N"
TAG_BOOL = "B"
TAG_INT = "I"
TAG_DEC = "D"
TAG_STR = "S"

VALID_TYPES = frozenset({"string", "integer", "number", "boolean", "null"})
_DECLARED_TO_TAG = {
    "string": TAG_STR,
    "integer": TAG_INT,
    "number": TAG_DEC,
    "boolean": TAG_BOOL,
    "null": TAG_NULL,
}

# byte separators (control characters that cannot appear in a UTF-8 name/value
# payload produced by the encoder itself)
NAME_SEP = b"\x1f"
FIELD_SEP = b"\x1e"

ROW_MAGIC = b"ROW\x01"
PK_MAGIC = b"PK\x01"


class CanonicalError(ValueError):
    """Raised when input data cannot be canonicalised deterministically."""


class DuplicateKeyError(CanonicalError):
    def __init__(self, duplicates: list[dict]):
        self.duplicates = duplicates
        preview = ", ".join(d["pk_text"] for d in duplicates[:5])
        more = "" if len(duplicates) <= 5 else f" ... ({len(duplicates)} total)"
        super().__init__(f"duplicate primary key rejected: {preview}{more}")


# --- value canonicalisation ----------------------------------------------
def canonical_decimal(value: Decimal) -> str:
    """Return a canonical plain decimal representation.

    No exponent notation, no leading ``+``, no insignificant leading zeros,
    no trailing fractional zeros; negative zero collapses to ``0``.
    """
    if value.is_nan() or value.is_infinite():
        raise CanonicalError("non-finite decimals are not supported")
    negative = value.is_signed() and value != 0
    text = format(value.copy_abs().normalize(), "f")
    if "." in text:
        int_part, frac = text.split(".", 1)
        frac = frac.rstrip("0")
        text = int_part + ("." + frac if frac else "")
    int_part = text.split(".", 1)[0]
    if int_part.strip("0") == "":
        text = ("0" + text[len(int_part):]) if text.startswith("0") else text
        text = "0" + text[1:] if len(int_part) > 1 else text
    return ("-" if negative else "") + text


def _auto_tag(value: Any) -> str:
    if value is None:
        return TAG_NULL
    if isinstance(value, bool):
        return TAG_BOOL
    if isinstance(value, int):
        return TAG_INT
    if isinstance(value, Decimal):
        return TAG_INT if value == value.to_integral_value() else TAG_DEC
    if isinstance(value, str):
        return TAG_STR
    raise CanonicalError(f"value of type {type(value).__name__} is not supported")


def coerce_csv_cell(raw: str, declared: str) -> Any:
    """Coerce a raw CSV string cell according to a declared column type.

    For every type except ``string`` an empty cell means NULL; a string column
    preserves the empty string so that "" and null stay distinguishable.
    """
    if declared == "string":
        return raw
    if raw == "":
        return None
    if declared == "null":
        return None
    if declared == "boolean":
        low = raw.lower()
        if low in ("true", "1"):
            return True
        if low in ("false", "0"):
            return False
        raise CanonicalError(f"invalid boolean literal {raw!r}")
    if declared == "integer":
        try:
            dec = Decimal(raw)
        except InvalidOperation as exc:
            raise CanonicalError(f"invalid integer literal {raw!r}") from exc
        if dec != dec.to_integral_value():
            raise CanonicalError(f"integer column got fractional value {raw!r}")
        return int(dec)
    if declared == "number":
        try:
            return Decimal(raw)
        except InvalidOperation as exc:
            raise CanonicalError(f"invalid number literal {raw!r}") from exc
    raise CanonicalError(f"unknown declared type {declared!r}")


def _coerce_typed(value: Any, declared: str) -> Any:
    """Coerce an already-parsed (JSON) value to the declared column type."""
    if value is None:
        return None
    if declared == "string":
        if isinstance(value, str):
            return value
        raise CanonicalError(f"string column got {type(value).__name__}")
    if declared == "null":
        return None
    if declared == "boolean":
        if isinstance(value, bool):
            return value
        raise CanonicalError(f"boolean column got {type(value).__name__}")
    if declared in ("integer", "number"):
        if isinstance(value, bool):
            raise CanonicalError("boolean is not a number")
        if isinstance(value, int):
            dec = Decimal(value)
        elif isinstance(value, Decimal):
            dec = value
        elif isinstance(value, str):
            # Numeric values may arrive as text (e.g. JSON produced by
            # spreadsheet export); apply the same parsing rules as CSV.
            try:
                dec = Decimal(value)
            except InvalidOperation as exc:
                raise CanonicalError(
                    f"{declared} column got non-numeric string {value!r}") from exc
        else:
            raise CanonicalError(f"numeric column got {type(value).__name__}")
        if declared == "integer":
            if dec != dec.to_integral_value():
                raise CanonicalError(f"integer column got fractional value {value}")
            return int(dec)
        return dec
    raise CanonicalError(f"unknown declared type {declared!r}")


def encode_value(value: Any, declared: str | None = None) -> bytes:
    """Canonical byte encoding of one scalar value."""
    if declared is not None and declared not in VALID_TYPES:
        raise CanonicalError(f"unknown declared type {declared!r}")
    if value is None:
        tag, payload = TAG_NULL, b""
    elif declared is not None:
        value = _coerce_typed(value, declared)
        if value is None:
            tag, payload = TAG_NULL, b""
        else:
            tag = _DECLARED_TO_TAG[declared]
            payload = _payload_bytes(tag, value)
    else:
        tag = _auto_tag(value)
        payload = _payload_bytes(tag, value)
    return f"{tag}:{len(payload)}:".encode("ascii") + payload


def _payload_bytes(tag: str, value: Any) -> bytes:
    if tag == TAG_BOOL:
        return b"T" if value else b"F"
    if tag == TAG_INT:
        return str(int(value)).encode("ascii")
    if tag == TAG_DEC:
        return canonical_decimal(value).encode("ascii")
    if tag == TAG_STR:
        return str(value).encode("utf-8")
    raise CanonicalError(f"tag {tag} takes no payload")


def encode_field(field_name: str, value: Any, declared: str | None) -> bytes:
    """One field fragment: UTF-8 field name, separator, typed value."""
    return field_name.encode("utf-8") + NAME_SEP + encode_value(value, declared)


def row_hash_input(field_names: Iterable[str], row: dict,
                   types: dict[str, str]) -> bytes:
    """Full deterministic hash input of one row.

    Field order is the schema's fixed order; every fragment carries the field
    name, its type tag and the payload byte length.
    """
    parts = [ROW_MAGIC]
    names = list(field_names)
    parts.append(len(names).to_bytes(2, "big"))
    for name in names:
        parts.append(encode_field(name, row.get(name), types.get(name)))
        parts.append(FIELD_SEP)
    return b"".join(parts)


def row_hash(field_names: Iterable[str], row: dict,
             types: dict[str, str]) -> bytes:
    return hashlib.sha256(row_hash_input(field_names, row, types)).digest()


def primary_key_encoding(key_fields: list[str], row: dict,
                         types: dict[str, str]) -> bytes:
    parts = [PK_MAGIC, len(key_fields).to_bytes(2, "big")]
    for name in key_fields:
        if name not in row or row[name] is None:
            raise CanonicalError(f"primary key field {name!r} must be present and non-null")
        parts.append(encode_value(row[name], types.get(name)))
        parts.append(FIELD_SEP)
    return b"".join(parts)


def bucket_index(pk_encoding: bytes) -> int:
    """Fixed primary-key partition: one of 256 stable buckets."""
    return hashlib.sha256(pk_encoding).digest()[0]
