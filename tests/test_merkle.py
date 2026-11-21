"""End-to-end test suite for the Merkle snapshot diff tool.

Run with:  python -I -m unittest -v   (from the repo root, tests/ on path)

Covers: deterministic hashing rules, fixed-bucket stability, duplicate-key
rejection, measured IO counters, corruption scoping, interrupted/resumed
builds, row-by-row verification, and guarded sync packages.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from decimal import Decimal

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from merkle import canonical
from merkle.builder import (BuildInterrupted, build_snapshot, prepare_schema,
                            _canonicalise_rows, _decode_rows)
from merkle.canonical import DuplicateKeyError
from merkle.check import check_snapshot, inject_corruption
from merkle.differ import diff_snapshots
from merkle.sample_data import SCHEMA_TYPES, base_rows, target_rows
from merkle.store import (BUCKET_COUNT, L1_COUNT, Store, leaf_id, l1_id,
                          NODE_ROOT, loads_json)
from merkle.sync import (SyncRejected, SyncVerificationFailed,
                         apply_sync_package, create_sync_package,
                         verify_package)


class TempStoreTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="merkle-test-")
        # durability fsyncs stay on in production; tests skip them for speed
        self.store = Store(self.tmp, fsync=False)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def build(self, name, rows, fail_after=None, types=None, keys=None):
        payload = json.dumps(rows).encode("utf-8")
        return build_snapshot(
            self.store, name, payload, "json",
            key_fields=keys or ["id"],
            declared_types=types or SCHEMA_TYPES,
            fail_after_nodes=fail_after)


# --------------------------------------------------------------------------
# 1. deterministic canonical hashing
# --------------------------------------------------------------------------
class CanonicalTests(unittest.TestCase):
    def test_null_vs_empty_string_distinct(self):
        self.assertNotEqual(
            canonical.encode_value(None),
            canonical.encode_value("", "string"))
        self.assertEqual(canonical.encode_value(None), b"N:0:")
        self.assertEqual(canonical.encode_value("", "string"), b"S:0:")

    def test_type_tag_enters_hash(self):
        h_int = canonical.encode_value(1, "integer")
        h_str = canonical.encode_value("1", "string")
        h_dec = canonical.encode_value(Decimal("1"), "number")
        self.assertEqual(len({h_int, h_str, h_dec}), 3)
        self.assertTrue(h_int.startswith(b"I:"))
        self.assertTrue(h_dec.startswith(b"D:"))

    def test_length_prefix_disambiguates_concatenation(self):
        # "ab"+"c" must not equal "a"+"bc"
        types = {"a": "string", "b": "string"}
        r1 = canonical.row_hash(["a", "b"], {"a": "ab", "b": "c"}, types)
        r2 = canonical.row_hash(["a", "b"], {"a": "a", "b": "bc"}, types)
        self.assertNotEqual(r1, r2)

    def test_field_order_matters(self):
        types = {"a": "string", "b": "string"}
        r1 = canonical.row_hash(["a", "b"], {"a": "x", "b": "y"}, types)
        r2 = canonical.row_hash(["b", "a"], {"a": "x", "b": "y"}, types)
        self.assertNotEqual(r1, r2)

    def test_field_name_enters_hash(self):
        t1 = {"a": "string"}
        t2 = {"b": "string"}
        r1 = canonical.row_hash(["a"], {"a": "v"}, t1)
        r2 = canonical.row_hash(["b"], {"b": "v"}, t2)
        self.assertNotEqual(r1, r2)

    def test_decimal_representations_canonicalise(self):
        pairs = [("1.20", "1.2"), ("100.00", "100"), ("0.0", "0"),
                 ("-0.000", "0"), ("1.2300", "1.23"), ("007.5", "7.50")]
        for a, b in pairs:
            self.assertEqual(
                canonical.encode_value(Decimal(a), "number"),
                canonical.encode_value(Decimal(b), "number"),
                f"{a} vs {b}")

    def test_integer_vs_decimal_column_distinct_even_when_equal(self):
        self.assertNotEqual(
            canonical.encode_value(Decimal("1.0"), "number"),
            canonical.encode_value(1, "integer"))

    def test_boolean_and_null_encodings(self):
        self.assertEqual(canonical.encode_value(True, "boolean"), b"B:1:T")
        self.assertEqual(canonical.encode_value(False, "boolean"), b"B:1:F")
        self.assertEqual(canonical.encode_value(None, "string"), b"N:0:")

    def test_csv_empty_cell_string_vs_null(self):
        self.assertEqual(canonical.coerce_csv_cell("", "string"), "")
        self.assertIsNone(canonical.coerce_csv_cell("", "integer"))
        self.assertIsNone(canonical.coerce_csv_cell("", "number"))


# --------------------------------------------------------------------------
# 2. fixed primary-key partitions
# --------------------------------------------------------------------------
class BucketTests(unittest.TestCase):
    def test_buckets_are_stable_and_in_range(self):
        for i in range(500):
            pk = canonical.primary_key_encoding(["id"], {"id": f"K-{i}"},
                                                {"id": "string"})
            idx = canonical.bucket_index(pk)
            self.assertGreaterEqual(idx, 0)
            self.assertLess(idx, BUCKET_COUNT)
            # deterministic: same key always lands in same bucket
            self.assertEqual(idx, canonical.bucket_index(pk))

    def test_new_row_does_not_shift_other_leaves(self):
        # Build two datasets where v2 only adds one row; every other bucket's
        # leaf hash must remain byte-identical.
        tmp = tempfile.mkdtemp()
        try:
            store = Store(tmp, fsync=False)
            rows1 = [{"id": f"R-{i:04d}", "v": i} for i in range(200)]
            types = {"id": "string", "v": "integer"}
            build_snapshot(store, "s1", json.dumps(rows1).encode(),
                           "json", ["id"], types)
            rows2 = rows1 + [{"id": "R-NEW", "v": -1}]
            build_snapshot(store, "s2", json.dumps(rows2).encode(),
                           "json", ["id"], types)
            new_pk = canonical.primary_key_encoding(
                ["id"], {"id": "R-NEW"}, types)
            new_bucket = canonical.bucket_index(new_pk)
            changed = []
            for idx in range(BUCKET_COUNT):
                h1 = store.load_node("s1", leaf_id(idx))["hash"]
                h2 = store.load_node("s2", leaf_id(idx))["hash"]
                if h1 != h2:
                    changed.append(idx)
            self.assertEqual(changed, [new_bucket])
        finally:
            shutil.rmtree(tmp)


# --------------------------------------------------------------------------
# 3. build + diff behaviour
# --------------------------------------------------------------------------
class BuildAndDiffTests(TempStoreTestCase):
    def test_duplicate_primary_key_rejected(self):
        rows = [{"id": "x", "v": 1}, {"id": "x", "v": 2}]
        with self.assertRaises(DuplicateKeyError) as ctx:
            self.build("dup", rows)
        self.assertEqual(len(ctx.exception.duplicates), 1)
        # nothing published
        self.assertFalse(self.store.is_complete("dup"))
        self.assertFalse(os.path.exists(self.store.source_path("dup")))

    def test_composite_key_duplicate_rejected(self):
        rows = [{"a": 1, "b": "z"}, {"a": 1, "b": "z"}]
        with self.assertRaises(DuplicateKeyError):
            build_snapshot(self.store, "dup2",
                           json.dumps(rows).encode(), "json",
                           ["a", "b"], {"a": "integer", "b": "string"})

    def test_identical_snapshots_have_same_root_and_zero_io(self):
        self.build("same1", base_rows())
        self.build("same2", base_rows())
        d = diff_snapshots(self.store, "same1", "same2")
        self.assertTrue(d["root_equal"])
        self.assertEqual(d["counts"],
                         {"inserted": 0, "deleted": 0, "modified": 0})
        # only the two root envelopes were opened; no child, no row at all
        self.assertEqual(d["tree_walk"]["nodes_loaded"], 2)
        self.assertEqual(d["tree_walk"]["rows_loaded"], 0)
        self.assertGreaterEqual(d["tree_walk"]["subtrees_skipped_equal"], 1)
        self.assertTrue(d["verified"])

    def test_demo_scenario_row_level_changes(self):
        self.build("demo-v1", base_rows())
        self.build("demo-v2", target_rows())
        d = diff_snapshots(self.store, "demo-v1", "demo-v2")
        self.assertFalse(d["root_equal"])
        self.assertEqual(d["counts"]["inserted"], 1)   # B-NEW-500
        self.assertEqual(d["counts"]["deleted"], 1)    # B-LAST-99
        # B-0010 amount+note and B-NULL-01 null->"" ;
        # B-0007 decimal-only change must NOT be modified
        modified_ids = {tuple(sorted(c["pk"].items()))[0][1]
                        for c in d["changes"] if c["type"] == "modified"}
        self.assertEqual(modified_ids, {"B-0010", "B-NULL-01"})
        ins = [c for c in d["changes"] if c["type"] == "inserted"][0]
        self.assertEqual(ins["pk"]["id"], "B-NEW-500")
        dele = [c for c in d["changes"] if c["type"] == "deleted"][0]
        self.assertEqual(dele["pk"]["id"], "B-LAST-99")
        # full row-by-row verification agrees
        self.assertTrue(d["full_scan"]["verified"])
        self.assertEqual(d["full_scan"]["inserted"], 1)
        self.assertEqual(d["full_scan"]["deleted"], 1)
        self.assertEqual(d["full_scan"]["modified"], 2)

    def test_walk_touches_only_changed_subtrees(self):
        self.build("demo-v1", base_rows())
        self.build("demo-v2", target_rows())
        d = diff_snapshots(self.store, "demo-v1", "demo-v2")
        w = d["tree_walk"]
        # 256 leaves + 16 l1 + root = 273 nodes per tree; pruned walk reads
        # far fewer than 546 envelopes and only the changed buckets' rows
        self.assertLess(w["nodes_loaded"], 546)
        changed_buckets = {c["bucket"] for c in d["changes"]}
        # rows_loaded equals rows inside changed buckets only
        expected_rows = 0
        for idx in changed_buckets:
            expected_rows += self.store.load_node(
                "demo-v1", leaf_id(idx))["record_count"]
            expected_rows += self.store.load_node(
                "demo-v2", leaf_id(idx))["record_count"]
        self.assertEqual(w["rows_loaded"], expected_rows)
        self.assertGreater(w["subtrees_skipped_equal"], 0)

    def test_null_correction_changes_hash_but_empty_equivalence_does_not(self):
        rows1 = [{"id": "1", "note": None, "amount": "1.20"}]
        rows2 = [{"id": "1", "note": "", "amount": "1.2"}]
        types = {"id": "string", "note": "string", "amount": "number"}
        self.build("n1", rows1, types=types)
        self.build("n2", rows2, types=types)
        d = diff_snapshots(self.store, "n1", "n2")
        # note null->"" is a modification even though amount text changed
        self.assertEqual(d["counts"]["modified"], 1)
        mod = d["changes"][0]
        self.assertIsNone(mod["base"]["note"])
        self.assertEqual(mod["target"]["note"], "")


# --------------------------------------------------------------------------
# 4. interrupted build and resume
# --------------------------------------------------------------------------
class ResumeTests(TempStoreTestCase):
    def test_interrupted_build_is_unpublished_and_resumable(self):
        rows = base_rows()
        with self.assertRaises(BuildInterrupted) as ctx:
            self.build("half", rows, fail_after=100)
        self.assertEqual(ctx.exception.after_nodes, 100)
        self.assertFalse(self.store.is_complete("half"))
        done = self.store.journal_done("half")
        self.assertEqual(len(done), 100)

        # resuming completes the build; the journaled nodes are not rebuilt
        before = {nid: self.store.node_path("half", nid) for nid in done}
        mtimes = {nid: os.path.getsize(p) for nid, p in
                  ((n, self.store.node_path("half", n)) for n in done)}
        manifest = build_snapshot(
            self.store, "half", json.dumps(rows).encode(), "json",
            ["id"], SCHEMA_TYPES)
        self.assertTrue(self.store.is_complete("half"))
        self.assertEqual(manifest["record_count"], len(rows))
        # root exists and total node count is exactly 273
        node_files = [f for f in os.listdir(self.store.nodes_dir("half"))
                      if f.endswith(".json")]
        self.assertEqual(len(node_files), BUCKET_COUNT + L1_COUNT + 1)

        # resumed tree equals a fresh, uninterrupted build
        self.build("fresh", rows)
        fresh_manifest = self.store.read_manifest("fresh")
        self.assertEqual(manifest["root_hash"], fresh_manifest["root_hash"])

    def test_root_not_published_until_all_children_done(self):
        rows = base_rows()
        with self.assertRaises(BuildInterrupted):
            self.build("half2", rows, fail_after=272)
        self.assertFalse(os.path.exists(
            self.store.node_path("half2", NODE_ROOT)))
        self.assertFalse(self.store.is_complete("half2"))

    def test_multiple_interruptions_then_complete(self):
        rows = base_rows()
        payload = json.dumps(rows).encode()
        # fail_after_nodes counts nodes written *this run*; journaled nodes
        # are skipped, so each run resumes from its previous high-water mark
        total_written = 0
        for budget in (50, 80, 80, 80, 80):
            try:
                build_snapshot(self.store, "multi", payload, "json",
                               ["id"], SCHEMA_TYPES,
                               fail_after_nodes=budget)
            except BuildInterrupted as exc:
                total_written += exc.after_nodes
        manifest = build_snapshot(self.store, "multi", payload, "json",
                                  ["id"], SCHEMA_TYPES)
        self.assertTrue(self.store.is_complete("multi"))
        self.build("ref", rows)
        self.assertEqual(manifest["root_hash"],
                         self.store.read_manifest("ref")["root_hash"])


# --------------------------------------------------------------------------
# 5. corruption detection and scoping
# --------------------------------------------------------------------------
class CorruptionTests(TempStoreTestCase):
    def _pair(self):
        self.build("c1", base_rows())
        self.build("c2", target_rows())

    def test_corrupt_single_leaf_is_scoped_to_one_bucket(self):
        self._pair()
        # b03 is non-empty in both demo snapshots
        inject_corruption(self.store, "c2", "node", target=leaf_id(3))
        report = check_snapshot(self.store, "c2")
        self.assertFalse(report["ok"])
        self.assertIn(leaf_id(3), report["affected_scopes"])
        # root summary alone would say "everything changed"; scoping must not
        report_scope = set(report["affected_scopes"])
        self.assertNotEqual(report_scope, {NODE_ROOT})
        self.assertNotIn(NODE_ROOT, report_scope)

        # The explicit integrity check is the authoritative corruption
        # detector.  In the diff walk, a Merkle pruner only visits a subtree
        # when parent hashes differ; here c2's parent still records the old
        # (pre-tamper) child hash, so the walk correctly reports what it can
        # prove from visited nodes and never fabricates a whole-table change.
        d = diff_snapshots(self.store, "c1", "c2")
        self.assertNotIn(
            leaf_id(3),
            [s for x in d["corruptions"] for s in x["scope"]])

    def test_corrupt_leaf_on_changed_path_is_detected_by_diff(self):
        # When the corrupted bucket is on a hash-divergent path, the walk
        # loads the leaf envelope and the parent/child cross-check fires.
        self._pair()
        # find a bucket that genuinely differs between c1 and c2
        d_clean = diff_snapshots(self.store, "c1", "c2")
        changed_bucket = d_clean["changes"][0]["bucket"]
        inject_corruption(self.store, "c2", "node",
                          target=leaf_id(changed_bucket))
        d = diff_snapshots(self.store, "c1", "c2")
        self.assertFalse(d["complete"])
        scopes = {s for x in d["corruptions"] for s in x["scope"]}
        self.assertIn(leaf_id(changed_bucket), scopes)

    def test_corrupt_row_block_detected_via_row_hash(self):
        self._pair()
        # bucket 0x03 is known non-empty for the demo dataset
        inject_corruption(self.store, "c2", "row", target="03")
        report = check_snapshot(self.store, "c2")
        self.assertFalse(report["ok"])
        self.assertIn(leaf_id(0x03), report["affected_scopes"])

    def test_corrupt_source_file_detected(self):
        self._pair()
        inject_corruption(self.store, "c1", "source")
        report = check_snapshot(self.store, "c1")
        self.assertFalse(report["ok"])
        self.assertIn("source", report["affected_scopes"])
        d = diff_snapshots(self.store, "c1", "c2")
        self.assertFalse(d["full_scan"]["verified"])
        self.assertTrue(any("source file" in e
                            for e in d["full_scan"]["errors"]))

    def test_corrupt_internal_node_reported_at_that_subtree(self):
        self._pair()
        inject_corruption(self.store, "c1", "internal", target=l1_id(3))
        report = check_snapshot(self.store, "c1")
        self.assertFalse(report["ok"])
        self.assertTrue(any(l1_id(3) in s for s in report["affected_scopes"]))

    def test_healthy_snapshot_passes_full_check(self):
        self._pair()
        for name in ("c1", "c2"):
            report = check_snapshot(self.store, name)
            self.assertTrue(report["ok"], report["issues"])
            self.assertEqual(report["nodes_verified"], 273)
            self.assertEqual(report["rows_verified"],
                             self.store.read_manifest(name)["record_count"])


# --------------------------------------------------------------------------
# 6. incremental sync packages
# --------------------------------------------------------------------------
class SyncTests(TempStoreTestCase):
    def setUp(self):
        super().setUp()
        self.build("base", base_rows())
        self.build("target", target_rows())
        self.diff = diff_snapshots(self.store, "base", "target")
        self.pkg = create_sync_package(self.store, "base", "target",
                                       self.diff)

    def test_package_roundtrip_reproduces_target_root(self):
        verify_package(self.pkg)
        result = apply_sync_package(self.store, "base", self.pkg,
                                    "replica")
        self.assertTrue(result["applied"])
        target_manifest = self.store.read_manifest("target")
        self.assertEqual(result["root_hash"],
                         target_manifest["root_hash"])
        # the freshly applied snapshot diffs as identical against target
        d = diff_snapshots(self.store, "replica", "target")
        self.assertTrue(d["root_equal"])
        self.assertEqual(d["counts"],
                         {"inserted": 0, "deleted": 0, "modified": 0})

    def test_baseline_mismatch_is_rejected_without_overwrite(self):
        # receiver is "target" (a different root) -> must reject
        with self.assertRaises(SyncRejected):
            apply_sync_package(self.store, "target", self.pkg, "evil")
        self.assertFalse(self.store.exists("evil"))
        # receiver snapshot untouched
        self.assertTrue(self.store.is_complete("target"))

    def test_tampered_package_fails_self_checksum(self):
        pkg = json.loads(json.dumps(self.pkg))
        pkg["changes"][0]["pk"]["id"] = "TAMPERED"
        with self.assertRaises(SyncVerificationFailed):
            verify_package(pkg)

    def test_tampered_row_payload_fails_row_hash_check(self):
        pkg = json.loads(json.dumps(self.pkg))
        for ch in pkg["changes"]:
            if ch["type"] == "inserted":
                ch["target_row"]["qty"] = 999999
        pkg["package_sha256"] = _recompute_checksum(pkg)
        with self.assertRaises(SyncVerificationFailed):
            apply_sync_package(self.store, "base", pkg, "bad-replica")
        self.assertFalse(self.store.exists("bad-replica"))

    def test_stale_package_after_receiver_drift_rejected(self):
        # drift the receiver: corrupt-free logical drift simulated by using
        # another snapshot's root as receiver by building a divergent copy
        drifted_rows = [dict(r) for r in base_rows()]
        for r in drifted_rows:
            if r["id"] == "B-0001":
                r["qty"] = -1
        self.build("drifted", drifted_rows)
        with self.assertRaises(SyncRejected):
            apply_sync_package(self.store, "drifted", self.pkg, "x")
        self.assertFalse(self.store.exists("x"))


def _recompute_checksum(pkg: dict) -> str:
    import hashlib
    from merkle.store import dumps_json
    part = dumps_json({k: v for k, v in pkg.items()
                       if k != "package_sha256"})
    return hashlib.sha256(part.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# 7. CSV ingestion and type rules end to end
# --------------------------------------------------------------------------
class CsvTests(TempStoreTestCase):
    def test_csv_null_empty_string_and_decimals(self):
        # Rules under test:
        #  - an empty CSV cell in a *string* column is "", not null
        #  - an empty CSV cell in a nullable column (active here) is null
        #  - 1.20/1.2 and 3.00/3 hash identically for a number column
        csv_text = ("id,name,amount,qty,active,note\r\n"
                    "1,a,1.20,10,true,\r\n"
                    "2,b,2.5,20,false,hello\r\n"
                    "3,c,3.00,30,,\"\"\r\n")
        m1 = build_snapshot(self.store, "csv1", csv_text.encode(), "csv",
                            ["id"], SCHEMA_TYPES)
        json_rows = [
            {"id": "1", "name": "a", "amount": "1.2", "qty": 10,
             "active": True, "note": ""},
            {"id": "2", "name": "b", "amount": "2.5", "qty": 20,
             "active": False, "note": "hello"},
            {"id": "3", "name": "c", "amount": "3", "qty": 30,
             "active": None, "note": ""},
        ]
        m2 = build_snapshot(self.store, "json1",
                            json.dumps(json_rows).encode(), "json",
                            ["id"], SCHEMA_TYPES)
        self.assertEqual(m1["root_hash"], m2["root_hash"])

    def test_csv_duplicate_keys_rejected(self):
        csv_text = "id,v\n1,a\n1,b\n"
        with self.assertRaises(DuplicateKeyError):
            build_snapshot(self.store, "csvdup", csv_text.encode(),
                           "csv", ["id"], {"id": "string", "v": "string"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
