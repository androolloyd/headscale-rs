#!/usr/bin/env python3
"""Offline tests for scripts/check_vendor_provenance.py (synthetic crates only)."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import pathlib
import sys
import tarfile
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "check_vendor_provenance.py"
spec = importlib.util.spec_from_file_location("check_vendor_provenance", SCRIPT)
cvp = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = cvp  # dataclasses resolve annotations through sys.modules
spec.loader.exec_module(cvp)

NAME, VERSION = "foo", "1.0.0"
CARGO_TOML = f'[package]\nname = "{NAME}"\nversion = "{VERSION}"\n'
PRISTINE = {
    "Cargo.toml": CARGO_TOML.encode(),
    "src/lib.rs": b"pub fn a() {}\npub fn b() {}\n",
    "src/util.rs": b"pub fn u() {}\n",
    "README.md": b"foo\n",
}
ROOT_CARGO_TOML = """\
[workspace]
members = ["app"]
exclude = ["vendor/foo"]

[patch.crates-io]
foo = { path = "vendor/foo" }
"""
ROOT_LOCK = f"""\
version = 4

[[package]]
name = "app"
version = "0.1.0"

[[package]]
name = "{NAME}"
version = "{VERSION}"
"""


def make_crate(files: dict[str, bytes], name: str = NAME, version: str = VERSION) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for path, data in sorted(files.items()):
            info = tarfile.TarInfo(f"{name}-{version}/{path}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class ProvenanceTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = pathlib.Path(self._tmp.name)
        self.repo = self.tmp / "repo"
        self.cache = self.tmp / "cache"
        self.cache.mkdir()
        self.archive = make_crate(PRISTINE)
        (self.cache / f"{NAME}-{VERSION}.crate").write_bytes(self.archive)
        self.archive_sha = cvp.sha256_bytes(self.archive)

        (self.repo / "app").mkdir(parents=True)
        (self.repo / "app" / "Cargo.toml").write_text('[package]\nname = "app"\nversion = "0.1.0"\n')
        (self.repo / "Cargo.toml").write_text(ROOT_CARGO_TOML)
        (self.repo / "Cargo.lock").write_text(ROOT_LOCK)
        self.vendor = self.repo / "vendor" / NAME
        for path, data in PRISTINE.items():
            self.write_vendored(path, data)
        # the local changes: one modified, one added, one removed file
        self.write_vendored("src/lib.rs", b"pub fn a() {}\npub fn b() { /* patched */ }\n")
        self.write_vendored("LOCAL.NOTES", b"why we patched\n")
        (self.vendor / "src" / "util.rs").unlink()

    # -- helpers ---------------------------------------------------------
    def write_vendored(self, path: str, data: bytes) -> None:
        target = self.vendor / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def run_script(self, *extra: str, index_lookup=None) -> tuple[int, str]:
        argv = ["--repo-root", str(self.repo), "--cache-dir", str(self.cache), "--walk", *extra]
        args = cvp.parse_args(argv)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            try:
                if index_lookup is None:
                    code = cvp.run(args)
                else:
                    code = cvp.run(args, index_lookup=index_lookup)
            except cvp.ProvenanceError as err:
                out.write(f"error: {err}\n")
                code = 2
        return code, out.getvalue()

    def update(self) -> None:
        code, out = self.run_script("--offline", "--update")
        self.assertEqual(code, 0, out)

    def manifest(self) -> dict:
        return json.loads((self.repo / "vendor" / "PATCHES.json").read_text())

    def write_manifest(self, manifest: dict) -> None:
        (self.repo / "vendor" / "PATCHES.json").write_text(cvp.dump_manifest(manifest))


class CheckTests(ProvenanceTestCase):
    def test_update_then_check_passes_and_records_every_difference(self) -> None:
        self.update()
        files = self.manifest()["crates"][NAME]["files"]
        self.assertEqual(files["src/lib.rs"]["status"], "modified")
        self.assertEqual(files["LOCAL.NOTES"]["status"], "added")
        self.assertEqual(files["src/util.rs"]["status"], "removed")
        self.assertEqual(files["LOCAL.NOTES"]["sha256"], cvp.sha256_bytes(b"why we patched\n"))
        self.assertEqual(set(files), {"src/lib.rs", "LOCAL.NOTES", "src/util.rs"})
        self.assertEqual(self.manifest()["crates"][NAME]["upstream"]["archive_sha256"], self.archive_sha)

        code, out = self.run_script("--offline")
        self.assertEqual(code, 0, out)
        self.assertIn("1 modified, 1 added, 1 removed", out)

    def test_check_passes_with_matching_index_checksum(self) -> None:
        self.update()
        code, out = self.run_script(index_lookup=lambda name, version: self.archive_sha)
        self.assertEqual(code, 0, out)

    def test_modified_file_after_review_fails(self) -> None:
        self.update()
        self.write_vendored("src/lib.rs", b"pub fn a() {}\npub fn b() { /* sneaky */ }\n")
        code, out = self.run_script("--offline")
        self.assertEqual(code, 1, out)
        self.assertIn("src/lib.rs: content changed since it was recorded", out)

    def test_unrecorded_modification_fails(self) -> None:
        self.update()
        self.write_vendored("README.md", b"foo, but different\n")
        code, out = self.run_script("--offline")
        self.assertEqual(code, 1, out)
        self.assertIn("unrecorded modified file: README.md", out)

    def test_unrecorded_added_file_fails(self) -> None:
        self.update()
        self.write_vendored("src/backdoor.rs", b"fn evil() {}\n")
        code, out = self.run_script("--offline")
        self.assertEqual(code, 1, out)
        self.assertIn("unrecorded added file: src/backdoor.rs", out)

    def test_unrecorded_removed_file_fails(self) -> None:
        self.update()
        (self.vendor / "README.md").unlink()
        code, out = self.run_script("--offline")
        self.assertEqual(code, 1, out)
        self.assertIn("unrecorded removed file: README.md", out)

    def test_stale_manifest_entry_fails(self) -> None:
        self.update()
        self.write_vendored("src/lib.rs", PRISTINE["src/lib.rs"])  # change reverted upstream-clean
        code, out = self.run_script("--offline")
        self.assertEqual(code, 1, out)
        self.assertIn("stale manifest entry: src/lib.rs", out)

    def test_manifest_archive_checksum_mismatch_fails(self) -> None:
        self.update()
        manifest = self.manifest()
        manifest["crates"][NAME]["upstream"]["archive_sha256"] = "0" * 64
        self.write_manifest(manifest)
        # the cached archive no longer matches the recorded hash, so offline cannot proceed ...
        code, out = self.run_script("--offline")
        self.assertEqual(code, 2, out)
        # ... and with a different (downloadable) archive the mismatch is reported
        (self.cache / f"{NAME}-{VERSION}.crate").unlink()
        provider_calls = []

        class Provider(cvp.PristineProvider):
            def __init__(inner, *a, **k):
                super().__init__(*a, fetch_archive=lambda n, v: provider_calls.append((n, v)) or self.archive, **k)

        args = cvp.parse_args(["--repo-root", str(self.repo), "--cache-dir", str(self.cache), "--walk"])
        out_buf = io.StringIO()
        with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(out_buf):
            code = cvp.run(args, provider_factory=Provider, index_lookup=lambda n, v: self.archive_sha)
        self.assertEqual(code, 1, out_buf.getvalue())
        self.assertIn("does not match vendor/PATCHES.json", out_buf.getvalue())
        self.assertEqual(provider_calls, [(NAME, VERSION)])

    def test_index_checksum_mismatch_fails_even_for_update(self) -> None:
        code, out = self.run_script("--update", index_lookup=lambda n, v: "f" * 64)
        self.assertEqual(code, 2, out)
        self.assertIn("does not match the crates.io index checksum", out)
        self.update()
        code, out = self.run_script(index_lookup=lambda n, v: "f" * 64)
        self.assertEqual(code, 1, out)
        self.assertIn("does not match the crates.io index checksum", out)

    def test_upstream_md_archive_hash_must_match(self) -> None:
        self.write_vendored("UPSTREAM.md", f"Starts from the exact `foo` 1.0.0 archive, SHA-256 `{'a' * 64}`.\n".encode())
        code, out = self.run_script("--offline", "--update")
        self.assertEqual(code, 2, out)
        self.write_vendored("UPSTREAM.md", f"Starts from the exact `foo` 1.0.0 archive, SHA-256 `{self.archive_sha}`.\n".encode())
        self.update()
        code, out = self.run_script("--offline")
        self.assertEqual(code, 0, out)

    def test_version_drift_fails(self) -> None:
        self.update()
        (self.vendor / "Cargo.toml").write_text(CARGO_TOML.replace(VERSION, "1.0.1"))
        code, out = self.run_script("--offline")
        # 1.0.1 is not in the cache and --offline forbids a download
        self.assertEqual(code, 2, out)

    def test_untracked_vendor_dir_fails(self) -> None:
        self.update()
        other = self.repo / "vendor" / "bar"
        other.mkdir()
        (other / "Cargo.toml").write_text('[package]\nname = "bar"\nversion = "0.1.0"\n')
        code, out = self.run_script("--offline")
        self.assertEqual(code, 1, out)
        self.assertIn("vendor/bar is not covered by vendor/PATCHES.json", out)

    def test_missing_manifest_is_operational_error(self) -> None:
        code, out = self.run_script("--offline")
        self.assertEqual(code, 2, out)
        self.assertIn("PATCHES.json is missing", out)


class WiringTests(ProvenanceTestCase):
    def test_patch_entry_outside_vendor_fails(self) -> None:
        self.update()
        (self.repo / "Cargo.toml").write_text(ROOT_CARGO_TOML + 'bar = { path = "elsewhere/bar" }\n')
        code, out = self.run_script("--offline")
        self.assertEqual(code, 1, out)
        self.assertIn("elsewhere/bar", out)

    def test_missing_patch_entry_fails(self) -> None:
        self.update()
        (self.repo / "Cargo.toml").write_text('[workspace]\nmembers = ["app"]\nexclude = ["vendor/foo"]\n')
        code, out = self.run_script("--offline")
        self.assertEqual(code, 1, out)
        self.assertIn("has no [patch.crates-io] path entry", out)

    def test_unknown_sourceless_lock_package_fails(self) -> None:
        self.update()
        (self.repo / "Cargo.lock").write_text(ROOT_LOCK + '\n[[package]]\nname = "mystery"\nversion = "0.0.1"\n')
        code, out = self.run_script("--offline")
        self.assertEqual(code, 1, out)
        self.assertIn("mystery 0.0.1 has no registry source", out)

    def test_wrong_vendored_version_in_lock_fails(self) -> None:
        self.update()
        (self.repo / "Cargo.lock").write_text(ROOT_LOCK.replace(f'version = "{VERSION}"', 'version = "0.9.0"'))
        code, out = self.run_script("--offline")
        self.assertEqual(code, 1, out)
        self.assertIn("is not the vendored version", out)

    def test_registry_package_in_lock_is_fine(self) -> None:
        self.update()
        (self.repo / "Cargo.lock").write_text(
            ROOT_LOCK + '\n[[package]]\nname = "serde"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'
        )
        code, out = self.run_script("--offline")
        self.assertEqual(code, 0, out)


class LocalPatchTests(ProvenanceTestCase):
    PATCH = (
        "--- a/vendor/foo/src/lib.rs\n"
        "+++ b/vendor/foo/src/lib.rs\n"
        "@@ -1,2 +1,2 @@\n"
        " pub fn a() {}\n"
        "-pub fn b() {}\n"
        "+pub fn b() { /* patched */ }\n"
        "--- /dev/null\n"
        "+++ b/vendor/foo/LOCAL.NOTES\n"
        "@@ -0,0 +1 @@\n"
        "+why we patched\n"
        "--- a/vendor/foo/src/util.rs\n"
        "+++ /dev/null\n"
        "@@ -1 +0,0 @@\n"
        "-pub fn u() {}\n"
    )

    def test_patch_reproduces_vendored_files(self) -> None:
        self.write_vendored("LOCAL.patch", self.PATCH.encode())
        self.update()
        code, out = self.run_script("--offline", "-v")
        self.assertEqual(code, 0, out)
        self.assertIn("LOCAL.patch reproduces 3 of 3 touched files", out)
        self.assertNotIn("warning:", out)

    def test_patch_mismatch_warns_and_is_fatal_when_strict(self) -> None:
        self.write_vendored("LOCAL.patch", self.PATCH.replace("/* patched */", "/* stale */").encode())
        self.update()
        code, out = self.run_script("--offline")
        self.assertEqual(code, 0, out)
        self.assertIn("LOCAL.patch does not reproduce the vendored file(s): src/lib.rs", out)
        code, out = self.run_script("--offline", "--strict-patch")
        self.assertEqual(code, 1, out)

    def test_unified_diff_applier_handles_missing_trailing_newline(self) -> None:
        old = b"one\ntwo"
        patch = (
            b"--- a/vendor/foo/f\n+++ b/vendor/foo/f\n@@ -1,2 +1,3 @@\n one\n-two\n"
            b"\\ No newline at end of file\n+two\n+three\n\\ No newline at end of file\n"
        )
        (parsed,) = cvp.parse_unified_diff(patch)
        self.assertEqual(cvp.apply_hunks(old, parsed.hunks, "f"), b"one\ntwo\nthree")

    def test_unified_diff_applier_finds_shifted_hunks_and_rejects_bad_context(self) -> None:
        old = b"".join(f"line{i}\n".encode() for i in range(1, 40))
        good = b"--- a/vendor/foo/f\n+++ b/vendor/foo/f\n@@ -20,3 +20,3 @@\n line10\n-line11\n+LINE11\n line12\n"
        (parsed,) = cvp.parse_unified_diff(good)
        self.assertIn(b"LINE11\n", cvp.apply_hunks(old, parsed.hunks, "f"))
        bad = good.replace(b" line12", b" lineXX")
        (parsed,) = cvp.parse_unified_diff(bad)
        with self.assertRaises(cvp.ProvenanceError):
            cvp.apply_hunks(old, parsed.hunks, "f")


class HelperTests(unittest.TestCase):
    def test_index_path(self) -> None:
        self.assertEqual(cvp.index_path("h2"), "2/h2")
        self.assertEqual(cvp.index_path("http"), "ht/tp/http")
        self.assertEqual(cvp.index_path("aws-lc-rs"), "aw/s-/aws-lc-rs")
        self.assertEqual(cvp.index_path("Foo"), "3/f/foo")

    def test_upstream_md_hash_extraction(self) -> None:
        a, b, c = "a" * 64, "b" * 64, "c" * 64
        text = (
            f"exact crates.io `h2` 0.4.20 archive, SHA-256 `{a}`.\n"
            f"Its archive SHA-256 is\n`{b}`.\n"
            f"original crates.io archive checksum is `{c}`\n"
            f"- src/client.rs: `{'d' * 64}`\n"
        )
        self.assertEqual(cvp.upstream_md_archive_hashes(text), {a, b, c})

    def test_safe_extract_rejects_traversal(self) -> None:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            info = tarfile.TarInfo("foo-1.0.0/../escape")
            info.size = 1
            tar.addfile(info, io.BytesIO(b"x"))
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(cvp.ProvenanceError):
            cvp.safe_extract(buffer.getvalue(), pathlib.Path(tmp), "foo-1.0.0")

    def test_diff_trees(self) -> None:
        diff = cvp.diff_trees({"a": "1", "b": "2", "c": "3"}, {"a": "1", "b": "9", "d": "4"})
        self.assertEqual(
            diff,
            {
                "b": {"status": "modified", "sha256": "9", "upstream_sha256": "2"},
                "c": {"status": "removed", "upstream_sha256": "3"},
                "d": {"status": "added", "sha256": "4"},
            },
        )


if __name__ == "__main__":
    unittest.main()
