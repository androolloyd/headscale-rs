#!/usr/bin/env python3
"""Offline tests for scripts/check_toolchain_pin.py (python3 -m unittest)."""

from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "check_toolchain_pin.py"
spec = importlib.util.spec_from_file_location("check_toolchain_pin", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

TOOLCHAIN = '[toolchain]\nchannel = "1.96.0"\ncomponents = ["clippy", "rustfmt"]\n'
WORKFLOW = "jobs:\n  a:\n    steps:\n      - uses: ./.github/actions/setup-rust\n      - run: cargo test\n"


def write(root: pathlib.Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def tree() -> pathlib.Path:
    root = pathlib.Path(tempfile.mkdtemp())
    files = {
        "rust-toolchain.toml": TOOLCHAIN,
        "deploy/docker/Dockerfile": "FROM rust:1.96.0-bookworm AS builder\n",
        ".github/workflows/ci.yml": WORKFLOW,
        "CHANGES.md": "the qualified toolchain is 1.96.0.\n",
    }
    for rel, text in files.items():
        write(root, rel, text)
    return root


class CheckToolchainPin(unittest.TestCase):
    def test_consistent_tree_passes(self) -> None:
        self.assertEqual(module.check(tree()), [])

    def test_floating_channel_is_rejected(self) -> None:
        root = tree()
        write(root, "rust-toolchain.toml", TOOLCHAIN.replace("1.96.0", "stable"))
        with self.assertRaises(module.CheckError):
            module.check(root)

    def test_dockerfile_drift_is_reported(self) -> None:
        root = tree()
        write(root, "deploy/docker/Dockerfile", "FROM rust:1.99-bookworm AS builder\n")
        self.assertTrue(any("Dockerfile" in p for p in module.check(root)))

    def test_floating_workflow_toolchain_is_reported(self) -> None:
        root = tree()
        write(
            root,
            ".github/workflows/ci.yml",
            WORKFLOW + "      - uses: dtolnay/rust-toolchain@master\n        with:\n          toolchain: nightly\n",
        )
        problems = module.check(root)
        self.assertTrue(any("dtolnay" in p for p in problems))
        self.assertTrue(any("floating" in p for p in problems))

    def test_workflow_without_setup_action_is_reported(self) -> None:
        root = tree()
        write(root, ".github/workflows/ci.yml", "jobs:\n  a:\n    steps:\n      - run: cargo test\n")
        self.assertTrue(any("never uses" in p for p in module.check(root)))

    def test_dated_nightly_override_is_allowed(self) -> None:
        root = tree()
        write(
            root,
            ".github/workflows/fuzz.yml",
            WORKFLOW + "        with:\n          toolchain: nightly-2026-08-21\n",
        )
        self.assertEqual(module.check(root), [])

    def test_changes_md_drift_is_reported(self) -> None:
        root = tree()
        write(root, "CHANGES.md", "the qualified toolchain is 1.95.0.\n")
        self.assertTrue(any("CHANGES.md" in p for p in module.check(root)))


if __name__ == "__main__":
    unittest.main()
