#!/usr/bin/env python3
"""Check that every crate under vendor/ is its pristine crates.io source plus a
reviewed, recorded set of local changes.

Why this exists
---------------
The root Cargo.toml redirects eleven registry crates to the local copies under
vendor/ with `[patch.crates-io]` path entries. `cargo deny`'s `[sources]` check
(`deny.toml` allows crates.io only) cannot see path patches, and Cargo.lock
carries no checksum for them, so nothing else notices if a vendored file drifts
from upstream or a new unreviewed change slips in. This script closes that gap.

What it verifies
----------------
For each vendor/<dir> (the package name and version come from its Cargo.toml):

1. The pristine archive https://static.crates.io/crates/<name>/<name>-<ver>.crate
   is fetched (or read from the cache) and its SHA-256 must equal, all at once:
   the crates.io sparse-index `cksum` for that version, the `archive_sha256`
   committed in vendor/PATCHES.json, and (when UPSTREAM.md states archive
   SHA-256 values) one of the archive hashes UPSTREAM.md states.
2. The vendored tree is compared file by file with the pristine tree. Every
   difference (file modified / added / removed) must appear in
   vendor/PATCHES.json with the SHA-256 of the vendored file. An unrecorded
   difference, a recorded difference that no longer exists, a recorded file whose
   content changed since it was recorded, or a version/archive mismatch fails.
3. If vendor/<dir>/LOCAL.patch exists it is applied (pure-Python unified-diff
   applier) to the pristine files and the result must reproduce the vendored
   files the patch touches. Files that differ from upstream but are not covered
   by the patch (UPSTREAM.md, SOURCE_SHA256SUMS, extra LICENSE files, ...) are
   only counted. Mismatches are reported as warnings by default and fail with
   --strict-patch.
4. Wiring: every `[patch.crates-io]` entry in the root Cargo.toml points at a
   vendor/ directory covered by the manifest (and vice versa), every
   `workspace.exclude` entry under vendor/ is covered, and every Cargo.lock
   package without a registry `source` is a first-party crate or a vendored
   crate at exactly the vendored version. A path override outside vendor/ is an
   error.

Normalisations (the full list - nothing else is ignored)
-------------------------------------------------------
* `.cargo-ok` at the root of a vendored crate is Cargo's registry-cache marker;
  it is not part of any .crate archive and is ignored.
* `.cargo_vcs_info.json` *is* part of the archive and is compared like any file.
* File modes (executable bit) and timestamps are not compared.
* Vendored files are taken from `git ls-files` when the repository root is a git
  checkout (so build leftovers such as vendor/*/target or a stray Cargo.lock do
  not count - `git add` a new vendored file before checking locally), otherwise
  from a directory walk. Use --walk to force the walk.

Usage
-----
    scripts/check_vendor_provenance.py                 # verify (needs network)
    scripts/check_vendor_provenance.py --list          # summarise the manifest
    scripts/check_vendor_provenance.py --update        # regenerate the manifest
    scripts/check_vendor_provenance.py --registry-src ~/.cargo/registry/src
                                                       # offline: use cargo's cache

Environment: VENDOR_PROVENANCE_CACHE selects the archive cache directory
(default: <repo>/target/vendor-provenance).

Exit status: 0 verified, 1 provenance violation, 2 could not verify (network
failure, malformed manifest, ...).
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST_NAME = "PATCHES.json"
SCHEMA = 1
IGNORED_ROOT_FILES = frozenset({".cargo-ok"})
USER_AGENT = "headscale-rs-vendor-provenance (+https://github.com/androolloyd/headscale-rs)"
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
HEX64 = re.compile(r"\b[0-9a-f]{64}\b")
# "archive ... SHA-256 `hex`" / "archive checksum is `hex`" / "Archive SHA-256:\n`hex`"
UPSTREAM_ARCHIVE_HASH = re.compile(
    r"archive[^`]{0,120}?(?:sha-?256|checksum)[^`0-9a-f]{0,40}`?(?P<hex>[0-9a-f]{64})`?",
    re.IGNORECASE | re.DOTALL,
)


class ProvenanceError(Exception):
    """Operational failure: the check could not be carried out (exit 2)."""


# --------------------------------------------------------------------------
# Hashing and trees
# --------------------------------------------------------------------------


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_path(path: pathlib.Path) -> str:
    if path.is_symlink():
        return sha256_bytes(b"symlink:" + os.readlink(path).encode())
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_toplevel(root: pathlib.Path) -> pathlib.Path | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    return pathlib.Path(out).resolve() if out else None


def list_tree(
    base: pathlib.Path,
    *,
    repo_root: pathlib.Path | None = None,
    use_git: bool = False,
) -> dict[str, str]:
    """Map relative POSIX path -> sha256 of every file under `base`."""
    files: dict[str, str] = {}
    if use_git and repo_root is not None:
        rel_base = base.resolve().relative_to(repo_root.resolve()).as_posix()
        raw = subprocess.run(
            ["git", "-C", str(repo_root), "ls-files", "-z", "--", rel_base],
            capture_output=True,
            check=True,
        ).stdout
        for item in raw.split(b"\0"):
            if not item:
                continue
            rel = os.fsdecode(item)[len(rel_base) + 1 :]
            path = base / rel
            if rel in IGNORED_ROOT_FILES or not (path.is_file() or path.is_symlink()):
                continue
            files[rel] = sha256_path(path)
        return files
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames.sort()
        for name in sorted(filenames) + [d for d in dirnames if (pathlib.Path(dirpath) / d).is_symlink()]:
            path = pathlib.Path(dirpath) / name
            rel = path.relative_to(base).as_posix()
            if rel in IGNORED_ROOT_FILES:
                continue
            files[rel] = sha256_path(path)
    return files


# --------------------------------------------------------------------------
# Pristine sources
# --------------------------------------------------------------------------


@dataclass
class Pristine:
    tree: pathlib.Path
    archive_sha256: str | None  # None when only an extracted copy was available
    origin: str


def index_path(name: str) -> str:
    lower = name.lower()
    if len(lower) == 1:
        return f"1/{lower}"
    if len(lower) == 2:
        return f"2/{lower}"
    if len(lower) == 3:
        return f"3/{lower[0]}/{lower}"
    return f"{lower[:2]}/{lower[2:4]}/{lower}"


def http_get(url: str, *, attempts: int = 4) -> bytes:
    last: Exception | None = None
    for attempt in range(attempts):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(request, timeout=60) as response:
                data = response.read(MAX_ARCHIVE_BYTES + 1)
            if len(data) > MAX_ARCHIVE_BYTES:
                raise ProvenanceError(f"{url} is larger than {MAX_ARCHIVE_BYTES} bytes")
            return data
        except (urllib.error.URLError, TimeoutError, ConnectionError) as err:
            last = err
            time.sleep(1.5 * (attempt + 1))
    raise ProvenanceError(f"cannot fetch {url}: {last}")


def fetch_index_cksum(name: str, version: str) -> str:
    """The crates.io sparse-index checksum of one released version."""
    body = http_get(f"https://index.crates.io/{index_path(name)}").decode()
    for line in body.splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        if entry.get("name", "").lower() == name.lower() and entry.get("vers") == version:
            return entry["cksum"]
    raise ProvenanceError(f"crates.io index has no {name} {version}")


def safe_extract(archive: bytes, destination: pathlib.Path, prefix: str) -> None:
    """Extract a .crate tarball (top directory `prefix`) without trusting it."""
    root = destination.resolve()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        for member in tar:
            name = member.name
            if not name.startswith(prefix + "/"):
                raise ProvenanceError(f"archive member {name!r} is outside {prefix}/")
            rel = name[len(prefix) + 1 :]
            target = (root / rel).resolve()
            if root != target and root not in target.parents:
                raise ProvenanceError(f"archive member {name!r} escapes the extraction root")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isreg():
                target.parent.mkdir(parents=True, exist_ok=True)
                handle = tar.extractfile(member)
                assert handle is not None
                target.write_bytes(handle.read())
            elif member.issym():
                target.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(member.linkname, target)
            else:
                raise ProvenanceError(f"archive member {name!r} has unsupported type")


class PristineProvider:
    """Obtain pristine crate sources: cache, then (unless offline) crates.io."""

    def __init__(
        self,
        cache_dir: pathlib.Path,
        workdir: pathlib.Path,
        *,
        offline: bool = False,
        registry_src: pathlib.Path | None = None,
        fetch_archive: Callable[[str, str], bytes] | None = None,
    ) -> None:
        self.cache_dir = cache_dir
        self.workdir = workdir
        self.offline = offline
        self.registry_src = registry_src
        self._fetch_archive = fetch_archive or self._download

    @staticmethod
    def _download(name: str, version: str) -> bytes:
        return http_get(f"https://static.crates.io/crates/{name}/{name}-{version}.crate")

    def _find_registry(self, name: str, version: str) -> tuple[pathlib.Path | None, pathlib.Path | None]:
        if self.registry_src is None:
            return None, None
        wanted = f"{name}-{version}"
        candidates = [self.registry_src / wanted]
        candidates += sorted(self.registry_src.glob(f"*/{wanted}"))
        for src in candidates:
            if not src.is_dir():
                continue
            # ~/.cargo/registry/src/<index>/<crate>  <->  registry/cache/<index>/<crate>.crate
            crate_file = src.parent.parent.parent / "cache" / src.parent.name / f"{wanted}.crate"
            return src, crate_file if crate_file.is_file() else None
        return None, None

    def get(self, name: str, version: str, expected_sha: str | None) -> Pristine:
        wanted = f"{name}-{version}"
        archive: bytes | None = None
        origin = ""

        src_dir, registry_crate = self._find_registry(name, version)
        if registry_crate is not None:
            archive, origin = registry_crate.read_bytes(), f"cargo registry cache {registry_crate}"
        elif src_dir is not None:
            return Pristine(src_dir, None, f"extracted registry copy {src_dir} (archive not verified)")

        cached = self.cache_dir / f"{wanted}.crate"
        if archive is None and cached.is_file():
            data = cached.read_bytes()
            if expected_sha is None or sha256_bytes(data) == expected_sha:
                archive, origin = data, f"cache {cached}"
        if archive is None:
            if self.offline:
                raise ProvenanceError(
                    f"{wanted}.crate is not in {self.cache_dir} and --offline was given"
                )
            archive, origin = self._fetch_archive(name, version), "static.crates.io"
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            cached.write_bytes(archive)

        destination = self.workdir / wanted
        if destination.exists():
            shutil.rmtree(destination)
        destination.mkdir(parents=True)
        safe_extract(archive, destination, wanted)
        return Pristine(destination, sha256_bytes(archive), origin)


def upstream_md_archive_hashes(text: str) -> set[str]:
    return {m.group("hex") for m in UPSTREAM_ARCHIVE_HASH.finditer(text)}


# --------------------------------------------------------------------------
# Tree comparison
# --------------------------------------------------------------------------


def diff_trees(
    pristine: dict[str, str], vendored: dict[str, str]
) -> dict[str, dict[str, str]]:
    """Per-path difference record between pristine and vendored hash maps."""
    out: dict[str, dict[str, str]] = {}
    for path in sorted(set(pristine) | set(vendored)):
        up, ours = pristine.get(path), vendored.get(path)
        if up == ours:
            continue
        if up is None:
            out[path] = {"status": "added", "sha256": ours}  # type: ignore[dict-item]
        elif ours is None:
            out[path] = {"status": "removed", "upstream_sha256": up}
        else:
            out[path] = {"status": "modified", "sha256": ours, "upstream_sha256": up}
    return out


# --------------------------------------------------------------------------
# LOCAL.patch reproduction (unified diff, stdlib only)
# --------------------------------------------------------------------------


@dataclass
class Hunk:
    old_start: int
    old: list[bytes] = field(default_factory=list)
    new: list[bytes] = field(default_factory=list)


@dataclass
class FilePatch:
    old_path: str | None  # None for /dev/null
    new_path: str | None
    hunks: list[Hunk] = field(default_factory=list)


HUNK_HEADER = re.compile(rb"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def parse_unified_diff(data: bytes) -> list[FilePatch]:
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    patches: list[FilePatch] = []
    i = 0
    while i < len(lines):
        if lines[i].startswith(b"--- ") and i + 1 < len(lines) and lines[i + 1].startswith(b"+++ "):
            old = lines[i][4:].split(b"\t")[0].decode()
            new = lines[i + 1][4:].split(b"\t")[0].decode()
            patch = FilePatch(None if old == "/dev/null" else old, None if new == "/dev/null" else new)
            i += 2
            while i < len(lines):
                header = HUNK_HEADER.match(lines[i])
                if not header:
                    break
                old_len = int(header.group(2)) if header.group(2) is not None else 1
                new_len = int(header.group(4)) if header.group(4) is not None else 1
                hunk = Hunk(int(header.group(1)))
                i += 1
                seen_old = seen_new = 0
                last: list[list[bytes]] = []
                while i < len(lines):
                    line = lines[i]
                    if line.startswith(b"\\"):
                        # "\ No newline at end of file" applies to the previous line
                        for side in last:
                            if side and side[-1].endswith(b"\n"):
                                side[-1] = side[-1][:-1]
                        i += 1
                        continue
                    if seen_old >= old_len and seen_new >= new_len:
                        break
                    tag, body = line[:1], line[1:] + b"\n"
                    if tag == b"":  # context line whose single space was stripped
                        tag, body = b" ", b"\n"
                    if tag == b" ":
                        hunk.old.append(body)
                        hunk.new.append(body)
                        seen_old += 1
                        seen_new += 1
                        last = [hunk.old, hunk.new]
                    elif tag == b"-":
                        hunk.old.append(body)
                        seen_old += 1
                        last = [hunk.old]
                    elif tag == b"+":
                        hunk.new.append(body)
                        seen_new += 1
                        last = [hunk.new]
                    else:
                        raise ProvenanceError(f"unexpected diff line {line[:60]!r}")
                    i += 1
                patch.hunks.append(hunk)
            patches.append(patch)
        else:
            i += 1
    return patches


def apply_hunks(original: bytes | None, hunks: list[Hunk], label: str) -> bytes:
    lines = original.splitlines(keepends=True) if original else []
    offset = 0
    for hunk in hunks:
        want = hunk.old
        base = hunk.old_start - 1 + offset if want else hunk.old_start + offset
        pos = None
        for shift in sorted(range(-400, 401), key=abs):
            cand = base + shift
            if 0 <= cand <= len(lines) and lines[cand : cand + len(want)] == want:
                pos = cand
                break
        if pos is None:
            raise ProvenanceError(f"{label}: hunk at line {hunk.old_start} does not apply")
        lines[pos : pos + len(want)] = hunk.new
        offset += len(hunk.new) - len(want) + (pos - base)
    return b"".join(lines)


def reproduce_local_patch(
    patch_bytes: bytes, crate_dir: str, pristine_tree: pathlib.Path
) -> dict[str, bytes | None]:
    """Apply LOCAL.patch to pristine files. Returns path -> new bytes (None = deleted)."""
    result: dict[str, bytes | None] = {}
    marker = f"vendor/{crate_dir}/"

    def rel(path: str) -> str:
        idx = path.find(marker)
        if idx < 0:
            raise ProvenanceError(f"LOCAL.patch path {path!r} is not under {marker}")
        return path[idx + len(marker) :]

    for patch in parse_unified_diff(patch_bytes):
        target = rel(patch.new_path or patch.old_path or "")
        source = pristine_tree / rel(patch.old_path) if patch.old_path else None
        original = source.read_bytes() if source is not None and source.is_file() else None
        if patch.old_path and original is None:
            raise ProvenanceError(f"LOCAL.patch modifies {target}, which pristine upstream lacks")
        updated = apply_hunks(original, patch.hunks, target)
        result[target] = None if patch.new_path is None else updated
    return result


# --------------------------------------------------------------------------
# Manifest handling
# --------------------------------------------------------------------------


@dataclass
class CrateInfo:
    dir: str
    name: str
    version: str


def discover_vendor_crates(vendor_dir: pathlib.Path) -> dict[str, CrateInfo]:
    crates: dict[str, CrateInfo] = {}
    for child in sorted(vendor_dir.iterdir()):
        manifest = child / "Cargo.toml"
        if not child.is_dir() or not manifest.is_file():
            continue
        package = tomllib.loads(manifest.read_text(encoding="utf-8")).get("package", {})
        crates[child.name] = CrateInfo(child.name, package["name"], package["version"])
    return crates


def load_manifest(path: pathlib.Path) -> dict:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as err:
        raise ProvenanceError(f"{path} is missing; create it with --update") from err
    except json.JSONDecodeError as err:
        raise ProvenanceError(f"{path} is not valid JSON: {err}") from err
    if manifest.get("schema") != SCHEMA or not isinstance(manifest.get("crates"), dict):
        raise ProvenanceError(f"{path} does not follow schema {SCHEMA}")
    return manifest


def dump_manifest(manifest: dict) -> str:
    return json.dumps(manifest, indent=2, sort_keys=True) + "\n"


# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------


@dataclass
class CrateResult:
    info: CrateInfo
    pristine: Pristine | None = None
    actual: dict[str, dict[str, str]] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)
    archive_problems: list[str] = field(default_factory=list)  # fatal even for --update
    warnings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    index_cksum: str | None = None


def analyse_crate(
    info: CrateInfo,
    repo_root: pathlib.Path,
    provider: PristineProvider,
    recorded: dict | None,
    *,
    use_git: bool,
    index_lookup: Callable[[str, str], str] | None,
    check_patch: bool,
) -> CrateResult:
    result = CrateResult(info)
    vendor_path = repo_root / "vendor" / info.dir
    recorded_sha = (recorded or {}).get("upstream", {}).get("archive_sha256")

    result.pristine = provider.get(info.name, info.version, recorded_sha)
    pristine = result.pristine
    pristine_hashes = list_tree(pristine.tree)
    vendored_hashes = list_tree(vendor_path, repo_root=repo_root, use_git=use_git)
    result.actual = diff_trees(pristine_hashes, vendored_hashes)

    # ---- archive checksum agreement -------------------------------------
    if pristine.archive_sha256 is None:
        result.notes.append(pristine.origin)
    else:
        if index_lookup is not None:
            result.index_cksum = index_lookup(info.name, info.version)
            if result.index_cksum != pristine.archive_sha256:
                result.archive_problems.append(
                    f"archive sha256 {pristine.archive_sha256} does not match the crates.io "
                    f"index checksum {result.index_cksum}"
                )
        else:
            result.notes.append("crates.io index checksum not consulted (offline)")
        if recorded_sha is not None and recorded_sha != pristine.archive_sha256:
            result.problems.append(
                f"archive sha256 {pristine.archive_sha256} does not match "
                f"vendor/{MANIFEST_NAME} ({recorded_sha})"
            )
        upstream_md = vendor_path / "UPSTREAM.md"
        if upstream_md.is_file():
            stated = upstream_md_archive_hashes(upstream_md.read_text(encoding="utf-8", errors="replace"))
            if stated and pristine.archive_sha256 not in stated:
                result.archive_problems.append(
                    f"archive sha256 {pristine.archive_sha256} is not among the archive hashes "
                    f"stated in vendor/{info.dir}/UPSTREAM.md ({', '.join(sorted(stated))})"
                )

    # ---- LOCAL.patch reproduction ---------------------------------------
    local_patch = vendor_path / "LOCAL.patch"
    if check_patch and local_patch.is_file():
        try:
            reproduced = reproduce_local_patch(local_patch.read_bytes(), info.dir, pristine.tree)
        except ProvenanceError as err:
            result.warnings.append(f"LOCAL.patch could not be applied to pristine: {err}")
        else:
            mismatched = []
            for path, content in sorted(reproduced.items()):
                ours = vendored_hashes.get(path)
                want = None if content is None else sha256_bytes(content)
                if ours != want:
                    mismatched.append(path)
            uncovered = sorted(set(result.actual) - set(reproduced))
            result.notes.append(
                f"LOCAL.patch reproduces {len(reproduced) - len(mismatched)} of {len(reproduced)} "
                f"touched files; {len(uncovered)} differing files are outside the patch "
                f"({', '.join(uncovered[:6])}{', ...' if len(uncovered) > 6 else ''})"
            )
            if mismatched:
                result.warnings.append(
                    "LOCAL.patch does not reproduce the vendored file(s): " + ", ".join(mismatched)
                )

    # ---- manifest comparison -------------------------------------------
    if recorded is None:
        result.problems.append("not listed in the manifest (run --update and review the result)")
        return result
    upstream = recorded.get("upstream", {})
    if upstream.get("name") != info.name or upstream.get("version") != info.version:
        result.problems.append(
            f"vendored Cargo.toml says {info.name} {info.version} but the manifest records "
            f"{upstream.get('name')} {upstream.get('version')}"
        )
    files = recorded.get("files", {})
    for path, entry in result.actual.items():
        if path not in files:
            result.problems.append(f"unrecorded {entry['status']} file: {path}")
            continue
        want = files[path]
        if want.get("status") != entry["status"]:
            result.problems.append(
                f"{path}: recorded as {want.get('status')} but is now {entry['status']}"
            )
        elif want.get("sha256") != entry.get("sha256"):
            result.problems.append(
                f"{path}: content changed since it was recorded "
                f"(recorded {want.get('sha256')}, now {entry.get('sha256')})"
            )
        elif entry["status"] != "added" and want.get("upstream_sha256") != entry.get("upstream_sha256"):
            result.problems.append(f"{path}: pristine upstream content differs from the recorded one")
    for path, want in files.items():
        if path not in result.actual:
            result.problems.append(
                f"stale manifest entry: {path} is recorded as {want.get('status')} but now matches upstream"
            )
    return result


def build_manifest_entry(result: CrateResult) -> dict:
    sha = result.pristine.archive_sha256 if result.pristine else None
    if sha is None:
        raise ProvenanceError(
            f"cannot record {result.info.name} {result.info.version}: no archive checksum "
            "(an extracted registry copy was used and no cargo registry cache .crate was found)"
        )
    return {
        "dir": f"vendor/{result.info.dir}",
        "upstream": {
            "name": result.info.name,
            "version": result.info.version,
            "registry": "crates.io",
            "archive_sha256": sha,
        },
        "files": dict(sorted(result.actual.items())),
    }


# --------------------------------------------------------------------------
# Wiring checks (Cargo.toml / Cargo.lock)
# --------------------------------------------------------------------------


def first_party_packages(repo_root: pathlib.Path) -> set[str]:
    names: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(repo_root):
        dirnames[:] = [d for d in dirnames if d not in {".git", "target", "node_modules", "vendor"}]
        if "Cargo.toml" in filenames:
            try:
                data = tomllib.loads((pathlib.Path(dirpath) / "Cargo.toml").read_text(encoding="utf-8"))
            except tomllib.TOMLDecodeError:
                continue
            if "package" in data:
                names.add(data["package"]["name"])
    return names


def lock_files(repo_root: pathlib.Path) -> list[pathlib.Path]:
    found = []
    for dirpath, dirnames, filenames in os.walk(repo_root):
        dirnames[:] = [d for d in dirnames if d not in {".git", "target", "node_modules", "vendor"}]
        if "Cargo.lock" in filenames:
            found.append(pathlib.Path(dirpath) / "Cargo.lock")
    return sorted(found)


def check_wiring(repo_root: pathlib.Path, vendor_crates: dict[str, CrateInfo], manifest_dirs: set[str]) -> list[str]:
    problems: list[str] = []
    covered = {f"vendor/{d}" for d in manifest_dirs}
    root_toml = tomllib.loads((repo_root / "Cargo.toml").read_text(encoding="utf-8"))

    patched: set[str] = set()
    for source, table in root_toml.get("patch", {}).items():
        for crate, spec in table.items():
            path = spec.get("path") if isinstance(spec, dict) else None
            if source != "crates-io" or path is None:
                problems.append(f"[patch.{source}] {crate} is not a crates.io path patch ({spec!r})")
                continue
            normalized = os.path.normpath(path).replace(os.sep, "/")
            if normalized not in covered:
                problems.append(f"[patch.crates-io] {crate} -> {path!r} is not a vendor/ crate covered by the manifest")
            else:
                patched.add(normalized)
    excluded = {
        os.path.normpath(e).replace(os.sep, "/")
        for e in root_toml.get("workspace", {}).get("exclude", [])
        if os.path.normpath(e).replace(os.sep, "/").startswith("vendor/")
    }
    for entry in sorted(covered - patched):
        problems.append(f"{entry} is in the manifest but has no [patch.crates-io] path entry in Cargo.toml")
    for entry in sorted(covered - excluded):
        problems.append(f"{entry} is not listed in workspace.exclude of the root Cargo.toml")
    for entry in sorted(excluded - covered):
        problems.append(f"workspace.exclude lists {entry}, which the manifest does not cover")
    for member in root_toml.get("workspace", {}).get("members", []):
        if os.path.normpath(member).startswith("vendor"):
            problems.append(f"workspace member {member!r} lives under vendor/")

    first_party = first_party_packages(repo_root)
    vendored_versions = {(c.name, c.version) for c in vendor_crates.values()}
    vendored_names = {c.name for c in vendor_crates.values()}
    for lock in lock_files(repo_root):
        label = lock.relative_to(repo_root).as_posix()
        try:
            data = tomllib.loads(lock.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as err:
            problems.append(f"{label} is not valid TOML: {err}")
            continue
        seen_vendored: set[tuple[str, str]] = set()
        for package in data.get("package", []):
            if "source" in package:
                continue
            ident = (package["name"], package["version"])
            if package["name"] in first_party:
                continue
            if ident in vendored_versions:
                seen_vendored.add(ident)
            elif package["name"] in vendored_names:
                problems.append(
                    f"{label}: {ident[0]} {ident[1]} has no registry source but is not the vendored version"
                )
            else:
                problems.append(f"{label}: package {ident[0]} {ident[1]} has no registry source and is neither first-party nor vendored")
        if label == "Cargo.lock":
            for ident in sorted(vendored_versions - seen_vendored):
                problems.append(f"{label}: no sourceless entry for vendored {ident[0]} {ident[1]} (patch not applied?)")
    return problems


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------


def summarise_files(files: dict) -> dict[str, int]:
    counts = {"modified": 0, "added": 0, "removed": 0}
    for entry in files.values():
        counts[entry["status"]] += 1
    return counts


def print_list(manifest: dict) -> None:
    print(f"{'crate':<16} {'version':<10} {'modified':>8} {'added':>6} {'removed':>7}  archive sha256")
    totals = {"modified": 0, "added": 0, "removed": 0}
    for key, crate in sorted(manifest["crates"].items()):
        counts = summarise_files(crate["files"])
        for k, v in counts.items():
            totals[k] += v
        up = crate["upstream"]
        print(
            f"{key:<16} {up['version']:<10} {counts['modified']:>8} {counts['added']:>6} "
            f"{counts['removed']:>7}  {up['archive_sha256'][:16]}..."
        )
    print(f"{'total':<16} {'':<10} {totals['modified']:>8} {totals['added']:>6} {totals['removed']:>7}")


def diff_manifests(old: dict, new: dict) -> list[str]:
    lines = []
    old_crates, new_crates = old.get("crates", {}), new["crates"]
    for key in sorted(set(old_crates) | set(new_crates)):
        if key not in new_crates:
            lines.append(f"- crate {key} removed")
            continue
        if key not in old_crates:
            lines.append(f"+ crate {key} added ({len(new_crates[key]['files'])} differing files)")
            continue
        o, n = old_crates[key], new_crates[key]
        if o["upstream"] != n["upstream"]:
            lines.append(f"~ {key}: upstream record changed {o['upstream']['version']} -> {n['upstream']['version']}")
        of, nf = o["files"], n["files"]
        for path in sorted(set(of) | set(nf)):
            if path not in nf:
                lines.append(f"- {key}/{path} (no longer differs from upstream)")
            elif path not in of:
                lines.append(f"+ {key}/{path} ({nf[path]['status']})")
            elif of[path] != nf[path]:
                lines.append(f"~ {key}/{path} ({nf[path]['status']}, content changed)")
    return lines


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--update", action="store_true", help="regenerate vendor/PATCHES.json from the current tree")
    mode.add_argument("--list", action="store_true", help="print a per-crate summary of vendor/PATCHES.json (no network)")
    parser.add_argument("--repo-root", type=pathlib.Path, default=REPO_ROOT)
    parser.add_argument("--crate", action="append", default=[], metavar="DIR", help="only check vendor/DIR (repeatable)")
    parser.add_argument("--cache-dir", type=pathlib.Path, default=None)
    parser.add_argument("--offline", action="store_true", help="never touch the network (cache / --registry-src only)")
    parser.add_argument("--registry-src", type=pathlib.Path, default=None, help="use cargo's registry src (and sibling cache) instead of downloading")
    parser.add_argument("--walk", action="store_true", help="walk the vendor directories instead of using git ls-files")
    parser.add_argument("--no-wiring", action="store_true", help="skip the Cargo.toml/Cargo.lock wiring checks")
    parser.add_argument("--no-patch-check", action="store_true", help="skip the LOCAL.patch reproduction check")
    parser.add_argument("--strict-patch", action="store_true", help="treat LOCAL.patch reproduction mismatches as failures")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args(argv)


def run(args: argparse.Namespace, provider_factory: Callable[..., PristineProvider] = PristineProvider,
        index_lookup: Callable[[str, str], str] | None = fetch_index_cksum) -> int:
    repo_root = args.repo_root.resolve()
    manifest_path = repo_root / "vendor" / MANIFEST_NAME

    if args.list:
        print_list(load_manifest(manifest_path))
        return 0

    vendor_crates = discover_vendor_crates(repo_root / "vendor")
    selected = {k: v for k, v in vendor_crates.items() if not args.crate or k in args.crate}
    unknown = sorted(set(args.crate) - set(vendor_crates))
    if unknown:
        raise ProvenanceError(f"no such vendor crate: {', '.join(unknown)}")

    manifest = None
    if manifest_path.exists() or not args.update:
        manifest = load_manifest(manifest_path)
    recorded_crates = (manifest or {}).get("crates", {})

    use_git = (not args.walk) and git_toplevel(repo_root) == repo_root
    cache_dir = args.cache_dir or pathlib.Path(
        os.environ.get("VENDOR_PROVENANCE_CACHE") or repo_root / "target" / "vendor-provenance"
    )
    lookup = None if (args.offline or args.registry_src) else index_lookup

    with tempfile.TemporaryDirectory(prefix="vendor-provenance-") as tmp:
        provider = provider_factory(
            cache_dir, pathlib.Path(tmp), offline=args.offline, registry_src=args.registry_src
        )
        results = [
            analyse_crate(
                info, repo_root, provider, recorded_crates.get(key),
                use_git=use_git, index_lookup=lookup, check_patch=not args.no_patch_check,
            )
            for key, info in selected.items()
            if args.update or key in recorded_crates  # uncovered dirs are reported below, unfetched
        ]

    if args.update:
        if args.crate:
            raise ProvenanceError("--update regenerates the whole manifest; do not combine it with --crate")
        for res in results:
            # archive-level problems (checksum disagreement) must not be baked into the manifest
            if res.archive_problems:
                raise ProvenanceError(f"{res.info.dir}: {'; '.join(res.archive_problems)}")
        new = {
            "schema": SCHEMA,
            "generated_by": "scripts/check_vendor_provenance.py --update",
            "notes": (
                "Each entry lists the files of vendor/<dir> that differ from the pristine crates.io "
                "archive named under 'upstream' (status + sha256 of the vendored file). Reviewed local "
                "changes only: regenerate with --update and review the diff of this file."
            ),
            "ignored_files": sorted(IGNORED_ROOT_FILES),
            "crates": {res.info.dir: build_manifest_entry(res) for res in results},
        }
        for line in diff_manifests(manifest or {}, new) or ["(no change)"]:
            print(line)
        manifest_path.write_text(dump_manifest(new), encoding="utf-8")
        print(f"wrote {manifest_path.relative_to(repo_root)}")
        print_list(new)
        return 0

    failed = False
    for res in results:
        problems = res.archive_problems + res.problems
        warnings = list(res.warnings)
        if args.strict_patch:
            problems += warnings
            warnings = []
        counts = summarise_files(res.actual)
        status = "FAIL" if problems else "ok"
        print(
            f"vendor/{res.info.dir} ({res.info.name} {res.info.version}): {status} - "
            f"{counts['modified']} modified, {counts['added']} added, {counts['removed']} removed vs upstream"
        )
        if args.verbose and res.pristine:
            print(f"    pristine source: {res.pristine.origin}")
        for note in res.notes:
            if args.verbose or "not verified" in note or "not consulted" in note:
                print(f"    note: {note}")
        for warning in warnings:
            print(f"    warning: {warning}")
            if os.environ.get("GITHUB_ACTIONS"):
                print(f"::warning title=vendor/{res.info.dir}::{warning}")
        for problem in problems:
            print(f"    ERROR: {problem}")
        failed |= bool(problems)

    manifest_only = sorted(set(recorded_crates) - set(vendor_crates))
    wiring: list[str] = []
    for key in sorted(set(selected) - set(recorded_crates)):
        wiring.append(f"vendor/{key} is not covered by vendor/{MANIFEST_NAME}")
    if not args.crate:
        for key in manifest_only:
            wiring.append(f"manifest lists vendor/{key}, which does not exist")
        if not args.no_wiring:
            wiring += check_wiring(repo_root, vendor_crates, set(recorded_crates) & set(vendor_crates))
    for problem in wiring:
        print(f"ERROR: {problem}")
    failed |= bool(wiring)

    if failed:
        print(
            "\nvendor provenance check FAILED. If the change is intended, run\n"
            "  scripts/check_vendor_provenance.py --update\n"
            "review `git diff vendor/PATCHES.json`, and commit it with the vendor change.",
            file=sys.stderr,
        )
        return 1
    print(f"vendor provenance verified for {len(results)} crate(s)")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        return run(args)
    except ProvenanceError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
