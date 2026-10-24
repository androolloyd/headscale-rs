#!/usr/bin/env python3
"""Convert pinned Go Unicode 15 source tables into private Rust implementation data.

This is source conversion, not a behavior probe. It runs no Go/Rust code and
accepts only the three exact input artifacts below. No network or dependencies.
"""

import hashlib
from pathlib import Path
import re

ROOT = Path.home() / "go/pkg/mod"
INPUTS = {
    "idna": (ROOT / "golang.org/x/net@v0.56.0/idna/tables15.0.0.go", "79fb7af83a29255478a5e56fdc8d176276ccdb4d1ff1b1459646cbf8d52cc5f3"),
    "norm": (ROOT / "golang.org/x/text@v0.38.0/unicode/norm/tables15.0.0.go", "49dda94f9429bac8c29efe11e09558d46abfaa3c8e1de59816f2910b99cade04"),
    "bidi": (ROOT / "golang.org/x/text@v0.38.0/unicode/bidi/tables15.0.0.go", "98c2d6d57e116667e73a4f5c89ee20ead7b27b50d561b5c5d23d8ebf0e3f3310"),
}


def without_comments(source):
    return re.sub(r"//[^\n]*", "", source)


def array(source, name, sparse=False):
    match = re.search(r"\bvar " + name + r" = \[([^]]*)\]\w+\{", source)
    if match is None:
        raise ValueError("missing array " + name)
    pos, depth = match.end(), 1
    end = pos
    while depth:
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
        end += 1
    body = without_comments(source[pos:end - 1])
    if sparse:
        result = []
        for entry in re.findall(r"\{([^{}]*)\}", body):
            fields = dict(re.findall(r"(value|lo|hi):\s*(0x[0-9a-fA-F]+|\d+)", entry))
            result.append(tuple(int(fields.get(key, "0"), 0) for key in ("value", "lo", "hi")))
        if len(result) != int(match[1]):
            raise ValueError("sparse declaration size " + name)
        return result
    tokens = re.findall(r"0x[0-9a-fA-F]+|\d+|[:,]", body)
    result = [0] * (int(match[1]) if match[1].isdigit() else 0)
    index = 0
    pos = 0
    while pos < len(tokens):
        value = int(tokens[pos], 0)
        pos += 1
        if pos < len(tokens) and tokens[pos] == ":":
            index = value
            value = int(tokens[pos + 1], 0)
            pos += 2
        if index >= len(result):
            result.extend([0] * (index + 1 - len(result)))
        result[index] = value
        index += 1
        if pos < len(tokens):
            if tokens[pos] != ",":
                raise ValueError("unexpected array token " + name)
            pos += 1
    if match[1].isdigit() and len(result) != int(match[1]):
        raise ValueError("array declaration size " + name)
    return result


def string_bytes(source, name):
    match = re.search(r"\b(?:var|const) " + name + r"(?: string)? = ", source)
    if match is None:
        raise ValueError("missing string " + name)
    pos = match.end()
    result = bytearray()
    while True:
        # Comments occur only outside literals in these generated declarations.
        while True:
            pos += len(source[pos:]) - len(source[pos:].lstrip())
            if source.startswith("//", pos):
                pos = source.index("\n", pos)
            else:
                break
        if source[pos] != '"':
            raise ValueError("expected string " + name)
        pos += 1
        while source[pos] != '"':
            ch = source[pos]
            pos += 1
            if ch != "\\":
                result.extend(ch.encode("utf-8"))
                continue
            escape = source[pos]
            pos += 1
            single = {"a": 7, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9, "v": 11, "\\": 92, '"': 34}
            if escape in single:
                result.append(single[escape])
            elif escape in "xuU":
                width = {"x": 2, "u": 4, "U": 8}[escape]
                value = int(source[pos:pos + width], 16)
                pos += width
                if escape == "x":
                    result.append(value)
                else:
                    result.extend(chr(value).encode("utf-8"))
            elif escape in "01234567":
                result.append(int(escape + source[pos:pos + 2], 8))
                pos += 2
            else:
                raise ValueError("unknown Go escape " + escape)
        pos += 1
        # Every continuation '+' appears before an optional line comment.
        pos += len(source[pos:]) - len(source[pos:].lstrip(" \t"))
        if source[pos:pos + 1] != "+":
            return list(result)
        pos += 1


def emit(name, ty, values):
    out = ["pub(super) const " + name + ": &[" + ty + "] = &[\n"]
    width = 8 if ty != "(u16, u8, u8)" else 3
    for start in range(0, len(values), width):
        row = values[start:start + width]
        render = lambda value: ("(" + ", ".join(hex(n) for n in value) + ")") if isinstance(value, tuple) else hex(value)
        out.append("    " + ", ".join(render(v) for v in row) + ",\n")
    out.append("];\n\n")
    return "".join(out)


def main():
    sources = {}
    header = ["// Copyright 2011, 2016 The Go Authors. All rights reserved.\n",
              "// Generated source conversion by convert_go15.py; see LICENSE-GO-STDLIB.\n",
              "// Selected Go 1.26.9 (!go1.27), Unicode 15.0.0. No Unicode data regeneration.\n"]
    for key, (path, digest) in INPUTS.items():
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError("pinned source hash changed: " + str(path))
        sources[key] = raw.decode("utf-8")
        header.append("// " + key + " source SHA-256: " + digest + "\n")
    out = ["".join(header), "\n"]
    arrays = {
        "idna": [("mappingIndex", "MAPPING_INDEX", "u16"), ("idnaValues", "IDNA_VALUES", "u16"), ("idnaIndex", "IDNA_INDEX", "u16"), ("idnaSparseOffset", "IDNA_SPARSE_OFFSET", "u16"), ("idnaSparseValues", "IDNA_SPARSE_VALUES", "(u16, u8, u8)")],
        "norm": [("decomps", "DECOMPS", "u8"), ("nfcValues", "NFC_VALUES", "u16"), ("nfcIndex", "NFC_INDEX", "u8"), ("nfcSparseOffset", "NFC_SPARSE_OFFSET", "u16"), ("nfcSparseValues", "NFC_SPARSE_VALUES", "(u16, u8, u8)")],
        "bidi": [("bidiValues", "BIDI_VALUES", "u8"), ("bidiIndex", "BIDI_INDEX", "u16")],
    }
    for key, declarations in arrays.items():
        for go_name, rust_name, ty in declarations:
            out.append(emit(rust_name, ty, array(sources[key], go_name, ty.startswith("("))))
    for go_name, rust_name in [("mappings", "MAPPINGS"), ("xorData", "XOR_DATA")]:
        out.append(emit(rust_name, "u8", string_bytes(sources["idna"], go_name)))
    packed = bytes(string_bytes(sources["norm"], "recompMapPacked"))
    if len(packed) % 8:
        raise ValueError("recomposition entry width")
    # Go builds a map in source order. Preserve last-value semantics, then
    # sort its keys for a dependency-free static binary search in Rust.
    recomp = {int.from_bytes(packed[i:i + 4], "big"): int.from_bytes(packed[i + 4:i + 8], "big") for i in range(0, len(packed), 8)}
    out.append(emit("RECOMPOSE", "(u32, u32)", sorted(recomp.items())))
    Path(__file__).with_name("data.rs").write_text("".join(out), encoding="utf-8")


if __name__ == "__main__":
    main()
