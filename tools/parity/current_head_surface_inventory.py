#!/usr/bin/env python3
"""Inventory upstream headscale public surfaces against headscale-rs evidence.

This script intentionally uses only the Python standard library. It scans the
checked-out upstream Go module and the local Rust checkout for public routes,
HeadscaleService RPCs, Cobra/Clap command names and aliases, and integration
test names. The output is JSON so audit lanes can consume it directly.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


DEFAULT_UPSTREAM_ROOT = Path(
    os.environ.get(
        "HEADSCALE_GO_ROOT",
        "/Users/androolloyd/go/pkg/mod/github.com/juanfont/headscale@v0.29.0-beta.2",
    )
)
UPSTREAM_VERSION = "v0.29.0-beta.2"
UPSTREAM_COMMIT = "171fd7a3c54156965753a63639cdcafcd50c8d67"

GO_METHODS = {
    "Get": "GET",
    "Post": "POST",
    "Put": "PUT",
    "Delete": "DELETE",
    "Head": "HEAD",
    "Patch": "PATCH",
    "Handle": "ANY",
    "HandleFunc": "ANY",
}
AXUM_METHODS = {
    "get": "GET",
    "post": "POST",
    "put": "PUT",
    "delete": "DELETE",
    "head": "HEAD",
    "patch": "PATCH",
    "any": "ANY",
}
PROTO_HTTP_METHODS = {"get", "post", "put", "delete", "patch"}


def rel_ref(root: Path, path: Path, line: int) -> str:
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = path
    return f"{rel}:{line}"


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def iter_files(root: Path, *parts: str, suffixes: tuple[str, ...]) -> list[Path]:
    base = root.joinpath(*parts)
    if not base.exists():
        return []
    return sorted(path for path in base.rglob("*") if path.suffix in suffixes)


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def canonical_path(path: str) -> str:
    path = re.sub(r"\{[^}/]+\}", "{param}", path)
    path = re.sub(r":[^/]+", "{param}", path)
    return path.rstrip("/") or "/"


def split_use_name(use: str) -> str:
    return use.strip().split()[0] if use.strip() else use.strip()


def slug(value: str) -> str:
    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-") or "item"


def camel_to_snake(name: str) -> str:
    s1 = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


def kebab_case(name: str) -> str:
    s1 = re.sub("(.)([A-Z][a-z]+)", r"\1-\2", name)
    return re.sub("([a-z0-9])([A-Z])", r"\1-\2", s1).lower()


def normalize_name(name: str) -> str:
    name = re.sub(r"^test", "", name, flags=re.IGNORECASE)
    return re.sub(r"[^a-z0-9]+", "", kebab_case(name).lower())


def find_source_hits(root: Path, pattern: str, suffixes: tuple[str, ...]) -> list[str]:
    regex = re.compile(pattern)
    hits: list[str] = []
    for path in iter_files(root, suffixes=suffixes):
        text = read_text(path)
        for match in regex.finditer(text):
            hits.append(rel_ref(root, path, line_number(text, match.start())))
    return hits


def git_ref(root: Path, ref: str = "HEAD") -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", ref],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def load_go_string_consts(upstream_root: Path) -> dict[str, str]:
    consts: dict[str, str] = {}
    for path in iter_files(upstream_root, suffixes=(".go",)):
        for line in read_text(path).splitlines():
            match = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\"([^\"]*)\"", line)
            if match:
                consts[match.group(1)] = match.group(2)
    return consts


def resolve_go_expr(expr: str, consts: dict[str, str]) -> str:
    expr = expr.strip()
    if expr.startswith('"') and expr.endswith('"'):
        return expr[1:-1]
    return consts.get(expr, expr)


def split_go_args(args: str) -> list[str]:
    values: list[str] = []
    current: list[str] = []
    in_string = False
    escape = False
    for char in args:
        if in_string:
            current.append(char)
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
            current.append(char)
            continue
        if char == ",":
            value = "".join(current).strip()
            if value:
                values.append(value)
            current = []
            continue
        current.append(char)
    value = "".join(current).strip()
    if value:
        values.append(value)
    return values


def brace_block(text: str, open_brace: int) -> tuple[str, int]:
    depth = 0
    in_string: str | None = None
    escape = False
    for index in range(open_brace, len(text)):
        char = text[index]
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == in_string:
                in_string = None
            continue
        if char in {'"', "`"}:
            in_string = char
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace + 1 : index], index + 1
    return text[open_brace + 1 :], len(text)


def paren_block(text: str, open_paren: int) -> tuple[str, int]:
    depth = 0
    in_string: str | None = None
    escape = False
    for index in range(open_paren, len(text)):
        char = text[index]
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == in_string:
                in_string = None
            continue
        if char in {'"', "`"}:
            in_string = char
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1 : index], index + 1
    return text[open_paren + 1 :], len(text)


def function_body(text: str, marker: str) -> tuple[str, int]:
    start = text.find(marker)
    if start < 0:
        return text, 0
    open_brace = text.find("{", start)
    if open_brace < 0:
        return text[start:], start
    body, end = brace_block(text, open_brace)
    return body, open_brace + 1


def direct_route_prefixes(text: str, consts: dict[str, str]) -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []
    for match in re.finditer(r"\br\.Route\(\s*([^,\n]+)", text):
        prefix = resolve_go_expr(match.group(1), consts)
        if not prefix.startswith("/"):
            continue
        open_paren = text.find("(", match.start())
        if open_paren < 0:
            continue
        _, end = paren_block(text, open_paren)
        spans.append((match.start(), end, prefix.rstrip("/")))
    return spans


def prefixed_path(path: str, offset: int, prefix_spans: list[tuple[int, int, str]]) -> str:
    prefixes = [prefix for start, end, prefix in prefix_spans if start < offset < end]
    if not prefixes:
        return path
    return "".join(prefixes) + path


def parse_upstream_direct_routes(upstream_root: Path, consts: dict[str, str]) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    scan_paths = [
        (upstream_root / "hscontrol" / "app.go", "func (h *Headscale) createRouter"),
        (upstream_root / "hscontrol" / "noise.go", "func (h *Headscale) NoiseUpgradeHandler"),
    ]
    pattern = re.compile(
        r"\br\.(Get|Post|Put|Delete|Head|Patch|Handle|HandleFunc)\(\s*([^,\n]+)",
        re.MULTILINE,
    )
    seen: set[tuple[str, str, str]] = set()
    for path, marker in scan_paths:
        if not path.exists():
            continue
        raw_text = read_text(path)
        text, base_offset = function_body(raw_text, marker)
        prefix_spans = direct_route_prefixes(text, consts)
        for match in pattern.finditer(text):
            method = GO_METHODS[match.group(1)]
            route_expr = match.group(2).strip()
            route_path = resolve_go_expr(route_expr, consts)
            if not route_path.startswith("/"):
                continue
            route_path = prefixed_path(route_path, match.start(), prefix_spans)
            line = line_number(raw_text, base_offset + match.start())
            key = (method, route_path, rel_ref(upstream_root, path, line))
            if key in seen:
                continue
            seen.add(key)
            routes.append(
                {
                    "surface": "control_http",
                    "method": method,
                    "path": route_path,
                    "canonical_path": canonical_path(route_path),
                    "source": rel_ref(upstream_root, path, line),
                }
            )
    return routes


def parse_proto_rpcs(upstream_root: Path) -> list[dict[str, Any]]:
    proto = upstream_root / "proto" / "headscale" / "v1" / "headscale.proto"
    if not proto.exists():
        return []
    raw_text = read_text(proto)
    text = "\n".join("" if line.lstrip().startswith("//") else line for line in raw_text.splitlines())
    rpcs: list[dict[str, Any]] = []
    service_match = re.search(r"\bservice\s+(\w+)\s*\{", text)
    service = service_match.group(1) if service_match else "unknown"
    rpc_pattern = re.compile(
        r"\brpc\s+(\w+)\s*\(([^)]*)\)\s*returns\s*\(([^)]*)\)\s*\{(.*?)\n\s*\}",
        re.DOTALL,
    )
    for match in rpc_pattern.finditer(text):
        name = match.group(1)
        body = match.group(4)
        http: dict[str, str] | None = None
        for method in PROTO_HTTP_METHODS:
            http_match = re.search(rf"\b{method}\s*:\s*\"([^\"]+)\"", body)
            if http_match:
                http = {
                    "method": method.upper(),
                    "path": http_match.group(1),
                    "canonical_path": canonical_path(http_match.group(1)),
                }
                break
        body_match = re.search(r"\bbody\s*:\s*\"([^\"]+)\"", body)
        if http and body_match:
            http["body"] = body_match.group(1)
        rpcs.append(
            {
                "service": service,
                "name": name,
                "rust_method": camel_to_snake(name),
                "request": match.group(2).strip(),
                "response": match.group(3).strip(),
                "http": http,
                "source": rel_ref(upstream_root, proto, line_number(text, match.start())),
            }
        )
    return rpcs


def proto_http_routes(rpcs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    for rpc in rpcs:
        http = rpc.get("http")
        if not http:
            continue
        routes.append(
            {
                "surface": "grpc_gateway",
                "method": http["method"],
                "path": http["path"],
                "canonical_path": http["canonical_path"],
                "rpc": rpc["name"],
                "source": rpc["source"],
            }
        )
    return routes


def parse_rust_routes(rust_root: Path) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for path in iter_files(rust_root / "headscale-api", "src", suffixes=(".rs",)) + iter_files(
        rust_root / "tools" / "real-client" / "headscale-rs-harness",
        "src",
        suffixes=(".rs",),
    ):
        text = read_text(path)
        for match in re.finditer(r"\.route\(\s*\"([^\"]+)\"", text):
            block, _ = paren_block(text, match.start() + len(".route"))
            methods = sorted({AXUM_METHODS[m] for m in re.findall(r"\b(get|post|put|delete|head|patch|any)\s*\(", block)})
            if not methods:
                methods = ["ANY"]
            route_path = match.group(1)
            line = line_number(text, match.start())
            for method in methods:
                key = (method, route_path, rel_ref(rust_root, path, line))
                if key in seen:
                    continue
                seen.add(key)
                routes.append(
                    {
                        "method": method,
                        "path": route_path,
                        "canonical_path": canonical_path(route_path),
                        "source": rel_ref(rust_root, path, line),
                    }
                )
        for match in re.finditer(r"\.fallback\(\s*basic_handlers::handle_fallback\s*\)", text):
            line = line_number(text, match.start())
            routes.append(
                {
                    "method": "GET",
                    "path": "/",
                    "canonical_path": "/",
                    "source": rel_ref(rust_root, path, line),
                    "note": "control-router fallback serves the upstream blank page for unmatched public paths",
                }
            )
    api_gateway_source = next((route["source"] for route in routes if route["path"] == "/api/*path"), None)
    if api_gateway_source is None:
        api_gateway_source = next((route["source"] for route in routes if route["path"].startswith("/api/v1/")), None)
    if api_gateway_source is not None:
        routes.append(
            {
                "method": "ANY",
                "path": "/api/v1/*",
                "canonical_path": "/api/v1/*",
                "source": api_gateway_source,
                "note": "Rust grpc-gateway exposes explicit /api/v1 routes plus an authenticated /api fallback",
            }
        )
    return routes


def compare_route(upstream_route: dict[str, Any], rust_route_index: dict[str, list[dict[str, Any]]]) -> tuple[str, list[str], str]:
    candidates = rust_route_index.get(upstream_route["canonical_path"], [])
    method = upstream_route["method"]
    matching = [
        route
        for route in candidates
        if route["method"] == method or route["method"] == "ANY" or method == "ANY"
    ]
    if matching:
        return "present", [route["source"] for route in matching], "matching Rust route path and method"
    if candidates:
        return (
            "needs-review",
            [route["source"] for route in candidates],
            "Rust has the path but no matching method was found by the source scanner",
        )
    return "missing", [], "no Rust route with this canonical path was found"


def parse_cobra_commands(upstream_root: Path, consts: dict[str, str]) -> list[dict[str, Any]]:
    cli_root = upstream_root / "cmd" / "headscale" / "cli"
    commands: dict[str, dict[str, Any]] = {}
    edges: dict[str, list[str]] = defaultdict(list)
    command_re = re.compile(r"\bvar\s+(\w+)\s*=\s*&cobra\.Command\s*\{")
    add_re = re.compile(r"\b(\w+)\.AddCommand\(([^)]*)\)")
    for path in iter_files(cli_root, suffixes=(".go",)):
        text = read_text(path)
        for match in command_re.finditer(text):
            var_name = match.group(1)
            open_brace = text.find("{", match.end() - 1)
            body, _ = brace_block(text, open_brace)
            use_match = re.search(r"\bUse\s*:\s*([^,\n]+)", body)
            if not use_match:
                continue
            use = resolve_go_expr(use_match.group(1), consts)
            aliases: list[str] = []
            aliases_match = re.search(r"\bAliases\s*:\s*\[\]string\s*\{([^}]*)\}", body)
            if aliases_match:
                aliases = [resolve_go_expr(value, consts) for value in split_go_args(aliases_match.group(1))]
            commands[var_name] = {
                "var": var_name,
                "name": split_use_name(use),
                "use": use,
                "aliases": aliases,
                "source": rel_ref(upstream_root, path, line_number(text, match.start())),
            }
        for match in add_re.finditer(text):
            parent = match.group(1)
            for child in split_go_args(match.group(2)):
                if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", child):
                    edges[parent].append(child)

    paths: list[dict[str, Any]] = []

    def walk(var_name: str, tokens: list[str], visited: set[str]) -> None:
        if var_name in visited or var_name not in commands:
            return
        visited = set(visited)
        visited.add(var_name)
        command = commands[var_name]
        path_tokens = tokens + [command["name"]]
        paths.append({**command, "path": path_tokens})
        for child in edges.get(var_name, []):
            walk(child, path_tokens, visited)

    if "rootCmd" in commands:
        walk("rootCmd", [], set())
    for var_name in sorted(commands):
        if not any(item["var"] == var_name for item in paths):
            walk(var_name, [], set())

    return [
        {
            **item,
            "path": " ".join(item["path"]),
            "path_tokens": item["path"],
        }
        for item in paths
    ]


def parse_rust_command_attrs(attr: str) -> tuple[str | None, list[str], bool]:
    name: str | None = None
    aliases: list[str] = []
    hidden = "hide = true" in attr
    for key, value in re.findall(r"\b(name|alias|visible_alias)\s*=\s*\"([^\"]+)\"", attr):
        if key == "name":
            name = value
        else:
            aliases.append(value)
    return name, aliases, hidden


def parse_rust_enum_commands(path: Path, rust_root: Path) -> dict[str, list[dict[str, Any]]]:
    text = read_text(path)
    enums: dict[str, list[dict[str, Any]]] = {}
    enum_re = re.compile(r"\benum\s+(\w+)\s*\{")
    variant_re = re.compile(r"^(\s*)([A-Z][A-Za-z0-9_]*)\b")
    for enum_match in enum_re.finditer(text):
        enum_name = enum_match.group(1)
        open_brace = text.find("{", enum_match.end() - 1)
        body, _ = brace_block(text, open_brace)
        body_start = open_brace + 1
        entries: list[dict[str, Any]] = []
        pending_attrs: list[str] = []
        for local_offset, line in enumerate(body.splitlines(True)):
            stripped = line.strip()
            absolute = body_start + sum(len(part) for part in body.splitlines(True)[:local_offset])
            if stripped.startswith("#[command("):
                pending_attrs.append(stripped)
                continue
            if stripped.startswith("#[") or stripped.startswith("///") or not stripped:
                continue
            match = variant_re.match(line)
            if not match:
                continue
            indent = len(match.group(1))
            if indent > 4:
                continue
            variant = match.group(2)
            attr = " ".join(pending_attrs)
            pending_attrs = []
            attr_name, aliases, hidden = parse_rust_command_attrs(attr)
            entries.append(
                {
                    "enum": enum_name,
                    "variant": variant,
                    "name": attr_name or kebab_case(variant),
                    "aliases": aliases,
                    "hidden": hidden,
                    "source": rel_ref(rust_root, path, line_number(text, absolute)),
                }
            )
        enums[enum_name] = entries
    return enums


def parse_rust_cli_commands(rust_root: Path) -> list[dict[str, Any]]:
    enum_entries: dict[str, list[dict[str, Any]]] = {}
    for rel in [Path("headscale-cli/src/main.rs"), Path("headscale-cli/src/admin/mod.rs"), Path("headscale-cli/src/lib.rs")]:
        path = rust_root / rel
        if path.exists():
            enum_entries.update(parse_rust_enum_commands(path, rust_root))

    commands: list[dict[str, Any]] = [
        {
            "name": "headscale",
            "aliases": [],
            "hidden": False,
            "path": "headscale",
            "path_tokens": ["headscale"],
            "source": "headscale-cli/src/main.rs:38",
        }
    ]
    subcommand_enums = {
        "users": "UsersCmd",
        "nodes": "NodesCmd",
        "preauthkeys": "PreauthKeysCmd",
        "auth": "AuthCmd",
        "apikeys": "ApiKeysCmd",
        "policy": "PolicyCmd",
        "debug": "DebugCmd",
        "generate": "GenerateCmd",
        "completion": "CompletionShell",
        "identity": "IdentityAction",
    }
    for entry in enum_entries.get("Commands", []):
        top_tokens = ["headscale", entry["name"]]
        commands.append({**entry, "path": " ".join(top_tokens), "path_tokens": top_tokens})
        sub_enum = subcommand_enums.get(entry["name"])
        if not sub_enum:
            continue
        for child in enum_entries.get(sub_enum, []):
            path_tokens = top_tokens + [child["name"]]
            commands.append({**child, "path": " ".join(path_tokens), "path_tokens": path_tokens})
    return commands


def compare_cli_command(upstream_cmd: dict[str, Any], rust_cli_index: dict[str, dict[str, Any]]) -> tuple[str, list[str], str]:
    key = " ".join(upstream_cmd["path_tokens"])
    rust_cmd = rust_cli_index.get(key)
    if not rust_cmd:
        return "missing", [], "no Rust Clap command with this primary path was found"
    missing_aliases = sorted(set(upstream_cmd["aliases"]) - set(rust_cmd.get("aliases", [])))
    if missing_aliases:
        return (
            "needs-review",
            [rust_cmd["source"]],
            "primary command is present but aliases are missing: " + ", ".join(missing_aliases),
        )
    return "present", [rust_cmd["source"]], "primary command and aliases found"


def parse_upstream_integration_tests(upstream_root: Path) -> list[dict[str, Any]]:
    tests: list[dict[str, Any]] = []
    for path in iter_files(upstream_root / "integration", suffixes=(".go",)):
        text = read_text(path)
        for match in re.finditer(r"\bfunc\s+(Test[A-Za-z0-9_]+)\s*\(", text):
            tests.append(
                {
                    "name": match.group(1),
                    "normalized_name": normalize_name(match.group(1)),
                    "source": rel_ref(upstream_root, path, line_number(text, match.start())),
                }
            )
    return tests


def parse_rust_integration_tests(rust_root: Path) -> list[dict[str, Any]]:
    tests: list[dict[str, Any]] = []
    test_roots = [
        rust_root / "headscale-api" / "tests",
        rust_root / "headscale-cli" / "tests",
        rust_root / "headscale-db" / "tests",
        rust_root / "headscale-identity" / "tests",
    ]
    for root in test_roots:
        for path in iter_files(root, suffixes=(".rs",)):
            text = read_text(path)
            for match in re.finditer(r"\b(?:async\s+)?fn\s+([a-zA-Z0-9_]+)\s*\(", text):
                name = match.group(1)
                if name.startswith(("fixture", "body_", "assert_", "helper", "service_for", "get_free_port")):
                    continue
                tests.append(
                    {
                        "kind": "rust_test",
                        "name": name,
                        "normalized_name": normalize_name(name),
                        "source": rel_ref(rust_root, path, line_number(text, match.start())),
                    }
                )
    real_client = rust_root / "tools" / "real-client"
    if real_client.exists():
        for path in sorted(real_client.glob("*.sh")):
            if path.name.endswith("-smoke.sh"):
                name = path.stem
                tests.append(
                    {
                        "kind": "real_client_smoke",
                        "name": name,
                        "normalized_name": normalize_name(name),
                        "source": rel_ref(rust_root, path, 1),
                    }
                )
    return tests


def compare_integration_test(upstream_test: dict[str, Any], rust_tests: list[dict[str, Any]]) -> tuple[str, list[str], str]:
    upstream_norm = upstream_test["normalized_name"]
    matches = [
        test
        for test in rust_tests
        if upstream_norm and (upstream_norm in test["normalized_name"] or test["normalized_name"] in upstream_norm)
    ]
    if matches:
        return "present", [test["source"] for test in matches[:10]], "normalized Rust test or smoke name overlaps upstream test name"
    tokens = set(re.findall(r"[a-z0-9]+", kebab_case(upstream_test["name"]).lower()))
    weak = [
        test
        for test in rust_tests
        if len(tokens.intersection(set(re.findall(r"[a-z0-9]+", kebab_case(test["name"]).lower())))) >= 2
    ]
    if weak:
        return (
            "needs-review",
            [test["source"] for test in weak[:10]],
            "related Rust test or smoke names found, but no normalized exact overlap",
        )
    return "needs-review", [], "no Rust integration or real-client smoke name overlap was found"


def build_inventory(
    upstream_root: Path,
    rust_root: Path,
    rust_ref: str,
    audit_date: str,
    rust_origin_main_ref: str | None = None,
) -> dict[str, Any]:
    consts = load_go_string_consts(upstream_root)
    proto_rpcs = parse_proto_rpcs(upstream_root)
    upstream_routes = sorted(
        parse_upstream_direct_routes(upstream_root, consts) + proto_http_routes(proto_rpcs),
        key=lambda item: (item["path"], item["method"], item.get("rpc", "")),
    )
    rust_routes = sorted(parse_rust_routes(rust_root), key=lambda item: (item["path"], item["method"], item["source"]))
    rust_route_index: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for route in rust_routes:
        rust_route_index[route["canonical_path"]].append(route)

    upstream_cli = sorted(parse_cobra_commands(upstream_root, consts), key=lambda item: item["path"])
    rust_cli = sorted(parse_rust_cli_commands(rust_root), key=lambda item: item["path"])
    rust_cli_index = {item["path"]: item for item in rust_cli}

    upstream_tests = sorted(parse_upstream_integration_tests(upstream_root), key=lambda item: item["name"])
    rust_tests = sorted(parse_rust_integration_tests(rust_root), key=lambda item: (item["kind"], item["name"]))

    rust_rpc_hits = {
        rpc["name"]: find_source_hits(
            rust_root / "headscale-api",
            rf"\basync\s+fn\s+{re.escape(rpc['rust_method'])}\s*\(",
            (".rs",),
        )
        for rpc in proto_rpcs
    }

    comparisons: dict[str, list[dict[str, Any]]] = {
        "routes": [],
        "proto_rpcs": [],
        "cli_commands": [],
        "integration_tests": [],
    }
    backlog: list[dict[str, Any]] = []

    for route in upstream_routes:
        status, evidence, reason = compare_route(route, rust_route_index)
        comparison = {
            "status": status,
            "upstream": route,
            "rust_evidence": evidence,
            "reason": reason,
        }
        comparisons["routes"].append(comparison)
        if status != "present":
            backlog.append(
                {
                    "id": f"route:{route['method'].lower()}:{slug(route['path'])}",
                    "category": "route",
                    **comparison,
                }
            )

    for rpc in proto_rpcs:
        evidence = rust_rpc_hits.get(rpc["name"], [])
        status = "present" if evidence else "missing"
        reason = "matching async HeadscaleService method implementation" if evidence else "no matching Rust async RPC method was found"
        comparison = {
            "status": status,
            "upstream": rpc,
            "rust_evidence": evidence,
            "reason": reason,
        }
        comparisons["proto_rpcs"].append(comparison)
        if status != "present":
            backlog.append(
                {
                    "id": f"proto-rpc:{slug(rpc['name'])}",
                    "category": "proto_rpc",
                    **comparison,
                }
            )

    for command in upstream_cli:
        status, evidence, reason = compare_cli_command(command, rust_cli_index)
        comparison = {
            "status": status,
            "upstream": command,
            "rust_evidence": evidence,
            "reason": reason,
        }
        comparisons["cli_commands"].append(comparison)
        if status != "present":
            backlog.append(
                {
                    "id": f"cli:{slug(command['path'])}",
                    "category": "cli_command",
                    **comparison,
                }
            )

    for test in upstream_tests:
        status, evidence, reason = compare_integration_test(test, rust_tests)
        comparison = {
            "status": status,
            "upstream": test,
            "rust_evidence": evidence,
            "reason": reason,
        }
        comparisons["integration_tests"].append(comparison)
        if status != "present":
            backlog.append(
                {
                    "id": f"integration-test:{slug(test['name'])}",
                    "category": "integration_test",
                    **comparison,
                }
            )

    comparison_counts = {
        category: dict(Counter(item["status"] for item in items))
        for category, items in comparisons.items()
    }

    return {
        "metadata": {
            "audit_date": audit_date,
            "upstream": {
                "root": str(upstream_root),
                "version": UPSTREAM_VERSION,
                "commit": UPSTREAM_COMMIT,
            },
            "headscale_rs": {
                "root": str(rust_root),
                "origin_main_commit": rust_origin_main_ref or git_ref(rust_root),
                "compared_ref": rust_ref,
            },
            "notes": [
                "Source-only scanner; results are backlog evidence, not a behavioral parity proof.",
                "Route path parameters are canonicalized across chi {name} and axum :name syntax before comparison.",
                "Integration-test comparison uses normalized name overlap and should be reviewed manually.",
            ],
        },
        "summary": {
            "upstream_counts": {
                "public_routes": len(upstream_routes),
                "proto_rpcs": len(proto_rpcs),
                "cli_commands": len(upstream_cli),
                "integration_tests": len(upstream_tests),
            },
            "rust_evidence_counts": {
                "routes": len(rust_routes),
                "cli_commands": len(rust_cli),
                "integration_or_smoke_tests": len(rust_tests),
            },
            "comparison_counts": comparison_counts,
            "backlog_count": len(backlog),
        },
        "upstream": {
            "public_routes": upstream_routes,
            "proto_rpcs": proto_rpcs,
            "cli_commands": upstream_cli,
            "integration_tests": upstream_tests,
        },
        "headscale_rs_evidence": {
            "routes": rust_routes,
            "cli_commands": rust_cli,
            "integration_or_smoke_tests": rust_tests,
            "proto_rpc_sources": rust_rpc_hits,
        },
        "comparisons": comparisons,
        "backlog": backlog,
    }


def compact_inventory(inventory: dict[str, Any]) -> dict[str, Any]:
    return {
        "metadata": {
            **inventory["metadata"],
            "notes": inventory["metadata"]["notes"]
            + ["Compact output keeps upstream inventories and backlog; rerun without --compact for full Rust evidence arrays."],
        },
        "summary": inventory["summary"],
        "upstream": inventory["upstream"],
        "backlog": inventory["backlog"],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream-root", type=Path, default=DEFAULT_UPSTREAM_ROOT)
    parser.add_argument("--rust-root", type=Path, default=Path.cwd())
    parser.add_argument("--rust-ref", default=None, help="Rust ref to record in metadata; defaults to git rev-parse HEAD")
    parser.add_argument("--audit-date", default="2026-06-02")
    parser.add_argument("--compact", action="store_true", help="Omit full Rust evidence and present comparisons from the JSON")
    parser.add_argument("--output", type=Path, help="Write JSON to this path instead of stdout")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    upstream_root = args.upstream_root.resolve()
    rust_root = args.rust_root.resolve()
    rust_origin_main_ref = git_ref(rust_root, "origin/main")
    rust_ref = args.rust_ref or git_ref(rust_root)
    inventory = build_inventory(upstream_root, rust_root, rust_ref, args.audit_date, rust_origin_main_ref)
    if args.compact:
        inventory = compact_inventory(inventory)
    payload = json.dumps(inventory, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
