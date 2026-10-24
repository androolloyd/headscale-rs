#!/usr/bin/env python3
"""Check production MapResponse dumps around a live policy reload."""

import json
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(message)


def resolver_addresses(response: dict) -> list[str]:
    config = response.get("DNSConfig") or {}
    return [item.get("Addr", "") for item in config.get("Resolvers", [])]


def main() -> None:
    if len(sys.argv) != 4:
        fail("usage: assert-mapresponse-dns-policy-reload.py DUMP_DIR BEFORE AFTER")
    root = Path(sys.argv[1])
    before, after = sys.argv[2:]
    if not before or not after or before == after:
        fail("distinct nonempty before/after resolver addresses are required")

    dumps = []
    for path in sorted(root.glob("*/*.json")):
        if path.name.endswith(("-full.json", "-change.json", "-policy.json")):
            dumps.append((path, json.loads(path.read_text())))

    policy = [(path, body) for path, body in dumps if path.name.endswith("-policy.json")]
    initial = [(path, body) for path, body in dumps if before in resolver_addresses(body)]
    changed = [
        (path, body)
        for path, body in dumps
        if path.name.endswith("-change.json") and after in resolver_addresses(body)
    ]
    if not initial:
        fail(f"initial MapResponse did not include DNS resolver {before}")
    if not changed:
        fail(f"change MapResponse did not include changed DNS resolver {after}")
    if len(policy) < 2 or any("DNSConfig" in body for _, body in policy):
        fail("expected unrelated and profile policy responses without DNSConfig")
    first_policy = policy[0][0].name
    changed_name = changed[0][0].name
    last_policy = policy[-1][0].name
    if not first_policy < changed_name < last_policy:
        fail("expected unrelated policy, DNS change, then profile policy response")

    result = {
        "initial_resolver_before": before,
        "change_resolver_after": after,
        "policy_responses_omitted_dns": True,
        "dns_profile_response_type": "change",
        "initial_dumps": len(initial),
        "policy_dumps": len(policy),
    }
    (root.parent / "mapresponse-dns-policy-reload-assertion.json").write_text(
        json.dumps(result, indent=2) + "\n"
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
