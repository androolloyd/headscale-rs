#!/usr/bin/env python3
"""Compare a stock client's ephemeral identity and observer netmap after reconnect."""

import json
import sys
from pathlib import Path


def read(path: Path):
    return json.loads(path.read_text())


def field(obj: dict, *names):
    for name in names:
        if name in obj:
            return obj[name]
    return None


def node(payload, name: str) -> dict:
    rows = payload if isinstance(payload, list) else payload.get("nodes", [])
    if len(rows) != 2:
        raise ValueError(f"expected two persisted nodes, got {len(rows)}")
    matches = [
        row
        for row in rows
        if any(name == str(field(row, key) or "") for key in ("name", "given_name", "givenName"))
    ]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one persisted node named {name}")
    return matches[0]


def peer(status: dict, wanted_id: str) -> dict:
    matches = [
        value
        for value in (status.get("Peer") or {}).values()
        if str(value.get("ID")) == wanted_id
    ]
    if len(matches) != 1:
        raise ValueError(f"observer netmap must contain peer {wanted_id} exactly once")
    return matches[0]


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit("usage: assert-ephemeral-reconnect.py BASE_PREFIX AFTER_PREFIX TARGET OBSERVER")
    before_prefix, after_prefix = map(Path, sys.argv[1:3])
    target_name, observer_name = sys.argv[3:]
    before_nodes = read(Path(f"{before_prefix}-nodes.json"))
    after_nodes = read(Path(f"{after_prefix}-nodes.json"))
    before_target = read(Path(f"{before_prefix}-target.json"))
    after_target = read(Path(f"{after_prefix}-target.json"))
    before_observer = read(Path(f"{before_prefix}-observer.json"))
    after_observer = read(Path(f"{after_prefix}-observer.json"))

    for name in (target_name, observer_name):
        original = node(before_nodes, name)
        current = node(after_nodes, name)
        for names in (
            ("id", "ID"),
            ("machine_key", "machineKey"),
            ("node_key", "nodeKey"),
            ("ip_addresses", "ipAddresses"),
        ):
            if field(original, *names) != field(current, *names):
                raise ValueError(f"{name} changed {names[0]} across reconnect")
        key = field(current, "pre_auth_key", "preAuthKey") or {}
        if key.get("ephemeral") is not True:
            raise ValueError(f"{name} lost ephemeral preauth-key state")
        if field(current, "online", "Online") is not True:
            raise ValueError(f"{name} is not online after reconnect")

    for label, old, new in (
        ("target", before_target, after_target),
        ("observer", before_observer, after_observer),
    ):
        if not new.get("HaveNodeKey") or not (new.get("Self") or {}).get("InNetworkMap"):
            raise ValueError(f"{label} client is not logged in with a netmap")
        for attr in ("ID", "NodeKey"):
            if (old.get("Self") or {}).get(attr) != (new.get("Self") or {}).get(attr):
                raise ValueError(f"{label} client changed self {attr}")
        if old.get("TailscaleIPs") != new.get("TailscaleIPs"):
            raise ValueError(f"{label} client changed Tailscale IPs")

    target_id = str((after_target.get("Self") or {}).get("ID"))
    old_peer = peer(before_observer, target_id)
    new_peer = peer(after_observer, target_id)
    if old_peer.get("NodeKey") != new_peer.get("NodeKey"):
        raise ValueError("observer received a different target node key")
    if new_peer.get("Online") is not True:
        raise ValueError("observer still sees target offline after reconnect")
    print(json.dumps({"target_id": target_id, "target_ips": after_target["TailscaleIPs"], "observer_peer_online": True}))


if __name__ == "__main__":
    try:
        main()
    except (KeyError, TypeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
