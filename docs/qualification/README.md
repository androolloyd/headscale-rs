# Qualification records

These JSON files were produced on the standalone `origin/main` line, a parallel
attempt at the headscale-go v0.29.5 update, before that line was reconciled into
the verified parity branch. They are kept as the records they were: each one is
bound to the tree it names (`rust_baseline`, `base_commit`, the source manifests
and hashes) and none of them describes the merged tree.

| file | what it records | tree it binds to |
| --- | --- | --- |
| `headscale-v0.29.5.json` | gates, hashes, preserved failures and the open-backlog list of the v0.29.5 update | `main` at its 2026-10-16 checkpoint (`b8963808`; rust baseline `e1d71910`) |
| `headscale-v0.29.5-source.json` | per-file SHA-256 manifest of that tree | same |
| `headscale-v0.29.5-source-audit.json` | mapping of 45 changed upstream production paths to that tree's Rust boundaries | same |
| `headscale-v0.29.5-via-followup.json` | focused `via` exit-route regression evidence (103 scenarios) | `main` at `7b6b71b2` (checked on base `b8963808`) |
| `embedded-mesh-20261017.json` | durable embedded-mesh HTTP policy and supervised raw-TLS gates | `main` at `5662f202` (checked on base `7b6b71b2`) |

Do not read their counts or hashes as results for the merged tree: the file
hashes cannot match it, the workspace test and scenario counts differ (the
merged tree checks in 106 differential scenarios), and the build was made with a
different toolchain pin. The merged tree's own results are in
[`../headscale-v0295-remaining-audit-2026-10-18.md`](../headscale-v0295-remaining-audit-2026-10-18.md)
and [`../../CHANGES.md`](../../CHANGES.md).

Statements in these records that the verified branch's later results supersede:

- `headscale-v0.29.5.json`, `open_replacement_parity_backlog` lists four items.
  The merged tree's `docs/headscale-go-parity-backlog.json` carries three open
  items; the policy-v2 compatibility-fixture and DNS live-resolver items were
  closed by later work.
- `headscale-v0.29.5.json`, `preserved_failures` (last entry) and
  `gates.stock_tailscale` (`postgres-user-node-lifecycle-restart`) say Rust keeps
  an immediate user-rename projection while the Go row fails. Checked against the
  real v0.29.5 binary, Go keeps the cached owner name until restart; the merged
  tree does the same, and the row is pinned for both targets.
- Statements of the form "no tests, builds or probes ran" in the audit documents
  describe the dated batch they sit in, not the merged tree.
