# Current-head parity scenarios

Scenarios in this directory exercise behavior observed in upstream headscale
while it is being staged outside the default scenario set. They are tracked by a
Rust golden until each scenario is promoted into the default
`./scripts/headscale_go_diff.sh` differential run.

The default v0.29 differential gate directly compares the former current-head
route-via, route auto-approval, SSH policy, SSH `acceptEnv`,
hold-and-delegate SSH check, SSH host-destination rejection, and
Taildrive/Taildrop capability scenarios against headscale-go.

No current-head-only scenarios are staged here right now.

Keep new current-head-only scenarios here only when the Go harness or Rust
implementation is not ready for default promotion yet.

Run the current-head Rust golden gate from the repository root:

```sh
./scripts/headscale_rs_current_head_golden.sh
```

Refresh the golden only after reviewing the semantic diff:

```sh
CURRENT_HEAD_UPDATE_GOLDEN=1 ./scripts/headscale_rs_current_head_golden.sh
```
