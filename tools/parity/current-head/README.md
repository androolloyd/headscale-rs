# Current-head parity scenarios

Scenarios in this directory exercise behavior observed in upstream headscale
outside the default scenario set for the pinned
`github.com/juanfont/headscale v0.29.0-beta.2`
harness. They are tracked by a Rust golden until each scenario is promoted into
the default `./scripts/headscale_go_diff.sh` differential run.

Run the current-head Rust golden gate from the repository root:

```sh
./scripts/headscale_rs_current_head_golden.sh
```

Refresh the golden only after reviewing the semantic diff:

```sh
CURRENT_HEAD_UPDATE_GOLDEN=1 ./scripts/headscale_rs_current_head_golden.sh
```
