# Current-head parity scenarios

Scenarios in this directory exercise behavior observed in upstream headscale
after the pinned `github.com/juanfont/headscale v0.28.0` baseline. They are not
part of the default `./scripts/headscale_go_diff.sh` differential run because
the checked-in Go harness deliberately remains pinned to v0.28.0.

Run the current-head Rust golden gate from the repository root:

```sh
./scripts/headscale_rs_current_head_golden.sh
```

Refresh the golden only after reviewing the semantic diff:

```sh
CURRENT_HEAD_UPDATE_GOLDEN=1 ./scripts/headscale_rs_current_head_golden.sh
```
