# Pinned parity goldens

`headscale-go-v0.28.0.json` is the normalized output from the pinned
`tools/parity/scenarios/*.json` differential suite. The default parity script
still compares `headscale-rs` against the pinned Go harness first; this golden
adds a second guard against accidental scenario deletion or harness output drift.

Refresh it only after reviewing the differential output and confirming the
scenario change is intentional:

```sh
PARITY_UPDATE_GOLDEN=1 ./scripts/headscale_go_diff.sh
```
