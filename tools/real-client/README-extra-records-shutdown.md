Run `extra-records-shutdown-smoke.py` with `HEADSCALE_GO_BIN` set to the pinned
v0.29.5 executable. The default SQLite mode requires no other service. To run
the Postgres row, set `EXTRA_RECORDS_DATABASE=postgres` and
`HEADSCALE_DB_POSTGRES_TEST_URL` to an isolated local test server URL. The
harness creates and drops its own two databases in that server.

Each case starts the production server, removes its watched DNS extra-records
file, checks health after a delay for the watcher to observe the deletion, and requires
a clean SIGTERM exit within eight seconds. `summary.json` and server logs live
under the reported `target/real-client/extra-records-shutdown-*` directory.
