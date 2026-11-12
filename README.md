# PgSniffer

PgSniffer passively analyzes PostgreSQL traffic. It reassembles TCP streams, understands the Simple and Extended Query protocols, and reports bounded latency statistics grouped by redacted SQL fingerprints.

[中文文档](README_CN.md)

## Features

- Connection isolation by TCP four-tuple and bidirectional request/response matching.
- Incremental framing for split and coalesced PostgreSQL messages.
- Simple Query, prepared statements, Bind, and Execute tracking.
- Live capture and offline PCAP analysis using packet timestamps.
- Bounded p95/p99 statistics with SQL literal redaction by default.
- Stable JSON reports for programmatic processing.
- Explicit detection of TLS/GSS encrypted sessions.

## Build

Go 1.26.11+ and the libpcap development package are required. This minimum
patch level includes the standard-library security fixes expected by the project.

```bash
sudo apt-get install libpcap-dev
make build
go test -race ./...
```

The executable is written to `bin/pgsniffer`. Build outputs under `bin/` and `dist/` are ignored by Git; CI publishes its Linux build as a GitHub Actions artifact instead of committing binaries to the repository.

## Docker end-to-end tests

The opt-in E2E suite builds PgSniffer, starts isolated PostgreSQL containers on random ports, uses `tcpdump` to capture real loopback traffic, and checks live reports against offline replay of the generated PCAP. It does not require `psql` or a host PostgreSQL driver.

```bash
# Docker must be running; use lo0 automatically on macOS and lo on Linux
make e2e

# Detect intermittent lifecycle or capture-ordering failures
make e2e-repeat

# Select another official PostgreSQL image or capture interface
PGSNIFFER_POSTGRES_IMAGE=postgres:12 make e2e
PGSNIFFER_E2E_INTERFACE=lo0 make e2e
```

The suite covers Simple Query, multi-statement transactions, `COPY TO STDOUT`, SQL errors, CancelRequest, named prepared statements and portals, text parameters, pipelined Extended Query messages, concurrent connections, TLS detection, abrupt server termination, incomplete latency, and deterministic live/offline results. Each run uses unique container/volume names and cleans up only resources it created.

Successful runs remove temporary artifacts. Failures retain their PCAP and JSON reports and print the directory. Set `PGSNIFFER_E2E_ARTIFACTS=.artifacts/e2e` to retain every run. On Linux hosts where the user cannot capture packets, set `PGSNIFFER_E2E_SUDO=1`; CI can instead use `PGSNIFFER_E2E_SETCAP=1` with passwordless `sudo setcap`.

This is the release regression baseline, not an exhaustive network appliance test. SCRAM/GSS authentication exchanges, IPv6/VLAN link types, deliberate packet loss/reordering, and long-duration load/soak testing remain separate compatibility scenarios.

## Usage

```bash
# List interfaces
./bin/pgsniffer -l

# Live capture
sudo ./bin/pgsniffer -i lo0 --server 127.0.0.1:5432

# Offline analysis
./bin/pgsniffer --read-pcap traffic.pcap --server 10.0.0.8:5432

# Redirect the JSON report when a file is needed
sudo ./bin/pgsniffer -i eth0 --server 10.0.0.8:5432 > report.json
```

Run `./bin/pgsniffer -h` for all options. Raw SQL values are not retained unless `--show-query-values` is explicitly enabled.

`--server` requires an IP literal and port. PgSniffer derives the BPF filter from this endpoint and uses the same IP and port to identify client-to-server and server-to-client traffic. Use bracket notation for IPv6, for example `--server '[::1]:5432'`.

## Timing semantics

- Simple Query: client `Q` through server `ReadyForQuery`.
- Extended Query: client `Execute` through `CommandComplete`, `PortalSuspended`, or `ErrorResponse`.
- A request still in flight when its TCP stream closes is marked incomplete.

## Limitations

TLS/GSS encrypted PostgreSQL payloads cannot be decoded from ordinary packet capture. PgSniffer detects and counts these sessions without attempting to bypass encryption.

Execution plans and index/cache hit ratios are not part of the wire protocol. Use PostgreSQL facilities such as `EXPLAIN`, `pg_stat_statements`, and `pg_stat_user_indexes` for that data.

PCAP files and raw SQL can contain sensitive information. Restrict their access and retention.

## License

MIT
