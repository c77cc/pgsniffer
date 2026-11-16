# PgSniffer

PgSniffer passively analyzes PostgreSQL traffic. It reassembles TCP streams, understands the Simple and Extended Query protocols, and reports latency statistics grouped by redacted SQL fingerprints without changing PostgreSQL logging.

[中文文档](README_CN.md)

## Features

- Live capture and offline PCAP analysis using packet timestamps.
- Simple Query, prepared statement, Bind, Execute, split-packet, and concurrent connection tracking.
- Call, error, incomplete-request, average, p95, p99, maximum, and total latency statistics.
- Capture-loss, truncation, TCP-gap, and midstream-connection diagnostics.
- Per-user, database, application, and client grouping with command tags, affected rows, SQLSTATE, severity, and transaction context.
- SQL literal redaction and bounded in-memory aggregation by default.
- PostgreSQL-aware normalization for strings, numbers, booleans, `IN` lists, and batched `VALUES`.
- Explicit detection of TLS/GSS encrypted sessions.
- Live HTTP health, JSON report, Prometheus endpoints, and periodic JSONL snapshots.

## Install

Prebuilt packages and SHA-256 checksums are available on [GitHub Releases](https://github.com/c77cc/pgsniffer/releases):

- Linux AMD64
- Linux ARM64
- macOS Intel
- macOS Apple Silicon
- Windows x64

Linux packages are self-contained and use an `AF_PACKET`/`TPACKET_V3` shared-memory ring. macOS uses the system-provided libpcap and requires no additional capture library. Windows requires [Npcap](https://npcap.com/) only for live capture and interface listing; offline PCAP/PCAPNG analysis has no Npcap dependency.

## Quick start

List capture interfaces:

```bash
./pgsniffer -l
```

Capture a PostgreSQL server until `Ctrl-C`, then print the JSON report:

```bash
sudo ./pgsniffer -i eth0 --server 10.0.0.8:5432 > report.json
```

Analyze an existing PCAP:

```bash
./pgsniffer --read-pcap traffic.pcap --server 10.0.0.8:5432
```

`--server` is required and accepts an IP literal plus port. Use brackets for IPv6, for example `--server '[::1]:5432'`. Run `./pgsniffer -h` for all options.

Raw SQL values are discarded from reports by default. `--log-queries` logs every completed query with its original SQL to stderr while capture is running. `--group-by raw-sql` disables fingerprint grouping and groups reports by the complete original SQL instead. Both options may expose sensitive values. The default report mode is `--group-by fingerprint`.

```bash
# Stream every original SQL statement to the terminal.
sudo ./pgsniffer -i eth0 --server 10.0.0.8:5432 --log-queries

# Group the final report by original SQL instead of fingerprints.
sudo ./pgsniffer -i eth0 --server 10.0.0.8:5432 --group-by raw-sql
```

## Long-running observability

Enable an HTTP endpoint bound to localhost:

```bash
sudo ./pgsniffer -i eth0 --server 10.0.0.8:5432 --listen 127.0.0.1:9108
```

The endpoints are:

- `GET /healthz` for liveness checks.
- `GET /report` for the current cumulative JSON report, limited by `-n`.
- `GET /metrics` for Prometheus text metrics across all bounded SQL groups.

Append periodic JSONL snapshots with:

```bash
sudo ./pgsniffer -i eth0 --server 10.0.0.8:5432 \
  --listen 127.0.0.1:9108 \
  --report-interval 1m \
  --report-file /var/log/pgsniffer/reports.jsonl
```

New report files are created with user-only permissions. The HTTP server has no built-in authentication, and reports may expose database names, users, client addresses, SQL fingerprints, or raw SQL when `--group-by raw-sql` is enabled. Do not bind it to a public address unless it is protected by a trusted authenticated proxy.

## Output

Durations are reported in milliseconds:

```json
{
  "generated_at": "2026-11-16T10:30:00Z",
  "queries": [
    {
      "fingerprint": "select tablename from pg_catalog.pg_tables where schemaname = ? and tablename like ?",
      "dimensions": {
        "user": "app_user",
        "database": "inventory",
        "application_name": "catalog-api",
        "client_address": "10.0.1.24"
      },
      "calls": 57,
      "errors": 0,
      "incomplete": 0,
      "rows_affected": 57,
      "command_tags": {"SELECT": 57},
      "transaction_status_before": {"idle": 57},
      "latency_ms": {
        "average": 11.643,
        "min": 1.433,
        "p95": 65.535,
        "p99": 156.734,
        "max": 156.734,
        "total": 663.65
      }
    }
  ],
  "capture": {
    "packets_seen": 920,
    "packets_matched": 920,
    "bytes_captured": 184320,
    "truncated_packets": 0,
    "kernel_packets_received": 920,
    "kernel_packets_dropped": 0,
    "interface_packets_dropped": 0,
    "tcp_gap_events": 0,
    "tcp_bytes_skipped": 0,
    "midstream_connections": 0,
    "statistics_errors": 0
  },
  "encrypted_sessions": 0,
  "decode_errors": 0,
  "dropped_query_keys": 0
}
```

`incomplete` counts requests without a complete response. `incomplete_reasons` distinguishes connection closure, capture/idle timeout, TCP gaps, protocol errors, and pipeline requests skipped after an error. Nonzero capture drops, truncated packets, or TCP gaps mean the report may be incomplete. `dropped_query_keys` counts new SQL-and-dimension groups merged after the bounded aggregation limit was reached.

With `--group-by raw-sql`, each entry is grouped by the exact original SQL and uses `query` instead of `fingerprint`:

```json
{
  "query": "SELECT * FROM users WHERE id = 123",
  "calls": 1
}
```

Queries that differ only in literal values remain separate groups in this mode.
For Extended Query protocol traffic, PostgreSQL sends SQL text and bind values separately; `--log-queries` and `--group-by raw-sql` show the original SQL text with placeholders such as `$1`, not a reconstructed SQL string.

## Timing semantics

- Simple Query: client `Q` through server `ReadyForQuery`.
- Extended Query: client `Execute` through `CommandComplete`, `PortalSuspended`, or `ErrorResponse`.
- Interrupted requests use the last observed packet timestamp and are marked incomplete.

## SQL fingerprint semantics

- Keywords and unquoted identifiers are lowercased, with canonical whitespace, punctuation, and operator formatting.
- Strings, dollar-quoted strings, numbers, booleans, and `NULL` become `?`; `$1`-style bind parameters are preserved.
- Literal/parameter-only `IN (...)` and `ARRAY[...]` lists collapse to one placeholder.
- Multi-row `VALUES` retains the first row shape and uses `...` for the remaining rows, avoiding fingerprints that differ only by batch size.
- Double-quoted and `U&"..."` identifiers preserve their case and contents.

## Limitations and security

- TLS/GSS-encrypted PostgreSQL payloads cannot be decoded from ordinary packet capture; only encrypted sessions are counted.
- Execution plans and index/cache hit ratios are not part of the wire protocol. Use `EXPLAIN`, `pg_stat_statements`, or `pg_stat_user_indexes` for those metrics.
- PgSniffer does not connect to PostgreSQL or execute SQL.
- Raw SQL and PCAP files may contain sensitive data. Restrict their access and retention.
- Live packet capture normally requires elevated privileges or Linux `CAP_NET_RAW`/`CAP_NET_ADMIN` capabilities.

## Build from source

Go 1.26.11+ is required. Linux builds do not require libpcap; macOS uses its system libpcap.

```bash
make build
go test ./...

# Optional Docker end-to-end suite
make e2e
```

The executable is written to `bin/pgsniffer`.

## License

[MIT](LICENSE)
