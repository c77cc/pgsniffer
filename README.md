# PgSniffer

PgSniffer passively analyzes PostgreSQL traffic. It reassembles TCP streams, understands the Simple and Extended Query protocols, and reports latency statistics grouped by redacted SQL fingerprints without changing PostgreSQL logging.

[中文文档](README_CN.md)

## Features

- Live capture and offline PCAP analysis using packet timestamps.
- Simple Query, prepared statement, Bind, Execute, split-packet, and concurrent connection tracking.
- Call, error, incomplete-request, average, p95, p99, maximum, and total latency statistics.
- SQL literal redaction and bounded in-memory aggregation by default.
- Explicit detection of TLS/GSS encrypted sessions.

## Install

Prebuilt packages and SHA-256 checksums are available on [GitHub Releases](https://github.com/c77cc/pgsniffer/releases):

- Linux AMD64
- Linux ARM64
- macOS Intel
- macOS Apple Silicon
- Windows x64

Linux packages are self-contained and use the native `AF_PACKET` interface. macOS uses the system-provided libpcap and requires no additional capture library. Windows requires [Npcap](https://npcap.com/) only for live capture and interface listing; offline PCAP/PCAPNG analysis has no Npcap dependency.

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

Raw SQL values are discarded by default. `--show-query-values` retains them and may expose sensitive data; `-v` logs completed queries while capture is running.

## Output

Durations are reported in milliseconds:

```json
{
  "generated_at": "2026-11-16T10:30:00Z",
  "queries": [
    {
      "fingerprint": "select tablename from pg_catalog.pg_tables where schemaname = ? and tablename like ?",
      "calls": 57,
      "errors": 0,
      "incomplete": 0,
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
  "encrypted_sessions": 0,
  "decode_errors": 0,
  "dropped_query_keys": 0
}
```

`incomplete` counts requests whose connection closed before a complete response. `dropped_query_keys` counts new fingerprints merged after the bounded aggregation limit was reached.

## Timing semantics

- Simple Query: client `Q` through server `ReadyForQuery`.
- Extended Query: client `Execute` through `CommandComplete`, `PortalSuspended`, or `ErrorResponse`.
- Interrupted requests use the last observed packet timestamp and are marked incomplete.

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
