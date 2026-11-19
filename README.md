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

Linux packages are self-contained and use an `AF_PACKET`/`TPACKET_V3` shared-memory ring. macOS uses the system-provided libpcap and requires no additional capture library. On Windows, live capture and interface listing require the [Npcap Installer](https://npcap.com/#download); the Npcap SDK is not required. Offline PCAP/PCAPNG analysis does not require Npcap.

## Quick start

List capture interfaces:

```bash
./pgsniffer --list-interfaces
```

On Windows, copy the listed `Device` value into `--interface`. For local PostgreSQL traffic, use the Npcap loopback device, for example:

```powershell
.\pgsniffer.exe --interface '\Device\NPF_Loopback' --server 127.0.0.1:5432
```

Capture a PostgreSQL server until `Ctrl-C`, then print the JSON report:

```bash
sudo ./pgsniffer --interface eth0 --server 10.0.0.8:5432 > report.json
```

After the interface and capture filter are opened successfully, pgsniffer writes runtime status to stderr:

```text
pgsniffer: capture started interface="eth0" server="10.0.0.8:5432" filter="host 10.0.0.8 and tcp port 5432"
pgsniffer: waiting for PostgreSQL traffic; press Ctrl+C to stop and print the report
pgsniffer: PostgreSQL traffic detected
pgsniffer: SQL capture is working
```

If no matching traffic or no complete SQL is seen after 10 seconds, pgsniffer prints a diagnostic hint. TLS/GSS sessions are identified explicitly because their SQL cannot be decoded. On shutdown, a one-line capture summary is written to stderr and the JSON report is written to stdout, so redirecting stdout to `report.json` remains safe.

Analyze an existing PCAP:

```bash
./pgsniffer --read-pcap traffic.pcap --server 10.0.0.8:5432
```

`--server` is required and accepts an IP literal plus port. Use brackets for IPv6, for example `--server '[::1]:5432'`. Run `./pgsniffer -h` for all options.

Raw SQL values are discarded from reports by default. `--log-queries` logs every completed query with its original SQL to stderr while capture is running. `--group-by raw-sql` disables fingerprint grouping and groups reports by the complete original SQL instead. Both options may expose sensitive values. The default report mode is `--group-by fingerprint`.

```bash
# Stream every original SQL statement to the terminal.
sudo ./pgsniffer --interface eth0 --server 10.0.0.8:5432 --log-queries

# Group the final report by original SQL instead of fingerprints.
sudo ./pgsniffer --interface eth0 --server 10.0.0.8:5432 --group-by raw-sql
```

## Command-line options

| Option | Description |
| --- | --- |
| `--server IP:PORT` | PostgreSQL server endpoint. Required for live capture and PCAP replay; IPv6 addresses must use brackets. |
| `--interface INTERFACE` | Network interface for live capture. The default is platform-specific. |
| `--list-interfaces` | List available capture interfaces and exit. |
| `--read-pcap FILE` | Analyze a PCAP/PCAPNG file instead of capturing live traffic. |
| `--group-by MODE` | Group reports by `fingerprint` or `raw-sql` (default: `fingerprint`). Raw SQL may expose sensitive values. |
| `--log-queries` | Log every completed original SQL query to stderr. This may expose sensitive values. |
| `--max-groups COUNT` | Maximum number of SQL groups, ordered by maximum completed-request latency (default: `50`; `0` reports all groups). |
| `--listen ADDRESS` | Serve `/healthz`, `/report`, and `/metrics`, for example `127.0.0.1:9108`. |
| `--report-interval DURATION` | Periodic JSONL report interval, for example `1m`; requires `--report-file`. |
| `--report-file FILE` | Append periodic JSONL reports to a file; requires `--report-interval`. |
| `--version` | Print the version and exit. |
| `-h`, `--help` | Show command-line help and exit. |

## Long-running observability

Enable an HTTP endpoint bound to localhost:

```bash
sudo ./pgsniffer --interface eth0 --server 10.0.0.8:5432 --listen 127.0.0.1:9108
```

The endpoints are:

- `GET /healthz` for liveness checks.
- `GET /report` for the current cumulative JSON report, limited by `--max-groups`.
- `GET /metrics` for Prometheus text metrics across all bounded SQL groups.

Prometheus query-duration metrics include completed requests only. `pgsniffer_query_duration_observations_total` reports the number of completed requests contributing to them; `pgsniffer_query_calls_total` continues to include incomplete requests.

Append periodic JSONL snapshots with:

```bash
sudo ./pgsniffer --interface eth0 --server 10.0.0.8:5432 \
  --listen 127.0.0.1:9108 \
  --report-interval 1m \
  --report-file /var/log/pgsniffer/reports.jsonl
```

New report files are created with user-only permissions. The HTTP server has no built-in authentication, and reports may expose database names, users, client addresses, SQL fingerprints, or raw SQL when `--group-by raw-sql` is enabled. Do not bind it to a public address unless it is protected by a trusted authenticated proxy.

## Output

Durations are reported in milliseconds:

```json
{
  "schema_version": 3,
  "build": {
    "version": "snapshot-cc5f307",
    "revision": "cc5f307a1b2c",
    "commit_time": "2026-11-19T02:45:00Z"
  },
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
      "dimension_status": {
        "startup_observed": true
      },
      "calls": 57,
      "errors": 0,
      "incomplete": 0,
      "rows_affected": 57,
      "command_tags": {"SELECT": 57},
      "transaction_status_before": {"idle": 57},
      "latency_ms": {
        "observations": 57,
        "average": 11.643,
        "min": 1.433,
        "p95": 65.535,
        "p99": 156.734,
        "max": 156.734,
        "total": 663.65,
        "first_response": {
          "observations": 57,
          "average": 10.8,
          "min": 1.2,
          "p95": 64,
          "p99": 155,
          "max": 155,
          "total": 615.6
        },
        "response_transfer": {
          "observations": 57,
          "average": 0.843,
          "min": 0.1,
          "p95": 1.535,
          "p99": 1.734,
          "max": 1.734,
          "total": 48.05
        }
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
    "tcp_sequence_discontinuities": 0,
    "largest_tcp_gap_bytes": 0,
    "connections_observed": 1,
    "startup_observed_connections": 1,
    "midstream_connections": 0,
    "protocol_state_loss_connections": 0,
    "statistics_errors": 0
  },
  "data_quality": {
    "completed_queries": 57,
    "excluded_queries": 0,
    "excluded_percentage": 0,
    "metadata_missing_queries": 0
  },
  "encrypted_sessions": 0,
  "decode_errors": 0,
  "dropped_query_keys": 0
}
```

Top-level fields:

| Field | Meaning |
| --- | --- |
| `schema_version` | JSON report schema version. Use it when consuming reports programmatically. |
| `build` | Version, source revision, and optional commit time of the pgsniffer executable that generated the report. |
| `generated_at` | Time at which this cumulative report snapshot was generated. |
| `queries` | SQL groups after applying the grouping mode, dimensions, sorting, and `--max-groups`. |
| `capture` | Capture health and packet completeness counters. |
| `data_quality` | Global completed, excluded, and metadata-missing query counts before `--max-groups` truncation. |
| `protocol_issues` | Optional aggregate protocol-state diagnostics, including expected and actual command tags. It never contains SQL text. |
| `encrypted_sessions` | TLS/GSS sessions detected but not decoded. |
| `decode_errors` | Packet, TCP stream, or PostgreSQL protocol decode failures. |
| `dropped_query_keys` | Query events routed to the bounded overflow group because a new SQL-and-dimensions key could not be admitted. |

Fields in each `queries` entry:

| Field | Meaning |
| --- | --- |
| `fingerprint` | Normalized SQL used as the group key in the default mode. Literal values are replaced while identifiers and placeholders such as `$1` are retained. |
| `query` | Exact original SQL group key in `--group-by raw-sql` mode; replaces `fingerprint`. |
| `dimensions.user` | PostgreSQL startup user. |
| `dimensions.database` | PostgreSQL startup database; defaults to the user when the client omits it. |
| `dimensions.application_name` | Client `application_name`, when available. |
| `dimensions.client_address` | Client IP address observed in the captured connection. |
| `dimension_status.startup_observed` | Whether pgsniffer decoded this connection's PostgreSQL StartupMessage. |
| `dimension_status.missing` | Optional list of unavailable dimensions. `user` and `database` are emitted as empty strings instead of being silently omitted. |
| `calls` | Number of observed requests in this SQL-and-dimensions group. |
| `errors` | Requests with an observed PostgreSQL error code or error message. |
| `incomplete` | Requests that did not have a complete response. They are excluded from `latency_ms`. |
| `rows_affected` | Sum of rows reported by PostgreSQL `CommandComplete` tags, including rows selected or modified. |
| `command_tags` | Counts by PostgreSQL command tag, such as `SELECT`, `INSERT`, or `UPDATE`. |
| `sqlstates` | Optional counts by five-character PostgreSQL SQLSTATE error code. |
| `error_severities` | Optional counts by PostgreSQL error severity. |
| `transaction_status_before` | Counts by transaction state before execution: `idle`, `in_transaction`, or `failed_transaction`. |
| `incomplete_reasons` | Optional counts explaining incomplete requests. |
| `latency_ms` | Completed-request latency in milliseconds. Incomplete requests do not affect these values or latency-based sorting. |
| `incomplete_observed_duration_ms` | Optional observed-duration aggregate for incomplete requests, ending at the last usable timestamp. It is diagnostic data, not SQL latency. |

`latency_ms` fields:

| Field | Meaning |
| --- | --- |
| `observations` | Completed requests included in the latency aggregate. This normally equals `calls - incomplete`. |
| `average` | Arithmetic mean over completed requests in the group. |
| `min` / `max` | Smallest and largest completed-request latency. |
| `p95` / `p99` | Approximate percentiles from the bounded latency histogram, clamped to the observed maximum. |
| `total` | Sum of completed-request latency. |
| `first_response` | Time from the complete client Query/Execute message to the beginning of the first attributable server response. It includes server wait/execution and network travel around that first response. |
| `response_transfer` | Time from the beginning of the first attributable server response until the terminal response is complete. It can include remaining server execution, row serialization, and network transfer; for COPY it can also include COPY data exchange. |
| `first_response.observations` / `response_transfer.observations` | Completed requests for which both phase boundaries were observed. This can be lower than `latency_ms.observations` when capture starts late or packets are missing. |
| Phase `average`, `min`, `p95`, `p99`, `max`, `total` | The same aggregates as the outer latency fields, calculated only over phase observations. |

`incomplete_observed_duration_ms` uses the same `observations`, `average`, `min`, `p95`, `p99`, `max`, and `total` fields. Its values measure how long incomplete requests were observable before a connection close, capture end, TCP gap, protocol error, or another incomplete condition. They must not be interpreted as database execution latency.

`capture` fields:

| Field | Meaning |
| --- | --- |
| `packets_seen` | Packets delivered by the capture source to pgsniffer. |
| `packets_matched` | Packets matched to the configured server endpoint after decoding. |
| `bytes_captured` | Captured bytes delivered to pgsniffer. |
| `truncated_packets` | Packets whose captured length was smaller than their original wire length. |
| `kernel_packets_received` | Packets reported as received by the live-capture backend; zero for offline files or unsupported backends. |
| `kernel_packets_dropped` | Packets dropped by the live-capture kernel buffer. |
| `interface_packets_dropped` | Packets reported dropped by the network interface or capture backend. |
| `tcp_gap_events` | TCP reassembly gaps where bytes were missing from the captured stream. |
| `tcp_bytes_skipped` | Number of bytes skipped across TCP gaps. |
| `tcp_sequence_discontinuities` | Gaps larger than the safe accounting limit, usually indicating sequence discontinuity, tuple reuse, or severely damaged capture data. Their untrusted byte distance is not added to `tcp_bytes_skipped`. |
| `largest_tcp_gap_bytes` | Largest observed TCP sequence distance, including discontinuities. |
| `connections_observed` | TCP connection streams created by the reassembler. |
| `startup_observed_connections` | Connections for which PostgreSQL StartupMessage was decoded. |
| `midstream_connections` | Connections first observed after their TCP handshake. |
| `protocol_state_loss_connections` | Connections disabled after a TCP gap or PostgreSQL decode failure. Their later traffic is not attributed to SQL. |
| `statistics_errors` | Failures while reading capture-backend statistics. |

`data_quality.completed_queries` is the number included in latency statistics. `excluded_queries` contains incomplete requests and `excluded_percentage` is calculated over completed plus excluded requests. `metadata_missing_queries` counts requests without a startup user or database. These counters cover all admitted events and are not reduced by `--max-groups`.

`user` and `database` are taken from StartupMessage, and a fully observed StartupMessage without a user is rejected as malformed. If `startup_observed` is false, the protocol decoder began from a later typed frontend message even when the capture process itself was already running; check the selected interface, endpoint direction, capture drops, and whether a proxy or existing upstream connection sits between pgsniffer and PostgreSQL.

`incomplete_reasons` can include `connection_closed`, `capture_or_idle_timeout`, `tcp_gap`, `protocol_error`, `client_terminated`, `pending_limit`, `operation_limit`, `sync_without_completion`, `aborted_after_error`, `command_tag_mismatch`, and `aborted_after_mismatch`. A command mismatch identifies only the request whose expected and actual command tags conflict; other requests in that Sync Group are excluded as aborted. `protocol_issues` also reports unknown prepared statements or portals, which commonly occur on midstream connections. Nonzero capture drops, truncated packets, TCP gaps, or protocol-state loss mean the report may be incomplete.

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

- Simple Query: complete client `Q` through complete server `ReadyForQuery`.
- Extended Query: complete client `Execute` through complete `CommandComplete`, `PortalSuspended`, or `ErrorResponse`.
- `first_response` ignores Extended Query `ParseComplete`, `BindComplete`, and Describe responses; it starts only on a response attributable to Execute.
- Interrupted requests use the last observed packet timestamp, are marked incomplete, and are reported under `incomplete_observed_duration_ms` instead of `latency_ms`.

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
