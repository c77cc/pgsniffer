# PgSniffer

PgSniffer 是一个旁路 PostgreSQL 流量分析工具。它重组 TCP 流、解析 Simple Query 和 Extended Query 协议，并按脱敏 SQL 指纹统计调用量、错误量和耗时，无需修改 PostgreSQL 日志配置。

[English](README.md)

## 主要能力

- 使用抓包时间戳进行实时流量和离线 PCAP 分析。
- 支持 Simple Query、prepared statement、Bind、Execute、拆包、粘包和并发连接。
- 统计调用量、错误量、未完成请求、平均、p95、p99、最大和总耗时。
- 报告抓包丢包、截断包、TCP 缺口和中途开始的连接。
- 按用户、数据库、应用和客户端分组，并统计命令标签、影响行数、SQLSTATE、错误级别和事务上下文。
- 默认脱敏 SQL 字面量，并使用有界内存聚合。
- 检测 TLS/GSS 加密连接并单独计数。

## 安装

[GitHub Releases](https://github.com/c77cc/pgsniffer/releases) 提供安装包及 SHA-256 校验文件：

- Linux AMD64
- Linux ARM64
- macOS Intel
- macOS Apple Silicon
- Windows x64

Linux 安装包使用 `AF_PACKET`/`TPACKET_V3` 共享内存环形缓冲，不依赖外部运行库。macOS 使用系统自带的 libpcap，无需额外安装抓包库。Windows 仅在实时抓包和枚举网卡时需要安装 [Npcap](https://npcap.com/)；离线分析 PCAP/PCAPNG 不依赖 Npcap。

## 快速使用

列出抓包网卡：

```bash
./pgsniffer -l
```

持续抓取 PostgreSQL 服务端流量，按 `Ctrl-C` 后输出 JSON 报告：

```bash
sudo ./pgsniffer -i eth0 --server 10.0.0.8:5432 > report.json
```

分析已有 PCAP：

```bash
./pgsniffer --read-pcap traffic.pcap --server 10.0.0.8:5432
```

`--server` 为必填参数，格式是 IP 字面量加端口。IPv6 需要使用方括号，例如 `--server '[::1]:5432'`。执行 `./pgsniffer -h` 可查看全部参数。

程序默认丢弃原始 SQL 值。`--show-query-values` 会保留这些值，可能暴露敏感数据；`-v` 可在抓包期间记录已完成的查询。

## 输出

所有耗时单位均为毫秒：

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

`incomplete` 表示没有获得完整响应的请求数量。`incomplete_reasons` 会区分连接关闭、抓包结束或空闲超时、TCP 缺口、协议错误，以及流水线出错后被跳过的请求。抓包丢包、截断包或 TCP 缺口非零时，报告可能不完整。`dropped_query_keys` 表示达到有界聚合上限后被合并的新“SQL 指纹与维度”组合数量。

## 耗时语义

- Simple Query：从客户端 `Q` 到服务端 `ReadyForQuery`。
- Extended Query：从客户端 `Execute` 到服务端 `CommandComplete`、`PortalSuspended` 或 `ErrorResponse`。
- 请求被中断时使用最后一个已观测数据包的时间戳，并标记为 `incomplete`。

## 限制与安全

- 普通抓包无法解析 TLS/GSS 加密后的 PostgreSQL 载荷，只会统计加密连接数量。
- 执行计划、索引和缓存命中率不在线协议中，需要使用 `EXPLAIN`、`pg_stat_statements` 或 `pg_stat_user_indexes`。
- PgSniffer 不会主动连接 PostgreSQL，也不会执行 SQL。
- 原始 SQL 和 PCAP 可能包含敏感数据，应限制访问和保留时间。
- 实时抓包通常需要管理员权限，Linux 也可授予 `CAP_NET_RAW`/`CAP_NET_ADMIN` capability。

## 从源码构建

需要 Go 1.26.11+。Linux 构建不需要 libpcap；macOS 使用系统提供的 libpcap。

```bash
make build
go test ./...

# 可选的 Docker 端到端测试
make e2e
```

可执行文件输出到 `bin/pgsniffer`。

## License

[MIT](LICENSE)
