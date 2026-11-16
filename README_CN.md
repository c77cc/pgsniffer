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
- 规范化 PostgreSQL 字符串、数值、布尔值、`IN` 列表和批量 `VALUES`，减少等价 SQL 产生重复指纹。
- 检测 TLS/GSS 加密连接并单独计数。
- 可通过 HTTP 实时提供健康状态、JSON 报告和 Prometheus 指标，并支持周期 JSONL 快照。

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

报告默认丢弃原始 SQL 值。`--log-queries` 会在抓包期间把每条已完成查询的原始 SQL 实时输出到 stderr；`--group-by raw-sql` 会关闭指纹聚合，改为按完整原始 SQL 分组和输出。这两个选项都可能暴露敏感值。报告默认采用 `--group-by fingerprint`。

```bash
# 在终端逐条实时输出原始 SQL。
sudo ./pgsniffer -i eth0 --server 10.0.0.8:5432 --log-queries

# 最终报告按原始 SQL 分组，不使用指纹。
sudo ./pgsniffer -i eth0 --server 10.0.0.8:5432 --group-by raw-sql
```

## 长期运行与实时观测

启用只监听本机的 HTTP 接口：

```bash
sudo ./pgsniffer -i eth0 --server 10.0.0.8:5432 --listen 127.0.0.1:9108
```

可用端点：

- `GET /healthz`：存活检查。
- `GET /report`：当前累计 JSON 报告，遵循 `-n` 限制。
- `GET /metrics`：Prometheus 文本指标，包含全部有界 SQL 聚合。

周期性追加 JSONL 快照：

```bash
sudo ./pgsniffer -i eth0 --server 10.0.0.8:5432 \
  --listen 127.0.0.1:9108 \
  --report-interval 1m \
  --report-file /var/log/pgsniffer/reports.jsonl
```

报告文件使用仅当前用户可读写的权限创建。HTTP 没有内置认证，报告和指标可能包含数据库、用户、客户端地址、SQL 指纹；启用 `--group-by raw-sql` 后还会包含原始 SQL。除非前面有受信任的认证代理，否则不要监听公网地址。

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

`incomplete` 表示没有获得完整响应的请求数量。`incomplete_reasons` 会区分连接关闭、抓包结束或空闲超时、TCP 缺口、协议错误，以及流水线出错后被跳过的请求。抓包丢包、截断包或 TCP 缺口非零时，报告可能不完整。`dropped_query_keys` 表示达到有界聚合上限后被合并的新“SQL 与维度”组合数量。

启用 `--group-by raw-sql` 后，每条记录按完整原始 SQL 分组，并使用 `query` 字段替代 `fingerprint`：

```json
{
  "query": "SELECT * FROM users WHERE id = 123",
  "calls": 1
}
```

这种模式下，仅字面量值不同的 SQL 也会成为不同分组。
对于 Extended Query 协议，PostgreSQL 会分别传输 SQL 文本和绑定值；`--log-queries` 与 `--group-by raw-sql` 展示的是包含 `$1` 等占位符的原始 SQL 文本，不会拼接生成一条新的 SQL。

## 耗时语义

- Simple Query：从客户端 `Q` 到服务端 `ReadyForQuery`。
- Extended Query：从客户端 `Execute` 到服务端 `CommandComplete`、`PortalSuspended` 或 `ErrorResponse`。
- 请求被中断时使用最后一个已观测数据包的时间戳，并标记为 `incomplete`。

## SQL 指纹语义

- SQL 关键字和未加引号的标识符转换为小写，空白、标点和运算符采用统一格式。
- 字符串、dollar-quoted 字符串、数值、布尔值和 `NULL` 归一化为 `?`；`$1` 形式的绑定参数保留。
- 仅含字面量或绑定参数的 `IN (...)` 和 `ARRAY[...]` 列表折叠为单个占位符。
- 多行 `VALUES` 保留第一行结构，并用 `...` 表示其余行，从而避免批量大小导致指纹分裂。
- 双引号和 `U&"..."` 标识符保留大小写和内容。

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
