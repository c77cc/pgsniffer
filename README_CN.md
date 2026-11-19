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

Linux 安装包使用 `AF_PACKET`/`TPACKET_V3` 共享内存环形缓冲，不依赖外部运行库。macOS 使用系统自带的 libpcap，无需额外安装抓包库。Windows 实时抓包和枚举网卡需要安装 [Npcap Installer](https://npcap.com/#download)，无需安装 Npcap SDK；离线分析 PCAP/PCAPNG 不依赖 Npcap。

## 快速使用

列出抓包网卡：

```bash
./pgsniffer --list-interfaces
```

Windows 下将列表中的 `Device` 值复制给 `--interface`。抓取本机 PostgreSQL 流量时使用 Npcap 回环设备，例如：

```powershell
.\pgsniffer.exe --interface '\Device\NPF_Loopback' --server 127.0.0.1:5432
```

持续抓取 PostgreSQL 服务端流量，按 `Ctrl-C` 后输出 JSON 报告：

```bash
sudo ./pgsniffer --interface eth0 --server 10.0.0.8:5432 > report.json
```

成功打开网卡并安装抓包过滤器后，pgsniffer 会将运行状态输出到 stderr：

```text
pgsniffer: capture started interface="eth0" server="10.0.0.8:5432" filter="host 10.0.0.8 and tcp port 5432"
pgsniffer: waiting for PostgreSQL traffic; press Ctrl+C to stop and print the report
pgsniffer: PostgreSQL traffic detected
pgsniffer: SQL capture is working
```

如果 10 秒后仍没有匹配流量或没有解析到完整 SQL，pgsniffer 会输出对应的排查提示。检测到 TLS/GSS 会话时也会明确说明加密 SQL 无法解析。停止抓包时，一行运行摘要会写入 stderr，完整 JSON 报告仍写入 stdout，因此将 stdout 重定向到 `report.json` 不受影响。

分析已有 PCAP：

```bash
./pgsniffer --read-pcap traffic.pcap --server 10.0.0.8:5432
```

`--server` 为必填参数，格式是 IP 字面量加端口。IPv6 需要使用方括号，例如 `--server '[::1]:5432'`。执行 `./pgsniffer -h` 可查看全部参数。

报告默认丢弃原始 SQL 值。`--log-queries` 会在抓包期间把每条已完成查询的原始 SQL 实时输出到 stderr；`--group-by raw-sql` 会关闭指纹聚合，改为按完整原始 SQL 分组和输出。这两个选项都可能暴露敏感值。报告默认采用 `--group-by fingerprint`。

```bash
# 在终端逐条实时输出原始 SQL。
sudo ./pgsniffer --interface eth0 --server 10.0.0.8:5432 --log-queries

# 最终报告按原始 SQL 分组，不使用指纹。
sudo ./pgsniffer --interface eth0 --server 10.0.0.8:5432 --group-by raw-sql
```

## 命令行参数

| 参数 | 说明 |
| --- | --- |
| `--server IP:PORT` | PostgreSQL 服务端地址。实时抓包和 PCAP 回放时必填；IPv6 地址必须使用方括号。 |
| `--interface INTERFACE` | 实时抓包使用的网卡，默认值因平台而异。 |
| `--list-interfaces` | 列出可用抓包网卡并退出。 |
| `--read-pcap FILE` | 分析 PCAP/PCAPNG 文件，不进行实时抓包。 |
| `--group-by MODE` | 按 `fingerprint` 或 `raw-sql` 聚合报告（默认：`fingerprint`）；原始 SQL 可能暴露敏感值。 |
| `--log-queries` | 将每条已完成查询的原始 SQL 输出到 stderr，可能暴露敏感值。 |
| `--max-groups COUNT` | 按最大耗时排序后最多输出的 SQL 分组数（默认：`50`；`0` 表示全部）。 |
| `--listen ADDRESS` | 提供 `/healthz`、`/report` 和 `/metrics`，例如 `127.0.0.1:9108`。 |
| `--report-interval DURATION` | 周期性 JSONL 报告的时间间隔，例如 `1m`；必须同时设置 `--report-file`。 |
| `--report-file FILE` | 追加写入周期性 JSONL 报告；必须同时设置 `--report-interval`。 |
| `--version` | 输出版本号并退出。 |
| `-h`、`--help` | 显示命令行帮助并退出。 |

## 长期运行与实时观测

启用只监听本机的 HTTP 接口：

```bash
sudo ./pgsniffer --interface eth0 --server 10.0.0.8:5432 --listen 127.0.0.1:9108
```

可用端点：

- `GET /healthz`：存活检查。
- `GET /report`：当前累计 JSON 报告，遵循 `--max-groups` 限制。
- `GET /metrics`：Prometheus 文本指标，包含全部有界 SQL 聚合。

周期性追加 JSONL 快照：

```bash
sudo ./pgsniffer --interface eth0 --server 10.0.0.8:5432 \
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
    "midstream_connections": 0,
    "statistics_errors": 0
  },
  "encrypted_sessions": 0,
  "decode_errors": 0,
  "dropped_query_keys": 0
}
```

顶层字段：

| 字段 | 含义 |
| --- | --- |
| `generated_at` | 生成当前累计报告快照的时间。 |
| `queries` | 应用分组模式、维度、排序和 `--max-groups` 后的 SQL 分组。 |
| `capture` | 抓包健康状态和数据完整性计数。 |
| `encrypted_sessions` | 已识别但无法解码的 TLS/GSS 会话数。 |
| `decode_errors` | 数据包、TCP 流或 PostgreSQL 协议解码失败次数。 |
| `dropped_query_keys` | 因有界聚合容量已满、无法接纳新的“SQL 与维度”键而被归入溢出组的查询事件数。 |

每个 `queries` 记录的字段：

| 字段 | 含义 |
| --- | --- |
| `fingerprint` | 默认模式下作为分组键的归一化 SQL。字面量会被替换，标识符和 `$1` 等占位符会保留。 |
| `query` | `--group-by raw-sql` 模式下作为分组键的完整原始 SQL，用来替代 `fingerprint`。 |
| `dimensions.user` | PostgreSQL 启动报文中的用户。 |
| `dimensions.database` | PostgreSQL 启动报文中的数据库；客户端未指定时默认等于用户。 |
| `dimensions.application_name` | 客户端提供的 `application_name`。 |
| `dimensions.client_address` | 从抓取连接中观察到的客户端 IP 地址。 |
| `calls` | 当前“SQL 与维度”分组中观察到的请求数量。 |
| `errors` | 观察到 PostgreSQL 错误码或错误消息的请求数量。 |
| `incomplete` | 未获得完整响应的请求数量，其耗时结束于最后一个可用时间戳。 |
| `rows_affected` | PostgreSQL `CommandComplete` 标签报告的行数总和，包括查询返回或数据修改的行数。 |
| `command_tags` | 按 PostgreSQL 命令标签统计的次数，例如 `SELECT`、`INSERT`、`UPDATE`。 |
| `sqlstates` | 可选，按五位 PostgreSQL SQLSTATE 错误码统计的次数。 |
| `error_severities` | 可选，按 PostgreSQL 错误级别统计的次数。 |
| `transaction_status_before` | 按执行前事务状态统计的次数：`idle`、`in_transaction` 或 `failed_transaction`。 |
| `incomplete_reasons` | 可选，未完整请求的原因计数。 |
| `latency_ms` | 以毫秒表示的观察耗时聚合。 |

`latency_ms` 字段：

| 字段 | 含义 |
| --- | --- |
| `average` | 当前分组全部调用的算术平均耗时。 |
| `min` / `max` | 观察到的最小和最大耗时。 |
| `p95` / `p99` | 由有界耗时直方图计算的近似分位数，且不会超过实际观察到的最大值。 |
| `total` | 当前分组全部调用的观察耗时总和。 |
| `first_response` | 从完整客户端 Query/Execute 消息到第一个归属于该请求的服务端响应开始之间的耗时，包含服务端等待/执行以及首响应往返抓包点的网络时间。 |
| `response_transfer` | 从第一个归属响应开始到终止响应完整到达之间的耗时，可能包含服务端后续执行、行序列化和网络传输；对于 COPY 还可能包含 COPY 数据交换。 |
| `first_response.observations` / `response_transfer.observations` | 成功观察到两个分段边界的调用数。抓包中途开始、丢包或请求中断时可能少于 `calls`。 |
| 分段中的 `average`、`min`、`p95`、`p99`、`max`、`total` | 与外层同名字段含义一致，但只基于成功获得分段时间的调用。 |

`capture` 字段：

| 字段 | 含义 |
| --- | --- |
| `packets_seen` | 抓包来源交给 pgsniffer 的数据包数。 |
| `packets_matched` | 解码后匹配所配置 PostgreSQL 服务端地址的数据包数。 |
| `bytes_captured` | 交给 pgsniffer 的抓取字节数。 |
| `truncated_packets` | 抓取长度小于线上原始长度的数据包数。 |
| `kernel_packets_received` | 实时抓包后端报告的内核接收包数；离线文件或不支持的后端为零。 |
| `kernel_packets_dropped` | 实时抓包内核缓冲区丢弃的数据包数。 |
| `interface_packets_dropped` | 网卡或抓包后端报告的丢包数。 |
| `tcp_gap_events` | TCP 重组时发现捕获流中缺少字节的次数。 |
| `tcp_bytes_skipped` | TCP 缺口累计跳过的字节数。 |
| `midstream_connections` | 在 TCP 握手完成之后才开始观察到的连接数。 |
| `statistics_errors` | 读取抓包后端统计信息失败的次数。 |

`incomplete_reasons` 可能包含 `connection_closed`、`capture_or_idle_timeout`、`tcp_gap`、`protocol_error`、`client_terminated`、`pending_limit`、`operation_limit`、`sync_without_completion` 和 `aborted_after_error`。抓包丢包、截断包或 TCP 缺口非零时，报告可能不完整。

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

- Simple Query：从完整客户端 `Q` 到完整服务端 `ReadyForQuery`。
- Extended Query：从完整客户端 `Execute` 到完整服务端 `CommandComplete`、`PortalSuspended` 或 `ErrorResponse`。
- `first_response` 会忽略 Extended Query 的 `ParseComplete`、`BindComplete` 和 Describe 响应，只从归属于 Execute 的响应开始计算。
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
