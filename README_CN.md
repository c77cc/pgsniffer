# PgSniffer

PgSniffer 是一个旁路 PostgreSQL 流量分析工具。它重组 TCP 流、解析 Simple Query 和 Extended Query 协议，并按脱敏 SQL 指纹统计调用量、错误量和耗时，无需修改 PostgreSQL 日志配置。

[English](README.md)

## 主要能力

- 使用抓包时间戳进行实时流量和离线 PCAP 分析。
- 支持 Simple Query、prepared statement、Bind、Execute、拆包、粘包和并发连接。
- 统计调用量、错误量、未完成请求、平均、p95、p99、最大和总耗时。
- 默认脱敏 SQL 字面量，并使用有界内存聚合。
- 检测 TLS/GSS 加密连接并单独计数。

## 安装

[GitHub Releases](https://github.com/c77cc/pgsniffer/releases) 提供安装包及 SHA-256 校验文件：

- Linux AMD64
- Linux ARM64
- Windows x64

Linux 运行时需要 libpcap；Windows 运行时需要安装 [Npcap](https://npcap.com/)。

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

`incomplete` 表示连接在完整响应前关闭的请求数量；`dropped_query_keys` 表示达到有界聚合上限后被合并的新 SQL 指纹数量。

## 耗时语义

- Simple Query：从客户端 `Q` 到服务端 `ReadyForQuery`。
- Extended Query：从客户端 `Execute` 到服务端 `CommandComplete`、`PortalSuspended` 或 `ErrorResponse`。
- 请求被中断时使用最后一个已观测数据包的时间戳，并标记为 `incomplete`。

## 限制与安全

- 普通抓包无法解析 TLS/GSS 加密后的 PostgreSQL 载荷，只会统计加密连接数量。
- 执行计划、索引和缓存命中率不在线协议中，需要使用 `EXPLAIN`、`pg_stat_statements` 或 `pg_stat_user_indexes`。
- PgSniffer 不会主动连接 PostgreSQL，也不会执行 SQL。
- 原始 SQL 和 PCAP 可能包含敏感数据，应限制访问和保留时间。
- 抓包通常需要管理员权限，Linux 也可授予 `CAP_NET_RAW`/`CAP_NET_ADMIN` capability。

## 从源码构建

类 Unix 系统需要 Go 1.26.11+ 和 libpcap 开发文件。

```bash
make build
go test ./...

# 可选的 Docker 端到端测试
make e2e
```

可执行文件输出到 `bin/pgsniffer`。

## License

[MIT](LICENSE)
