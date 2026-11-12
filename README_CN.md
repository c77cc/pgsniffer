# PgSniffer

PgSniffer 是一个旁路 PostgreSQL 流量分析工具。它重组 TCP 流、理解 PostgreSQL Simple Query 和 Extended Query 协议，并按 SQL 指纹统计调用量、错误量和延迟分位数，无需修改数据库日志配置。

[English](README.md)

## 主要能力

- 按 TCP 四元组隔离连接，双向关联请求与响应。
- 支持拆包、粘包、Simple Query、prepared statement、Bind 和 Execute。
- 使用抓包时间戳计算耗时；可读取离线 PCAP 文件。
- 默认将字符串和数字字面量替换为 `?`，避免高基数和敏感数据泄漏。
- 使用固定空间直方图输出平均值、p95、p99 和最大耗时。
- 输出稳定的 JSON 报告，便于程序处理。
- 检测 TLS/GSS 加密连接，并明确计数为不可解析连接。

## 环境要求

- Go 1.26.11 或更高版本（构建产物需要包含对应的标准库安全修复）。
- libpcap 开发库。

Linux：

```bash
sudo apt-get install libpcap-dev
# 或 sudo yum install libpcap-devel
```

macOS：系统通常已经提供 libpcap。Windows 建议安装 Npcap SDK。

## 构建和测试

```bash
make build
go test ./...
go test -race ./...
```

可执行文件输出到 `bin/pgsniffer`。`bin/` 和 `dist/` 下的构建产物都由 Git 忽略；CI 构建的 Linux 二进制通过 GitHub Actions artifact 提供，不再将二进制提交到源码仓库。

## Docker 端到端测试

端到端测试默认不随 `go test ./...` 执行。它会构建 PgSniffer，使用随机端口和唯一名称启动隔离的 PostgreSQL 容器，抓取真实回环流量，并将实时报告与同一份 PCAP 的离线回放结果逐项比较。宿主机无需安装 `psql` 或 PostgreSQL 驱动。

```bash
# Docker 需要处于运行状态；macOS 默认 lo0，Linux 默认 lo
make e2e

# 连续执行三次，用于发现生命周期或抓包时序抖动
make e2e-repeat

# 切换 PostgreSQL 镜像或抓包网卡
PGSNIFFER_POSTGRES_IMAGE=postgres:12 make e2e
PGSNIFFER_E2E_INTERFACE=lo0 make e2e
```

当前固化场景包括 Simple Query、多语句事务、`COPY TO STDOUT`、SQL 错误、CancelRequest、命名 prepared statement/portal、文本参数、扩展协议流水线、并发连接、TLS 识别、数据库进程异常中止、未完成请求耗时，以及实时/离线结果一致性。每次运行只清理自己创建的容器和卷。

成功时会删除临时产物；失败时保留 PCAP 和 JSON 报告并打印目录。设置 `PGSNIFFER_E2E_ARTIFACTS=.artifacts/e2e` 可保留每次执行结果。Linux 普通用户没有抓包权限时可设置 `PGSNIFFER_E2E_SUDO=1`；CI 更适合使用 `PGSNIFFER_E2E_SETCAP=1` 配合免密 `sudo setcap`。

这套用例是发布回归基线，不等同于完整网络设备认证。SCRAM/GSS 认证交换、IPv6/VLAN 链路、主动制造丢包/乱序，以及长时间压力/浸泡测试仍属于独立兼容性场景。

## 使用

列出网卡：

```bash
./bin/pgsniffer -l
```

实时抓取默认 PostgreSQL 端口：

```bash
sudo ./bin/pgsniffer -i lo0 --server 127.0.0.1:5432
```

读取离线文件：

```bash
./bin/pgsniffer --read-pcap traffic.pcap --server 10.0.0.8:5432
```

输出 JSON 报告；需要文件时使用标准输出重定向：

```bash
sudo ./bin/pgsniffer -i eth0 --server 10.0.0.8:5432 > report.json
```

常用参数：

```text
-i                    抓包网卡，默认 lo0
--server              PostgreSQL 服务端 IP:PORT；用于自动过滤流量并识别方向
-n                    输出前 N 个 SQL 指纹，0 表示全部
--read-pcap            分析已有 PCAP
-v                    实时记录完成的查询
--show-query-values    显示并保存原始 SQL；可能包含敏感信息
```

`--server` 必须使用 IP 字面量和端口。PgSniffer 会据此自动生成 BPF，并通过同一个 IP 和端口区分客户端请求与服务端响应。IPv6 使用方括号，例如 `--server '[::1]:5432'`。

## 耗时语义

- Simple Query：从客户端 `Q` 消息到服务端 `ReadyForQuery`。
- Extended Query：从客户端 `Execute` 到服务端 `CommandComplete`、`PortalSuspended` 或 `ErrorResponse`。
- 连接在请求完成前中断时，该请求会标记为 `incomplete`。

## 限制

TLS 或 GSS 加密后的 PostgreSQL 载荷无法通过普通抓包解析。PgSniffer 会统计这类连接，但不会尝试绕过加密。

索引命中率、执行计划、缓存命中率等信息不在线协议中，需另外结合 `EXPLAIN`、`pg_stat_statements` 和 `pg_stat_user_indexes`。本项目不会主动连接数据库，也不会在抓包过程中执行 SQL。

## 安全建议

- 默认保持 SQL 脱敏，不要在生产环境随意开启 `--show-query-values`。
- Linux 上可授予二进制 `CAP_NET_RAW`/`CAP_NET_ADMIN`，避免长期使用 root 运行。
- PCAP 文件可能包含完整业务数据，应限制访问并设置独立的轮转与保留策略。

## License

MIT
