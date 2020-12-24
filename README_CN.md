PgSniffer是一个命令行工具，通过抓取PostgreSQL流量，计算出慢SQL

<img src="https://github.com/c77cc/pgsniffer/blob/master/example.gif" width="30%" height="30%">
[Origin Image](https://raw.githubusercontent.com/c77cc/pgsniffer/master/example.gif)

## 解决了什么问题
---
* 忘记开启log_min_duration_statement？修改配置文件再次重启pg-server，好麻烦。。。
* SQL慢列表，SQL调用次数。
* 最小化影响生产环境。
* 绿色小工具，依赖少(仅依赖pcap)，使用方便灵活

## 编译安装
---
#### linux

Linux平台需要安装libpcap
```
yum install libpcap-devel -y
```

```
make
```

#### Windows
* 安装mingw32
* 安装npcap for windows <https://nmap.org/npcap/>

```
make win
```

## 使用方法
---
```
./pgsniffer -i lo0
```

## 可选参数
---
```
-i         lo0                        监听的网卡名称
-l                                    列出所有网卡信息
-f        "tcp port 5432"             监听的端口
-n         50                         结果显示最慢的N条SQL
-v                                    打印捕捉到的每一条SQL
```

### TODO
---
* 获取PostgreSQL基本性能数据
* 自动保存抓包到文件
* sql索引命中分析
