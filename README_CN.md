PgSniffer是一个命令行工具，通过抓取PostgreSQL流量，计算出slow-sql-log

<img src="https://github.com/c77cc/pgsniffer/blob/master/example.gif" width="30%" height="30%">
[Origin Image](https://raw.githubusercontent.com/c77cc/pgsniffer/master/example.gif)

## 解决了什么问题
---
* 忘记开启log_min_duration_statement？修改配置文件再次重启pg-server，好麻烦。。。
* SQL慢列表，SQL调用次数。
* 最小化影响生产环境。

## 二进制安装
---
* [Mac OS 64bit](https://raw.githubusercontent.com/c77cc/pgsniffer/master/bin/pgsniffer.darwin64bit)
* [Linux 64bit](https://raw.githubusercontent.com/c77cc/pgsniffer/master/bin/pgsniffer.linux64bit)
* [Windows 64bit](https://raw.githubusercontent.com/c77cc/pgsniffer/master/bin/pgsniffer.win64bit.exe)

## 编译安装
---
#### linux

Linux平台需要安装libpcap
```
yum install libpcap-devel -y
```

`通用版`

{OS}:windows, linux, drawin, freebsd

{ARCH}: amd64, 386, arm

```
GOOS={OS} GOARCH={ARCH} go build -o pgsniffer sniffer.go
```

`Mac OS X 64bit`

```
GOOS=darwin GOARCH=amd64 go build -o pgsniffer sniffer.go

```

#### Windows
* 安装gcc <http://heanet.dl.sourceforge.net/project/mingw-w64/Toolchains%20targetting%20Win32/Personal%20Builds/mingw-builds/installer/mingw-w64-install.exe>
* 安装pcap for windows <https://www.winpcap.org/install/bin/WpdPack_4_1_2.zip> <http://www.winpcap.org/install/bin/WinPcap_4_1_3.exe>
* 将WpdPack_4_1_2.zip解压到C:\WpdPack
* 目前Windows不支持监听127.0.0.1

`Windows 64bit`

```
GOOS=windows GOARCH=amd64 go build -o pgsniffer.exe sniffer.go

```


## 使用方法
---
```
sudo ./pgsniffer -i lo0 -f "tcp port 5432"
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

# License
---
The MIT License

