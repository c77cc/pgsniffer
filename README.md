PgSniffer is a command-line tool, capture PostgreSQL network traffic, calculate slow-sql-log.

## Why PgSniffer
---
* Forgot open log_min_duration_statement? Edit the configuration file and restart pg-server, so trouble...
* Slow SQL list, SQL number of calls.
* Minimize effect the production environment.

## Binary Installation
---
* bin/ directory

## Compile Installation
---
#### Linux

```
`Universal`

{OS}:windows, linux, drawin, freebsd

{ARCH}: amd64, 386, arm

```
GOOS={OS} GOARCH={ARCH} go build -o pgsniffer sniffer.go
```

`Mac OS X 64bit`

```
GOOS=darwin GOARCH=amd64 go build -o pgsniffer sniffer.go

#### Windows
* Install gcc(mingw64bit) <http://heanet.dl.sourceforge.net/project/mingw-w64/Toolchains%20targetting%20Win32/Personal%20Builds/mingw-builds/installer/mingw-w64-install.exe>
* Install pcap-devel for windows <https://www.winpcap.org/install/bin/WpdPack_4_1_2.zip> <http://www.winpcap.org/install/bin/WinPcap_4_1_3.exe>
* Extract WpdPack_4_1_2.zip to C:\
* Currently not support listening 127.0.0.1 on Windows.

`Windows 64bit`

```
GOOS=windows GOARCH=amd64 go build -o pgsniffer.exe sniffer.go

```


## Usage
---
```
sudo ./pgsniffer -i lo0 -f "tcp port 5432"
```

## Options
---
```
-i 		lo0						device interface
-l                              list all device interface
-f		"tcp port 5432"			port and direction
-n 		50						show top-n slowest sql
-v 								output all sqls captured
```

### TODO
---
* Get PostgreSQL basic performance data
* Automatically saved to a capture file
* SQL index hit Analysis

# License
---
The MIT License
