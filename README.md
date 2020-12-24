PgSniffer is a command-line tool, capture PostgreSQL network traffic, calculate slow-sql-log.

<img src="https://github.com/c77cc/pgsniffer/blob/master/example.gif" width="30%" height="30%">
[Origin Image](https://raw.githubusercontent.com/c77cc/pgsniffer/master/example.gif)

## Why PgSniffer
---
* Forgot open log_min_duration_statement? Edit the configuration file and restart pg-server, so trouble...
* Slow SQL list, SQL number of calls.
* Minimize effect the production environment.


## Compile Installation
---
#### Mac OS / Linux

You need install libpcap on Linux platform.

```
yum install libpcap-devel -y
```

```
make
```

#### Windows
* Install mingw32
* Install npcap for windows <https://nmap.org/npcap/>

```
make win
```

## Usage
---
```
sudo ./pgsniffer -i lo0
```

## Options
---
```
-i         lo0                        device interface
-l                                    list all device interface
-f        "tcp port 5432"             port and direction
-n         50                         show top-n slowest sql
-v                                    output all sqls captured
```

### TODO
---
* Get PostgreSQL basic performance data
* Automatically saved to a capture file
* SQL index hit Analysis
