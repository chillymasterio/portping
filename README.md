# portping

**Like `ping`, but for TCP ports.**

```
$ portping google.com 443

PORTPING google.com:443 (142.250.74.46) — DNS 12.4 ms

  [1] google.com:443  open  12.3 ms
  [2] google.com:443  open  11.8 ms
  [3] google.com:443  open  12.1 ms
  ^C
--- google.com:443 portping statistics ---
3 attempts, 3 open, 0 refused, 0 timeout/error (0% loss)
rtt min/avg/max/jitter = 11.8/12.1/12.3/0.2 ms
```

## Why?

`ping` tells you a host is alive. It doesn't tell you if port 443 is accepting connections, if your firewall rules work, or if that Redis on port 6379 is actually listening.

`portping` does.

- **Zero dependencies** — single C file, compiles everywhere
- **Cross-platform** — Windows, Linux, macOS
- **Scriptable** — exit code 0 = at least one connection succeeded
- **Familiar** — same flags and output style as `ping`

## Install

### Build from source

```bash
cmake -B build
cmake --build build
# binary is at build/portping (or build/Release/portping.exe on Windows)
```

Or just compile directly:

```bash
# Linux / macOS
gcc -O2 -o portping portping.c -lm

# Windows (MSVC)
cl portping.c ws2_32.lib
```

### Download

Grab a prebuilt binary from [Releases](https://github.com/chillymasterio/portping/releases/latest).

## Usage

```
portping [options] <host> <port>

Options:
  -c <count>     Number of attempts (default: infinite)
  -t <ms>        Timeout per attempt in ms (default: 2000)
  -i <ms>        Interval between attempts in ms (default: 1000)
  -4             Force IPv4
  -6             Force IPv6
  -T             Show timestamp on each line
  -q             Quiet mode — only show summary
  -b             Grab service banner after connect
  -H <path>      HTTP health check (GET path, show status)
  -A             Alert (beep) on state change
  -w <sec>       Stop after <sec> seconds total (deadline)
  --csv          Output in CSV format
  --json         Output summary as JSON
  --no-color     Disable colored output
  -V, --version  Show version
  -h             Show help
```

### Examples

```bash
# Check if HTTPS is open
portping example.com 443

# 5 attempts with 500ms timeout
portping -c 5 -t 500 192.168.1.1 22

# Fast polling — 200ms interval
portping -c 20 -i 200 db-server 5432

# Force IPv4
portping -4 example.com 443

# Scan multiple ports at once
portping myserver.com 22,80,443,3306,8080

# Port range scan
portping myserver.com 8080-8090

# Mixed ranges and individual ports
portping myserver.com 22,80-85,443,8080-8082

# Grab service banners (SSH, SMTP, FTP, etc.)
portping -b -c 1 myserver.com 22

# Run for exactly 30 seconds with timestamps
portping -T -w 30 db-server 5432

# HTTP health check
portping -H /health -c 10 api-server 8080

# JSON output for automation
portping --json -c 5 prod-api 443

# CSV output for monitoring
portping --csv -c 100 prod-api 443 > log.csv

# Alert when port state changes (beeps on DOWN/UP transitions)
portping -A prod-db 5432

# Quiet mode — just the summary
portping -q -c 10 example.com 443

# Script: wait for a service to come up
until portping -c 1 -t 1000 localhost 8080 > /dev/null 2>&1; do
    sleep 1
done
echo "Service is up!"
```

### Multi-port scan

Pass comma-separated ports to scan all of them at once:

```
$ portping myserver.com 22,80,443,3306

  Scanning myserver.com ports: 22,80,443,3306

  22     myserver.com:22  open     8.2 ms
  80     myserver.com:80  open     7.9 ms
  443    myserver.com:443  open     8.1 ms
  3306   myserver.com:3306  refused  7.5 ms

  3/4 ports open
```

### Output

| Status | Meaning |
|---|---|
| `open` | TCP connection accepted |
| `refused` | Port actively rejected (RST) |
| `timeout` | No response within timeout |
| `error` | Socket/network error |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | At least one successful connection |
| `1` | All attempts failed |

## Use cases

- **Firewall testing** — verify port rules without installing nmap
- **Service monitoring** — check if a port is accepting connections
- **Deploy scripts** — wait for a service to be ready before proceeding
- **Troubleshooting** — distinguish between "host down", "port closed", and "filtered"
- **Latency measurement** — TCP handshake time to a specific service
- **Service discovery** — scan multiple ports, grab banners
- **Log analysis** — CSV output with timestamps for dashboards

## License

MIT
