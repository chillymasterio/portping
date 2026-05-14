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
3 attempts, 3 open, 0 refused, 0 timeout/error (0% loss), time 2.1s
rtt min/avg/max/jitter = 11.8/12.1/12.3/0.2 ms
rtt p50/p90/p95/p99   = 12.1/12.3/12.3/12.3 ms
```

## Why?

`ping` tells you a host is alive. It doesn't tell you if port 443 is accepting connections, if your firewall rules work, or if that Redis on port 6379 is actually listening.

`portping` does.

- **Zero dependencies** — single C file, compiles everywhere
- **Cross-platform** — Windows, Linux, macOS
- **Scriptable** — exit codes for success, failure, jitter, RTT, and loss thresholds
- **Familiar** — same flags and output style as `ping`
- **Parallel scanning** — probe hundreds of ports in seconds
- **SLA monitoring** — built-in thresholds for automated alerting

## Install

### Build from source

```bash
# Using CMake
cmake -B build && cmake --build build

# Using Make
make

# Or compile directly
gcc -O2 -o portping portping.c -lm
```

### Install system-wide

```bash
sudo make install
# or
sudo cmake --install build
```

### Download

Grab a prebuilt binary from [Releases](https://github.com/chillymasterio/portping/releases/latest).

## Quick Start

```bash
# Check if a port is open
portping example.com 443

# Use host:port syntax
portping example.com:22

# Scan multiple ports
portping server.com 22,80,443,3306

# Scan a range
portping server.com 8080-8090

# Fast parallel scan of common ports
portping --top-ports 100 --parallel 50 --only-open server.com
```

## Options

### Connection

| Flag | Description |
|------|-------------|
| `-c <N>` | Number of probes (default: infinite) |
| `-t <ms>` | Timeout per probe (default: 2000) |
| `-i <ms>` | Interval between probes (default: 1000) |
| `-w <sec>` | Total deadline in seconds |
| `-4` / `-6` | Force IPv4 / IPv6 |
| `-u` | UDP mode instead of TCP |
| `-S <addr>` | Bind to source address |
| `-I <iface>` | Bind to network interface (Linux) |
| `--ttl <N>` | Set IP TTL |
| `--nodelay` | Set TCP_NODELAY |
| `--dns-retry` | Retry DNS resolution on failure |
| `--source-port <N>` | Bind to specific local port |
| `--retry <N>` | Retry failed probes N times |
| `--adaptive` | Auto-adjust interval based on results |
| `--resolve-each` | Re-resolve DNS on every probe |

### Output

| Flag | Description |
|------|-------------|
| `-T` | Show timestamps |
| `--ts-format <fmt>` | Custom strftime format |
| `-p` | Show service name for port |
| `-r` | Show reverse DNS |
| `-g` | Show RTT histogram |
| `-q` | Quiet — only summary |
| `--slow <ms>` | Only show probes slower than threshold |
| `--loss` | Only show failed probes |
| `--no-summary` | Suppress summary stats |
| `--no-color` | Disable ANSI colors |
| `-o <file>` | Write output to file |
| `--csv` | CSV format |
| `--json` | JSON summary |
| `--json-stream` | NDJSON (one JSON per probe) |
| `--compact` | Single char per probe (. x !) |
| `--avg-only` | Print average RTT only |
| `--progress` | Show completion percentage |
| `--label <text>` | Custom label in banner |
| `--no-dns` | Suppress DNS info in banner |
| `--color=MODE` | Color: always/never/auto |
| `--quiet-fail` | Suppress errors for scripting |

### Probing

| Flag | Description |
|------|-------------|
| `-b` | Grab service banner |
| `-H <path>` | HTTP health check (GET path) |
| `-A` | Alert on state change |
| `--exec <cmd>` | Run command on state change |
| `--flood` | No-delay rapid fire mode |
| `--backoff` | Exponential backoff on failure |
| `--fail <N>` | Exit after N consecutive failures |
| `--pass <N>` | Exit after N consecutive successes |
| `--until-open` | Wait until port opens |
| `--until-closed` | Wait until port closes |
| `--log <file>` | Append results to log file |

### Scan Mode

| Flag | Description |
|------|-------------|
| `--parallel <N>` | Probe N ports simultaneously |
| `--top-ports <N>` | Scan top 20/50/100 common ports |
| `--only-open` | Show only open ports |
| `--only-closed` | Show only closed ports |
| `--count-only` | Print open port count only |
| `--web` | Preset: 80,443,8080,8443 |
| `--db` | Preset: 3306,5432,1433,27017,6379 |
| `--mail` | Preset: 25,465,587,993,995,143,110 |
| `--remote` | Preset: 22,23,3389,5900,5901 |

### SLA Thresholds

| Flag | Exit Code | Description |
|------|-----------|-------------|
| `--max-jitter <ms>` | 2 | Jitter exceeds threshold |
| `--max-rtt <ms>` | 3 | Avg RTT exceeds threshold |
| `--max-loss <pct>` | 4 | Loss % exceeds threshold |
| `--expect-closed` | 0 | Port closed = success |
| `--latency-warn <ms>` | 6 | Avg latency above warning |
| `--latency-crit <ms>` | 5 | Any probe exceeds critical |
| `--min-success <pct>` | 7 | Success rate below threshold |

## Examples

### Basic monitoring

```bash
# Monitor with timestamps, alert on change
portping -T -A prod-db 5432

# Run for 60 seconds, log results
portping -w 60 --log /var/log/portping.log web-server 443

# HTTP health check
portping -H /api/health -c 10 api.example.com 8080
```

### Scripting

```bash
# Wait for service to start
portping --until-open -i 500 localhost 8080

# SLA check in CI/CD
portping --max-rtt 100 --max-loss 5 -c 50 prod-api 443 || alert

# Quick firewall verification
portping --expect-closed -c 1 server 3306 || echo "DB port exposed!"
```

### Scanning

```bash
# Fast scan of common ports
portping --top-ports 100 --parallel 50 --only-open target.com

# Scan with service identification
portping -p target.com 20-25,80,443,3306,5432,8080-8090

# CSV export for analysis
portping --csv --parallel 20 server.com 1-1024 > scan.csv
```

### Advanced

```bash
# Banner grab to identify services
portping -b -c 1 server.com 22,25,80,3306

# JSON output for dashboards
portping --json -c 100 -i 200 prod-server 443 | jq .

# Exponential backoff monitoring
portping --backoff -A --exec "/usr/local/bin/notify.sh" prod-db 5432

# Flood test (no delay)
portping --flood -c 1000 -q localhost 8080
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | At least one connection succeeded |
| 1 | All probes failed |
| 2 | Jitter threshold exceeded (--max-jitter) |
| 3 | RTT threshold exceeded (--max-rtt) |
| 4 | Loss threshold exceeded (--max-loss) |

## License

MIT
