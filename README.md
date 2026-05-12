# portping

**Like `ping`, but for TCP ports.**

```
$ portping google.com 443

PORTPING google.com:443 (142.250.74.46)

  [1] google.com:443  open  12.3 ms
  [2] google.com:443  open  11.8 ms
  [3] google.com:443  open  12.1 ms
  ^C
--- google.com:443 portping statistics ---
3 attempts, 3 open, 0 refused, 0 timeout/error (0% loss)
rtt min/avg/max = 11.8/12.1/12.3 ms
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
gcc -O2 -o portping portping.c

# Windows (MSVC)
cl portping.c ws2_32.lib
```

### Download

Grab a prebuilt binary from [Releases](https://github.com/USER/portping/releases/latest).

## Usage

```
portping [options] <host> <port>

Options:
  -c <count>     Number of attempts (default: infinite)
  -t <ms>        Timeout per attempt in ms (default: 2000)
  -i <ms>        Interval between attempts in ms (default: 1000)
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

# Script: wait for a service to come up
until portping -c 1 -t 1000 localhost 8080 > /dev/null 2>&1; do
    sleep 1
done
echo "Service is up!"
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

## License

MIT
