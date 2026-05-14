# Changelog

## [2.3.0] - 2026-05-14

### Added
- `--avg-only` for scriptable average RTT output
- `--source-port` to bind to a specific local port
- `--retry <N>` to retry failed probes before reporting failure
- `--min-success <pct>` SLA threshold (exit code 7)
- `--adaptive` interval that adjusts based on probe results
- `--quiet-fail` to suppress error output for scripting
- `--color=always/never/auto` for explicit color control
- `--progress` completion percentage during counted runs
- Interface name display in banner when `-I` is used

## [2.2.0] - 2026-05-14

### Added
- `--latency-warn` and `--latency-crit` for RTT threshold monitoring
- `--resolve-each` to re-resolve DNS on every probe
- `--no-dns` to suppress DNS resolution banner
- `--label` for custom host identification in output
- Latency threshold violation counts in summary
- Exit codes 5/6 for latency threshold violations
- `--compact` minimal single-character-per-probe output (`.` open, `x` refused, `!` timeout, `E` error)
- `--json-stream` newline-delimited JSON output per probe

### Fixed
- Added `_POSIX_C_SOURCE` for nanosleep/timespec availability
- Buffer size warning in port range expansion

## [2.1.0] - 2026-05-14

### Added
- `-u` flag for UDP port probing
- `-I <iface>` flag to bind to specific network interface
- `-o <file>` flag to redirect output to a file
- `--flood` rapid-fire mode with no interval delay
- `--parallel <N>` for concurrent multi-port scanning
- `--top-ports <N>` to scan top 20/50/100 common ports
- `--slow <ms>` to only display probes above RTT threshold
- `--ttl <N>` to set IP time-to-live on probes
- `--dns-retry` for resilient DNS resolution
- `--expect-closed` to invert exit code (closed port = success)
- `--max-jitter <ms>` SLA threshold (exit code 2)
- `--max-rtt <ms>` SLA threshold (exit code 3)
- `--max-loss <pct>` SLA threshold (exit code 4)
- `--ts-format <fmt>` for custom timestamp format
- Man page (portping.1)
- Longest open/fail streak tracking in statistics
- Repeated scan support (-c flag in scan mode)

### Changed
- Parallel scan dramatically speeds up multi-port probing
- Timestamp uses cross-platform strftime instead of OS-specific code

## [2.0.0] - 2026-05-13

### Added
- `-4` / `-6` flags to force IPv4 or IPv6
- `-T` flag to show timestamps on each probe line
- `-q` quiet mode (summary only)
- `-p` flag to show service names for ports
- `-r` flag for reverse DNS lookup display
- `-g` flag for RTT distribution histogram
- `-b` flag for service banner grabbing
- `-H <path>` for HTTP health check with status display
- `-A` flag for audible alert on state change
- `-S <addr>` to bind to specific source address
- `-w <sec>` total deadline in seconds
- `--csv` output mode for monitoring integration
- `--json` output mode with full statistics
- `--exec <cmd>` to run command on state change
- `--log <file>` to append results to log file
- `--fail <n>` exit after N consecutive failures
- `--pass <n>` exit after N consecutive successes
- `--until-open` / `--until-closed` wait modes
- `--backoff` exponential retry delay on failures
- `--loss` flag to only show failed probes
- `--no-summary` to suppress summary statistics
- `--no-color` to disable ANSI colors
- `--nodelay` to set TCP_NODELAY on sockets
- `--count-only` for scriptable open port count
- `--only-open` / `--only-closed` scan filters
- Port presets: `--web`, `--db`, `--mail`, `--remote`
- Multi-port scan with comma-separated ports
- Port range support (e.g., `80-90`)
- Mixed port ranges and lists (e.g., `22,80-85,443`)
- `host:port` single-argument syntax
- Service name as port argument (e.g., `https`)
- Percentile statistics (p50/p90/p95/p99)
- Jitter (standard deviation) in RTT stats
- DNS resolution time display
- Session duration in summary
- Color-coded loss percentage
- Service names in multi-port scan output
- Makefile for non-CMake builds

### Changed
- RTT summary now shows min/avg/max/jitter instead of min/avg/max
- JSON output includes percentiles and duration

### Fixed
- Input validation for timeout, interval, count, deadline
- Proper SIGTERM handling alongside SIGINT
- `timer_t` renamed to `pp_timer_t` to avoid POSIX conflict

## [1.0.0] - 2026-05-13

### Added
- Initial release
- Cross-platform TCP port connectivity checker
- Non-blocking connect with configurable timeout
- Color terminal output with Windows VT100 detection
- Min/avg/max RTT statistics
- Scriptable exit codes (0 = success, 1 = all failed)
- `-c`, `-t`, `-i` flags
