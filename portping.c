/*
 * portping - TCP port connectivity checker
 * Like ping, but for TCP ports.
 *
 * License: MIT
 */

#define _POSIX_C_SOURCE 200809L

#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  typedef int socklen_t;
#else
  #include <sys/socket.h>
  #include <sys/select.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <errno.h>
  #define SOCKET int
  #define INVALID_SOCKET (-1)
  #define SOCKET_ERROR (-1)
  #define closesocket close
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <math.h>

#ifdef _WIN32
  #define strtok_r strtok_s
#endif

/* ── Timing ── */

#ifdef _WIN32
  #include <windows.h>

  typedef struct {
      LARGE_INTEGER start;
  } pp_timer_t;

  static double freq_ms;

  static void timer_init(void) {
      LARGE_INTEGER f;
      QueryPerformanceFrequency(&f);
      freq_ms = (double)f.QuadPart / 1000.0;
  }

  static void timer_start(pp_timer_t *t) {
      QueryPerformanceCounter(&t->start);
  }

  static double timer_elapsed_ms(pp_timer_t *t) {
      LARGE_INTEGER now;
      QueryPerformanceCounter(&now);
      return (double)(now.QuadPart - t->start.QuadPart) / freq_ms;
  }

  static void sleep_ms(int ms) { Sleep(ms); }
#else
  #include <sys/time.h>
  #include <time.h>

  typedef struct {
      struct timeval start;
  } pp_timer_t;

  static void timer_init(void) { }

  static void timer_start(pp_timer_t *t) {
      gettimeofday(&t->start, NULL);
  }

  static double timer_elapsed_ms(pp_timer_t *t) {
      struct timeval now;
      gettimeofday(&now, NULL);
      return (now.tv_sec - t->start.tv_sec) * 1000.0 +
             (now.tv_usec - t->start.tv_usec) / 1000.0;
  }

  static void sleep_ms(int ms) {
      struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
      nanosleep(&ts, NULL);
  }
#endif

#define PORTPING_VERSION "2.4.0"
#define MAX_RTT_SAMPLES 10000

/* ── Globals ── */

static volatile int running = 1;

static void handle_signal(int sig) {
    (void)sig;
    running = 0;
}

/* ── Socket helpers ── */

static int net_init(void) {
#ifdef _WIN32
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa);
#else
    return 0;
#endif
}

static void net_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

static int set_nonblocking(SOCKET s) {
#ifdef _WIN32
    unsigned long mode = 1;
    return ioctlsocket(s, FIONBIO, &mode);
#else
    int flags = fcntl(s, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(s, F_SETFL, flags | O_NONBLOCK);
#endif
}

/* ── Resolve ── */

static int resolve(const char *host, const char *port, int af, struct addrinfo **res) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = af;
    hints.ai_socktype = SOCK_STREAM;
    return getaddrinfo(host, port, &hints, res);
}

static void format_addr(struct addrinfo *ai, char *buf, size_t len) {
    void *addr;
    if (ai->ai_family == AF_INET) {
        addr = &((struct sockaddr_in *)ai->ai_addr)->sin_addr;
    } else {
        addr = &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr;
    }
    inet_ntop(ai->ai_family, addr, buf, (socklen_t)len);
}

/* ── Reverse DNS ── */

static int reverse_dns(struct addrinfo *ai, char *buf, size_t len) {
    return getnameinfo(ai->ai_addr, (socklen_t)ai->ai_addrlen,
                       buf, (socklen_t)len, NULL, 0, 0);
}

/* ── Service name lookup ── */

static const char *lookup_service(const char *port) {
    struct servent *se = getservbyport(htons((unsigned short)atoi(port)), "tcp");
    return se ? se->s_name : NULL;
}

/* ── Banner grab ── */

static int grab_banner(SOCKET s, char *buf, int maxlen, int timeout_ms) {
    fd_set rfds;
    struct timeval tv;
    int n;

    FD_ZERO(&rfds);
    FD_SET(s, &rfds);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    if (select((int)s + 1, &rfds, NULL, NULL, &tv) <= 0)
        return 0;

    n = recv(s, buf, maxlen - 1, 0);
    if (n <= 0) return 0;
    buf[n] = '\0';

    /* strip trailing newlines */
    while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r'))
        buf[--n] = '\0';

    return n;
}

/* ── HTTP health check ── */

static int http_check(SOCKET s, const char *host, const char *path,
                      char *status_out, int status_max) {
    char req[512];
    char resp[1024];
    int n, total = 0;
    fd_set rfds;
    struct timeval tv;

    n = snprintf(req, sizeof(req),
        "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n",
        path, host);
    send(s, req, n, 0);

    FD_ZERO(&rfds);
    FD_SET(s, &rfds);
    tv.tv_sec = 2;
    tv.tv_usec = 0;

    if (select((int)s + 1, &rfds, NULL, NULL, &tv) <= 0) {
        snprintf(status_out, status_max, "no response");
        return -1;
    }

    total = recv(s, resp, sizeof(resp) - 1, 0);
    if (total <= 0) {
        snprintf(status_out, status_max, "empty response");
        return -1;
    }
    resp[total] = '\0';

    /* Parse "HTTP/1.x NNN reason" */
    if (strncmp(resp, "HTTP/", 5) == 0) {
        char *sp = strchr(resp, ' ');
        if (sp) {
            int code = atoi(sp + 1);
            /* Find reason phrase */
            char *sp2 = strchr(sp + 1, ' ');
            if (sp2) {
                char *eol = strstr(sp2, "\r\n");
                if (eol) *eol = '\0';
                snprintf(status_out, status_max, "%d%s", code, sp2);
            } else {
                snprintf(status_out, status_max, "%d", code);
            }
            return code;
        }
    }

    snprintf(status_out, status_max, "invalid HTTP");
    return -1;
}

/* ── Source address binding ── */

static const char *g_source_addr = NULL;
static int g_tcp_nodelay = 0;
static int g_ttl = 0;
static const char *g_interface = NULL;
static double g_latency_warn = 0;
static double g_latency_crit = 0;
static int g_resolve_each = 0;
static int g_no_dns_banner = 0;
static const char *g_label = NULL;
static int g_compact = 0;
static int g_avg_only = 0;
static int g_source_port = 0;
static int g_retry = 0;
static double g_min_success_rate = 0;
static int g_adaptive = 0;
static int g_quiet_fail = 0;
static int g_progress = 0;
static int g_prometheus = 0;
static int g_nagios = 0;
static int g_shell_output = 0;
static int g_tap = 0;
static int g_grace_probes = 0;
static int g_http_check = 0;
static int g_expect_http_code = 200;
static int g_show_resolve = 0;
static int g_csv_output = 0;
static int g_json_output = 0;

static int bind_source(SOCKET s, int family) {
    if (!g_source_addr && !g_source_port) return 0;

    if (g_source_addr) {
        char sport[16] = {0};
        if (g_source_port) snprintf(sport, sizeof(sport), "%d", g_source_port);
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = family;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(g_source_addr, g_source_port ? sport : NULL, &hints, &res) != 0) return -1;
        int ret = bind(s, res->ai_addr, (int)res->ai_addrlen);
        freeaddrinfo(res);
        return ret;
    }

    /* Source port only, no address */
    if (family == AF_INET6) {
        struct sockaddr_in6 sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin6_family = AF_INET6;
        sa.sin6_port = htons((uint16_t)g_source_port);
        sa.sin6_addr = in6addr_any;
        return bind(s, (struct sockaddr *)&sa, sizeof(sa));
    } else {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons((uint16_t)g_source_port);
        sa.sin_addr.s_addr = INADDR_ANY;
        return bind(s, (struct sockaddr *)&sa, sizeof(sa));
    }
}

/* ── UDP probe ── */

typedef enum {
    RESULT_OPEN,
    RESULT_REFUSED,
    RESULT_TIMEOUT,
    RESULT_ERROR
} result_t;

static result_t udp_ping(struct addrinfo *ai, int timeout_ms, double *elapsed) {
    pp_timer_t t;
    SOCKET s;
    fd_set rfds;
    struct timeval tv;
    char buf[1] = {0};

    s = socket(ai->ai_family, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return RESULT_ERROR;

    bind_source(s, ai->ai_family);
    set_nonblocking(s);
    timer_start(&t);

    sendto(s, buf, 1, 0, ai->ai_addr, (int)ai->ai_addrlen);

    FD_ZERO(&rfds);
    FD_SET(s, &rfds);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    if (select((int)s + 1, &rfds, NULL, NULL, &tv) > 0) {
        char resp[64];
        int n = recvfrom(s, resp, sizeof(resp), 0, NULL, NULL);
        *elapsed = timer_elapsed_ms(&t);
        closesocket(s);
        if (n < 0) {
#ifdef _WIN32
            int err = WSAGetLastError();
            return (err == WSAECONNRESET) ? RESULT_REFUSED : RESULT_OPEN;
#else
            return (errno == ECONNREFUSED) ? RESULT_REFUSED : RESULT_OPEN;
#endif
        }
        return RESULT_OPEN;
    }

    *elapsed = timer_elapsed_ms(&t);
    closesocket(s);
    /* No ICMP unreachable = likely open|filtered */
    return RESULT_OPEN;
}

/* ── TCP connect with timeout ── */

static result_t tcp_ping_ex(struct addrinfo *ai, int timeout_ms, double *elapsed,
                            char *banner, int banner_max) {
    pp_timer_t t;
    SOCKET s;
    fd_set wfds, efds;
    struct timeval tv;
    int err;
    socklen_t errlen;
    result_t ret;

    s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (s == INVALID_SOCKET)
        return RESULT_ERROR;

    bind_source(s, ai->ai_family);
    if (g_tcp_nodelay) {
        int one = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof(one));
    }
    if (g_ttl > 0) {
        int ttl = g_ttl;
        setsockopt(s, IPPROTO_IP, IP_TTL, (char *)&ttl, sizeof(ttl));
    }
#ifdef SO_BINDTODEVICE
    if (g_interface) {
        setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, g_interface, (int)strlen(g_interface) + 1);
    }
#endif
    set_nonblocking(s);

    timer_start(&t);

    if (connect(s, ai->ai_addr, (int)ai->ai_addrlen) == 0) {
        *elapsed = timer_elapsed_ms(&t);
        if (banner && banner_max > 0)
            grab_banner(s, banner, banner_max, 500);
        closesocket(s);
        return RESULT_OPEN;
    }

#ifdef _WIN32
    if (WSAGetLastError() != WSAEWOULDBLOCK) {
        closesocket(s);
        return RESULT_ERROR;
    }
#else
    if (errno != EINPROGRESS) {
        int e = errno;
        closesocket(s);
        return (e == ECONNREFUSED) ? RESULT_REFUSED : RESULT_ERROR;
    }
#endif

    FD_ZERO(&wfds);
    FD_ZERO(&efds);
    FD_SET(s, &wfds);
    FD_SET(s, &efds);

    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    if (select((int)s + 1, NULL, &wfds, &efds, &tv) <= 0) {
        *elapsed = timer_elapsed_ms(&t);
        closesocket(s);
        return RESULT_TIMEOUT;
    }

    *elapsed = timer_elapsed_ms(&t);

    err = 0;
    errlen = sizeof(err);
    getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &errlen);

    if (err == 0) {
        if (banner && banner_max > 0)
            grab_banner(s, banner, banner_max, 500);
        ret = RESULT_OPEN;
    }
#ifdef _WIN32
    else if (err == WSAECONNREFUSED)
        ret = RESULT_REFUSED;
#else
    else if (err == ECONNREFUSED)
        ret = RESULT_REFUSED;
#endif
    else
        ret = RESULT_TIMEOUT;

    closesocket(s);
    return ret;
}

static result_t tcp_ping(struct addrinfo *ai, int timeout_ms, double *elapsed) {
    return tcp_ping_ex(ai, timeout_ms, elapsed, NULL, 0);
}

/* Connect and return open socket (caller must close). Returns INVALID_SOCKET on failure. */
static SOCKET tcp_connect(struct addrinfo *ai, int timeout_ms, double *elapsed) {
    pp_timer_t t;
    SOCKET s;
    fd_set wfds, efds;
    struct timeval tv;
    int err;
    socklen_t errlen;

    s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    bind_source(s, ai->ai_family);
    if (g_tcp_nodelay) {
        int one = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof(one));
    }
    set_nonblocking(s);
    timer_start(&t);

    if (connect(s, ai->ai_addr, (int)ai->ai_addrlen) == 0) {
        *elapsed = timer_elapsed_ms(&t);
        return s;
    }

#ifdef _WIN32
    if (WSAGetLastError() != WSAEWOULDBLOCK) { closesocket(s); return INVALID_SOCKET; }
#else
    if (errno != EINPROGRESS) { closesocket(s); return INVALID_SOCKET; }
#endif

    FD_ZERO(&wfds); FD_ZERO(&efds);
    FD_SET(s, &wfds); FD_SET(s, &efds);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    if (select((int)s + 1, NULL, &wfds, &efds, &tv) <= 0) {
        *elapsed = timer_elapsed_ms(&t);
        closesocket(s);
        return INVALID_SOCKET;
    }

    *elapsed = timer_elapsed_ms(&t);
    err = 0; errlen = sizeof(err);
    getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &errlen);

    if (err != 0) { closesocket(s); return INVALID_SOCKET; }
    return s;
}

/* ── Output formatting ── */

#ifdef _WIN32
  #define COLOR_GREEN  ""
  #define COLOR_RED    ""
  #define COLOR_YELLOW ""
  #define COLOR_RESET  ""
  #define COLOR_BOLD   ""

  static int use_color = 0;

  static void detect_color(void) {
      HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
      DWORD mode;
      if (GetConsoleMode(h, &mode)) {
          if (SetConsoleMode(h, mode | 0x0004 /* ENABLE_VIRTUAL_TERMINAL_PROCESSING */)) {
              use_color = 1;
          }
      }
  }

  #define C_GREEN  (use_color ? "\033[32m" : "")
  #define C_RED    (use_color ? "\033[31m" : "")
  #define C_YELLOW (use_color ? "\033[33m" : "")
  #define C_RESET  (use_color ? "\033[0m"  : "")
  #define C_BOLD   (use_color ? "\033[1m"  : "")
#else
  static int use_color = 1;
  static void detect_color(void) {
      if (!isatty(1)) use_color = 0;
  }

  #include <unistd.h>

  #define C_GREEN  (use_color ? "\033[32m" : "")
  #define C_RED    (use_color ? "\033[31m" : "")
  #define C_YELLOW (use_color ? "\033[33m" : "")
  #define C_RESET  (use_color ? "\033[0m"  : "")
  #define C_BOLD   (use_color ? "\033[1m"  : "")
#endif

/* ── Timestamp ── */

static const char *g_ts_format = "%H:%M:%S";
static int g_show_date = 0;
static int g_fail_fast = 0;
static int g_grab_banner = 0;
static int g_banner_timeout_ms = 2000;

static void print_timestamp(void) {
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char buf[64];
    strftime(buf, sizeof(buf), g_ts_format, tm);
    printf("%s ", buf);
}

/* ── Usage ── */

static void usage(const char *prog) {
    fprintf(stderr,
        "portping %s - TCP port connectivity checker\n"
        "\n"
        "Usage: %s [options] <host> <port>\n"
        "       %s [options] <host>:<port>\n"
        "       %s [options] <host> <port1,port2,...>\n"
        "       %s [options] <host> <startPort-endPort>\n"
        "\n"
        "Options:\n"
        "  -c <count>      Number of attempts (default: infinite)\n"
        "  -t <ms>         Timeout per attempt in ms (default: 2000)\n"
        "  -i <ms>         Interval between attempts in ms (default: 1000)\n"
        "  -w <sec>        Stop after <sec> seconds total (deadline)\n"
        "  -4              Force IPv4\n"
        "  -6              Force IPv6\n"
        "  -S <addr>       Bind to specific source address\n"
        "  --source-port <n> Bind to specific source port\n"
        "  --retry <n>     Retry failed probes up to n times\n"
        "\n"
        "Output:\n"
        "  -T              Show timestamp on each line\n"
        "  -p              Show service name for port\n"
        "  -r              Show reverse DNS for IP\n"
        "  -g              Show RTT histogram in summary\n"
        "  -q              Quiet mode — only show summary\n"
        "  --loss          Only print failed probes\n"
        "  --no-summary    Suppress summary statistics\n"
        "  --no-color      Disable colored output\n"
        "  --csv           Output in CSV format\n"
        "  --json          Output summary as JSON\n"
        "  --json-stream   NDJSON output (one JSON object per probe)\n"
        "  --compact       Minimal single-char-per-probe output\n"
        "  --avg-only      Print average RTT only (for scripting)\n"
        "\n"
        "Probing:\n"
        "  -b              Grab service banner after connect\n"
        "  -H <path>       HTTP health check (GET path, show status)\n"
        "  -A              Alert (beep) on state change\n"
        "  --exec <cmd>    Run command on state change\n"
        "  --backoff       Exponential backoff on failures\n"
        "  --fail <n>      Exit after n consecutive failures\n"
        "  --pass <n>      Exit after n consecutive successes\n"
        "  --until-open    Wait until port opens, then exit\n"
        "  --until-closed  Wait until port closes, then exit\n"
        "  --log <file>    Append results to log file\n"
        "  --label <text>  Custom label in output header\n"
        "  --resolve-each  Re-resolve DNS on every probe\n"
        "  --no-dns        Suppress DNS info in banner\n"
        "  --latency-warn <ms>  RTT warning threshold\n"
        "  --latency-crit <ms>  RTT critical threshold\n"
        "  --min-success <pct>  Min success rate (exit code 7)\n"
        "\n"
        "Scan mode:\n"
        "  --only-open     Show only open ports in scan\n"
        "  --only-closed   Show only closed ports in scan\n"
        "  --count-only    Print open port count only\n"
        "  --web           Preset: 80,443,8080,8443\n"
        "  --db            Preset: 3306,5432,1433,27017,6379\n"
        "  --mail          Preset: 25,465,587,993,995,143,110\n"
        "  --remote        Preset: 22,23,3389,5900,5901\n"
        "\n"
        "  -V, --version   Show version\n"
        "  -h, --help      Show this help\n"
        "\n"
        "Examples:\n"
        "  %s google.com 443\n"
        "  %s -c 5 -t 500 192.168.1.1 22\n"
        "  %s server.com 22,80,443\n"
        "  %s -H /health api.example.com 8080\n"
        "  %s --until-open -i 500 db-server 5432\n"
        "\n", PORTPING_VERSION, prog, prog, prog, prog, prog, prog, prog, prog, prog);
}

/* ── Statistics helpers ── */

static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}

static double percentile(double *sorted, int n, double p) {
    if (n <= 0) return 0;
    if (n == 1) return sorted[0];
    double idx = p / 100.0 * (n - 1);
    int lo = (int)idx;
    int hi = lo + 1;
    if (hi >= n) return sorted[n - 1];
    double frac = idx - lo;
    return sorted[lo] * (1 - frac) + sorted[hi] * frac;
}

/* ── Top ports list (most commonly open, nmap-inspired) ── */

static const char *top_ports_20 = "21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5900,8080,8443";
static const char *top_ports_50 = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,1723,2049,3306,3389,5432,5900,5901,6379,8080,8443,8888,9090,27017,80,443,22,25,53,110,143,993,995,587,465,3389,5900,8080,1433,3306,5432,27017,6379,11211";
static const char *top_ports_100 = "7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1521,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,5901,6000,6001,6379,6646,7070,8000,8008,8009,8080,8081,8443,8888,9090,9100,9999,10000,27017,32768";

/* ── Port presets ── */

static const char *resolve_preset(const char *port) {
    if (strcmp(port, "--web") == 0)
        return "80,443,8080,8443";
    if (strcmp(port, "--db") == 0)
        return "3306,5432,1433,27017,6379,5984";
    if (strcmp(port, "--mail") == 0)
        return "25,465,587,993,995,143,110";
    if (strcmp(port, "--remote") == 0)
        return "22,23,3389,5900,5901";
    return NULL;
}

/* ── Scan globals ── */

typedef enum {
    SCAN_ALL,
    SCAN_OPEN,
    SCAN_CLOSED
} scan_filter_t;

static scan_filter_t scan_filter = SCAN_ALL;
static int scan_count_only = 0;
static int scan_parallel = 0;

/* ── Parallel port scan ── */

typedef struct {
    SOCKET sock;
    int port;
    pp_timer_t timer;
    int done;
    result_t result;
    double ms;
} probe_slot_t;

static int scan_ports_parallel(const char *host, const char *portlist, int af,
                               int timeout_ms, int csv, int batch_size) {
    char buf[4096];
    char *ports[2048];
    int nports = 0;
    char *tok, *save;
    int open_count = 0;

    strncpy(buf, portlist, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    for (tok = strtok_r(buf, ",", &save); tok && nports < 2048; tok = strtok_r(NULL, ",", &save))
        ports[nports++] = tok;

    if (csv)
        printf("host,port,ip,status,ms\n");
    else if (!scan_count_only)
        printf("\n  Scanning %s — %d ports (%d parallel)\n\n", host, nports, batch_size);

    int p = 0;
    while (p < nports) {
        int batch = (p + batch_size <= nports) ? batch_size : nports - p;
        probe_slot_t *slots = calloc(batch, sizeof(probe_slot_t));
        int j;

        /* Start all connections */
        for (j = 0; j < batch; j++) {
            struct addrinfo *res;
            slots[j].port = atoi(ports[p + j]);
            slots[j].done = 0;
            slots[j].result = RESULT_TIMEOUT;
            slots[j].sock = INVALID_SOCKET;

            if (resolve(host, ports[p + j], af, &res) != 0) {
                slots[j].done = 1;
                slots[j].result = RESULT_ERROR;
                continue;
            }

            SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
            if (s == INVALID_SOCKET) {
                slots[j].done = 1;
                slots[j].result = RESULT_ERROR;
                freeaddrinfo(res);
                continue;
            }

            set_nonblocking(s);
            timer_start(&slots[j].timer);
            int rc_unused = connect(s, res->ai_addr, (int)res->ai_addrlen);
            (void)rc_unused; /* non-blocking, will complete via select */
            slots[j].sock = s;
            freeaddrinfo(res);
        }

        /* Wait with select */
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        fd_set wfds;
        FD_ZERO(&wfds);
        SOCKET maxfd = 0;
        for (j = 0; j < batch; j++) {
            if (!slots[j].done && slots[j].sock != INVALID_SOCKET) {
                FD_SET(slots[j].sock, &wfds);
                if (slots[j].sock > maxfd) maxfd = slots[j].sock;
            }
        }

        select((int)maxfd + 1, NULL, &wfds, NULL, &tv);

        /* Check results */
        for (j = 0; j < batch; j++) {
            if (slots[j].done) continue;
            if (slots[j].sock == INVALID_SOCKET) continue;

            slots[j].ms = timer_elapsed_ms(&slots[j].timer);

            if (FD_ISSET(slots[j].sock, &wfds)) {
                int err = 0;
                socklen_t el = sizeof(err);
                getsockopt(slots[j].sock, SOL_SOCKET, SO_ERROR, (char *)&err, &el);
                slots[j].result = (err == 0) ? RESULT_OPEN : RESULT_REFUSED;
            }
            closesocket(slots[j].sock);
        }

        /* Print results */
        for (j = 0; j < batch; j++) {
            char pstr[8];
            snprintf(pstr, sizeof(pstr), "%d", slots[j].port);
            const char *sn = lookup_service(pstr);
            const char *svc = sn ? sn : "";
            result_t r = slots[j].result;

            if (csv) {
                const char *st = (r == RESULT_OPEN) ? "open" :
                                 (r == RESULT_REFUSED) ? "refused" :
                                 (r == RESULT_TIMEOUT) ? "timeout" : "error";
                printf("%s,%d,,%s,%.1f\n", host, slots[j].port, st, slots[j].ms);
            } else if (!scan_count_only) {
                int show = 1;
                if (scan_filter == SCAN_OPEN && r != RESULT_OPEN) show = 0;
                if (scan_filter == SCAN_CLOSED && r == RESULT_OPEN) show = 0;

                if (show) {
                    const char *col = (r == RESULT_OPEN) ? C_GREEN :
                                      (r == RESULT_REFUSED) ? C_RED : C_YELLOW;
                    const char *label = (r == RESULT_OPEN) ? "open" :
                                        (r == RESULT_REFUSED) ? "refused" : "timeout";
                    printf("  %s%-6d%s %-8s %s:%d  %s%-8s%s %.1f ms\n",
                           col, slots[j].port, C_RESET, svc,
                           host, slots[j].port, col, label, C_RESET, slots[j].ms);
                }
            }
            if (r == RESULT_OPEN) open_count++;
        }

        free(slots);
        p += batch;
    }

    if (scan_count_only)
        printf("%d\n", open_count);
    else if (!csv)
        printf("\n  %d/%d ports open\n\n", open_count, nports);

    return (open_count > 0) ? 0 : 1;
}

/* ── Port scan (comma-separated ports) ── */

static int scan_ports(const char *host, const char *portlist, int af,
                      int timeout_ms, int csv) {
    char buf[1024];
    char *tok, *save;
    int open_count = 0, total = 0;

    strncpy(buf, portlist, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    if (csv)
        printf("host,port,ip,status,ms\n");
    else if (!scan_count_only)
        printf("\n  Scanning %s ports: %s\n\n", host, portlist);

    for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        struct addrinfo *res;
        int rc = resolve(host, tok, af, &res);
        if (rc != 0) {
            fprintf(stderr, "  Cannot resolve %s:%s\n", host, tok);
            continue;
        }

        char ipstr[INET6_ADDRSTRLEN];
        format_addr(res, ipstr, sizeof(ipstr));

        double ms = 0;
        result_t r = tcp_ping(res, timeout_ms, &ms);
        total++;

        if (csv) {
            const char *status = (r == RESULT_OPEN) ? "open" :
                                 (r == RESULT_REFUSED) ? "refused" :
                                 (r == RESULT_TIMEOUT) ? "timeout" : "error";
            printf("%s,%s,%s,%s,%.1f\n", host, tok, ipstr, status, ms);
        } else {
            int show = !scan_count_only;
            if (scan_filter == SCAN_OPEN && r != RESULT_OPEN) show = 0;
            if (scan_filter == SCAN_CLOSED && r == RESULT_OPEN) show = 0;

            if (show) {
                const char *sn = lookup_service(tok);
                const char *svc = sn ? sn : "";
                switch (r) {
                case RESULT_OPEN:
                    printf("  %s%-6s%s %-8s %s:%s  %sopen%s     %.1f ms\n",
                           C_GREEN, tok, C_RESET, svc, host, tok, C_GREEN, C_RESET, ms);
                    break;
                case RESULT_REFUSED:
                    printf("  %s%-6s%s %-8s %s:%s  %srefused%s  %.1f ms\n",
                           C_RED, tok, C_RESET, svc, host, tok, C_RED, C_RESET, ms);
                    break;
                case RESULT_TIMEOUT:
                    printf("  %s%-6s%s %-8s %s:%s  %stimeout%s\n",
                           C_YELLOW, tok, C_RESET, svc, host, tok, C_YELLOW, C_RESET);
                    break;
                case RESULT_ERROR:
                    printf("  %s%-6s%s %-8s %s:%s  %serror%s\n",
                           C_RED, tok, C_RESET, svc, host, tok, C_RED, C_RESET);
                    break;
                }
            }
            if (r == RESULT_OPEN) open_count++;
        }

        freeaddrinfo(res);
    }

    if (scan_count_only)
        printf("%d\n", open_count);
    else if (!csv)
        printf("\n  %d/%d ports open\n\n", open_count, total);

    return (open_count > 0) ? 0 : 1;
}

/* ── Main ── */

int main(int argc, char **argv) {
    const char *host = NULL;
    const char *port = NULL;
    int count = 0;  /* 0 = infinite */
    int timeout_ms = 2000;
    int interval_ms = 1000;
    int af = AF_UNSPEC;
    int show_timestamp = 0;
    int quiet = 0;
    int csv = 0;
    int deadline_sec = 0;  /* 0 = no deadline */
    int banner_grab = 0;
    const char *http_path = NULL;
    int json = 0;
    int json_stream = 0;
    int alert_change = 0;
    int show_service = 0;
    int fail_count = 0;   /* exit after N consecutive failures */
    int pass_count = 0;   /* exit after N consecutive successes */
    const char *log_file = NULL;
    int show_histogram = 0;
    const char *exec_cmd = NULL;
    const char *source_addr = NULL;
    int show_loss_only = 0;
    int until_open = 0;
    int until_closed = 0;
    int exp_backoff = 0;
    int show_rdns = 0;
    int no_summary = 0;
    int use_udp = 0;
    int flood_mode = 0;
    int expect_closed = 0;
    int dns_retry = 0;
    const char *output_file = NULL;
    int top_ports = 0;
    double rtt_threshold = 0;  /* --slow-threshold: only show probes above this ms */
    double max_jitter_threshold = 0;
    double max_rtt_threshold = 0;
    double max_loss_threshold = -1;  /* -1 = disabled */
    int i;

    /* Parse args */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-V") == 0 || strcmp(argv[i], "--version") == 0) {
            printf("portping %s\n", PORTPING_VERSION);
            return 0;
        } else if (strcmp(argv[i], "--version-json") == 0) {
            printf("{\"name\":\"portping\",\"version\":\"%s\",\"platform\":\"%s\"}\n",
                   PORTPING_VERSION,
#ifdef _WIN32
                   "windows"
#elif __APPLE__
                   "macos"
#else
                   "linux"
#endif
            );
            return 0;
        } else if (strcmp(argv[i], "--no-color") == 0) {
            use_color = 0;
        } else if (strncmp(argv[i], "--color=", 8) == 0) {
            const char *val = argv[i] + 8;
            if (strcmp(val, "never") == 0) use_color = 0;
            else if (strcmp(val, "always") == 0) use_color = 1;
            /* "auto" keeps default behavior */
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            count = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            timeout_ms = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            interval_ms = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-4") == 0) {
            af = AF_INET;
        } else if (strcmp(argv[i], "-6") == 0) {
            af = AF_INET6;
        } else if (strcmp(argv[i], "-T") == 0) {
            show_timestamp = 1;
        } else if (strcmp(argv[i], "--ts-format") == 0 && i + 1 < argc) {
            show_timestamp = 1;
            g_ts_format = argv[++i];
        } else if (strcmp(argv[i], "-q") == 0) {
            quiet = 1;
        } else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
            deadline_sec = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-b") == 0) {
            banner_grab = 1;
        } else if (strcmp(argv[i], "-H") == 0 && i + 1 < argc) {
            http_path = argv[++i];
        } else if (strcmp(argv[i], "--csv") == 0) {
            csv = 1;
            quiet = 1;
        } else if (strcmp(argv[i], "--json-stream") == 0) {
            json_stream = 1;
        } else if (strcmp(argv[i], "--json") == 0) {
            json = 1;
            quiet = 1;
        } else if (strcmp(argv[i], "-A") == 0) {
            alert_change = 1;
        } else if (strcmp(argv[i], "-p") == 0) {
            show_service = 1;
        } else if (strcmp(argv[i], "--fail") == 0 && i + 1 < argc) {
            fail_count = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--pass") == 0 && i + 1 < argc) {
            pass_count = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--log") == 0 && i + 1 < argc) {
            log_file = argv[++i];
        } else if (strcmp(argv[i], "-S") == 0 && i + 1 < argc) {
            source_addr = argv[++i];
        } else if (strcmp(argv[i], "--exec") == 0 && i + 1 < argc) {
            exec_cmd = argv[++i];
        } else if (strcmp(argv[i], "-g") == 0) {
            show_histogram = 1;
        } else if (strcmp(argv[i], "--only-open") == 0) {
            scan_filter = SCAN_OPEN;
        } else if (strcmp(argv[i], "--only-closed") == 0) {
            scan_filter = SCAN_CLOSED;
        } else if (strcmp(argv[i], "--nodelay") == 0) {
            g_tcp_nodelay = 1;
        } else if (strcmp(argv[i], "--ttl") == 0 && i + 1 < argc) {
            g_ttl = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-I") == 0 && i + 1 < argc) {
            g_interface = argv[++i];
        } else if (strcmp(argv[i], "--no-summary") == 0) {
            no_summary = 1;
        } else if (strcmp(argv[i], "-r") == 0) {
            show_rdns = 1;
        } else if (strcmp(argv[i], "--backoff") == 0) {
            exp_backoff = 1;
        } else if (strcmp(argv[i], "--latency-warn") == 0 && i + 1 < argc) {
            g_latency_warn = atof(argv[++i]);
        } else if (strcmp(argv[i], "--latency-crit") == 0 && i + 1 < argc) {
            g_latency_crit = atof(argv[++i]);
        } else if (strcmp(argv[i], "--resolve-each") == 0) {
            g_resolve_each = 1;
        } else if (strcmp(argv[i], "--no-dns") == 0) {
            g_no_dns_banner = 1;
        } else if (strcmp(argv[i], "--label") == 0 && i + 1 < argc) {
            g_label = argv[++i];
        } else if (strcmp(argv[i], "--compact") == 0) {
            g_compact = 1;
        } else if (strcmp(argv[i], "--avg-only") == 0) {
            g_avg_only = 1;
        } else if (strcmp(argv[i], "--source-port") == 0 && i + 1 < argc) {
            g_source_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--retry") == 0 && i + 1 < argc) {
            g_retry = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--min-success") == 0 && i + 1 < argc) {
            g_min_success_rate = atof(argv[++i]);
        } else if (strcmp(argv[i], "--adaptive") == 0) {
            g_adaptive = 1;
        } else if (strcmp(argv[i], "--quiet-fail") == 0) {
            g_quiet_fail = 1;
        } else if (strcmp(argv[i], "--prometheus") == 0) {
            g_prometheus = 1;
        } else if (strcmp(argv[i], "--nagios") == 0) {
            g_nagios = 1;
        } else if (strcmp(argv[i], "--shell") == 0) {
            g_shell_output = 1;
        } else if (strcmp(argv[i], "--tap") == 0) {
            g_tap = 1;
        } else if (strcmp(argv[i], "--grace") == 0 && i + 1 < argc) {
            g_grace_probes = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--progress") == 0) {
            g_progress = 1;
        } else if (strcmp(argv[i], "--until-open") == 0) {
            until_open = 1;
        } else if (strcmp(argv[i], "--until-closed") == 0) {
            until_closed = 1;
        } else if (strcmp(argv[i], "--count-only") == 0) {
            scan_count_only = 1;
        } else if (strcmp(argv[i], "--parallel") == 0 && i + 1 < argc) {
            scan_parallel = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-u") == 0) {
            use_udp = 1;
        } else if (strcmp(argv[i], "--flood") == 0) {
            flood_mode = 1;
            quiet = 1;
        } else if (strcmp(argv[i], "--expect-closed") == 0) {
            expect_closed = 1;
        } else if (strcmp(argv[i], "--dns-retry") == 0) {
            dns_retry = 1;
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        } else if (strcmp(argv[i], "--top-ports") == 0 && i + 1 < argc) {
            top_ports = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--slow") == 0 && i + 1 < argc) {
            rtt_threshold = atof(argv[++i]);
        } else if (strcmp(argv[i], "--max-jitter") == 0 && i + 1 < argc) {
            max_jitter_threshold = atof(argv[++i]);
        } else if (strcmp(argv[i], "--max-rtt") == 0 && i + 1 < argc) {
            max_rtt_threshold = atof(argv[++i]);
        } else if (strcmp(argv[i], "--max-loss") == 0 && i + 1 < argc) {
            max_loss_threshold = atof(argv[++i]);
        } else if (strcmp(argv[i], "--loss") == 0) {
            show_loss_only = 1;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        } else if (!host) {
            host = argv[i];
        } else if (!port) {
            port = argv[i];
        }
    }

    /* Support host:port syntax */
    static char host_buf[256];
    if (host && !port) {
        const char *colon = strrchr(host, ':');
        if (colon && colon != host) {
            size_t hlen = colon - host;
            if (hlen >= sizeof(host_buf)) hlen = sizeof(host_buf) - 1;
            memcpy(host_buf, host, hlen);
            host_buf[hlen] = '\0';
            host = host_buf;
            port = colon + 1;
        }
    }

    /* --top-ports implies scan mode (set port before validation) */
    if (top_ports > 0 && !port) {
        if (top_ports <= 20) port = top_ports_20;
        else if (top_ports <= 50) port = top_ports_50;
        else port = top_ports_100;
    }

    if (!host || !port) {
        usage(argv[0]);
        return 1;
    }

    /* Validate arguments */
    if (timeout_ms <= 0) {
        fprintf(stderr, "Error: timeout must be positive (got %d)\n", timeout_ms);
        return 1;
    }
    if (interval_ms <= 0) {
        fprintf(stderr, "Error: interval must be positive (got %d)\n", interval_ms);
        return 1;
    }
    if (count < 0) {
        fprintf(stderr, "Error: count must be non-negative (got %d)\n", count);
        return 1;
    }
    if (deadline_sec < 0) {
        fprintf(stderr, "Error: deadline must be non-negative (got %d)\n", deadline_sec);
        return 1;
    }

    /* Init */
    detect_color();
    timer_init();
    signal(SIGINT, handle_signal);
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, handle_signal);
#endif

    if (net_init() != 0) {
        fprintf(stderr, "Failed to initialize networking.\n");
        return 1;
    }

    if (source_addr) g_source_addr = source_addr;

    /* Redirect output to file if specified */
    if (output_file) {
        FILE *of = freopen(output_file, "w", stdout);
        if (!of) {
            fprintf(stderr, "Cannot open output file '%s'\n", output_file);
            return 1;
        }
        use_color = 0;
    }

    /* Resolve service name to port number if needed */
    static char port_num_buf[8];
    if (port && !strchr(port, ',') && !strchr(port, '-') && atoi(port) == 0) {
        struct servent *se = getservbyname(port, "tcp");
        if (se) {
            snprintf(port_num_buf, sizeof(port_num_buf), "%d", ntohs(se->s_port));
            port = port_num_buf;
        }
    }

    /* Check port presets */
    const char *preset = resolve_preset(port);
    if (preset) port = preset;

    /* Multi-port scan mode (comma or range) */
    if (strchr(port, ',') != NULL || strchr(port, '-') != NULL) {
        /* Expand ranges like 80-85 into 80,81,82,83,84,85 */
        char expanded[4096] = {0};
        char tmp[1024];
        char *tok, *save;
        strncpy(tmp, port, sizeof(tmp) - 1);
        tmp[sizeof(tmp) - 1] = '\0';

        for (tok = strtok_r(tmp, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
            char *dash = strchr(tok, '-');
            if (dash && dash != tok) {
                int start = atoi(tok);
                int end = atoi(dash + 1);
                if (start > 0 && end > 0 && end >= start && end - start < 1024) {
                    int p;
                    for (p = start; p <= end; p++) {
                        char pbuf[16];
                        snprintf(pbuf, sizeof(pbuf), "%d", p);
                        if (expanded[0]) strncat(expanded, ",", sizeof(expanded) - strlen(expanded) - 1);
                        strncat(expanded, pbuf, sizeof(expanded) - strlen(expanded) - 1);
                    }
                } else {
                    if (expanded[0]) strncat(expanded, ",", sizeof(expanded) - strlen(expanded) - 1);
                    strncat(expanded, tok, sizeof(expanded) - strlen(expanded) - 1);
                }
            } else {
                if (expanded[0]) strncat(expanded, ",", sizeof(expanded) - strlen(expanded) - 1);
                strncat(expanded, tok, sizeof(expanded) - strlen(expanded) - 1);
            }
        }

        int scan_count_iters = (count > 0) ? count : 1;
        int ret = 0, sc;
        for (sc = 0; sc < scan_count_iters && running; sc++) {
            if (scan_count_iters > 1 && !csv && !scan_count_only)
                printf("  === Scan %d/%d ===\n", sc + 1, scan_count_iters);
            if (scan_parallel > 0)
                ret = scan_ports_parallel(host, expanded, af, timeout_ms, csv, scan_parallel);
            else
                ret = scan_ports(host, expanded, af, timeout_ms, csv);
            if (sc + 1 < scan_count_iters && running)
                sleep_ms(interval_ms);
        }
        net_cleanup();
        return ret;
    }

    /* Resolve */
    pp_timer_t dns_timer;
    timer_start(&dns_timer);
    struct addrinfo *res;
    int rc = resolve(host, port, af, &res);
    double dns_ms = timer_elapsed_ms(&dns_timer);
    if (rc != 0 && dns_retry) {
        int attempt;
        for (attempt = 0; attempt < 3 && rc != 0; attempt++) {
            sleep_ms(1000 * (attempt + 1));
            if (!quiet) fprintf(stderr, "DNS retry %d/3...\n", attempt + 1);
            timer_start(&dns_timer);
            rc = resolve(host, port, af, &res);
            dns_ms = timer_elapsed_ms(&dns_timer);
        }
    }
    if (rc != 0) {
        if (!g_quiet_fail) fprintf(stderr, "Cannot resolve %s: %s\n", host, gai_strerror(rc));
        net_cleanup();
        return 1;
    }

    char ipstr[INET6_ADDRSTRLEN];
    format_addr(res, ipstr, sizeof(ipstr));

    const char *svc_name = show_service ? lookup_service(port) : NULL;
    char rdns_buf[256] = {0};
    if (show_rdns) reverse_dns(res, rdns_buf, sizeof(rdns_buf));

    if (csv)
        printf("seq,host,port,ip,status,ms\n");
    else if (!quiet && !g_no_dns_banner) {
        printf("\n%sPORTPING%s %s%s:%s%s", C_BOLD, C_RESET, C_BOLD, host, port, C_RESET);
        if (g_label) printf(" [%s%s%s]", C_YELLOW, g_label, C_RESET);
        if (svc_name) printf(" (%s/%s)", ipstr, svc_name);
        else printf(" (%s)", ipstr);
        if (rdns_buf[0] && strcmp(rdns_buf, host) != 0)
            printf(" [%s]", rdns_buf);
        if (g_interface) printf(" via %s", g_interface);
        printf(" — DNS %.1f ms\n\n", dns_ms);
    } else if (!quiet && g_no_dns_banner) {
        printf("\n");
    }

    /* Ping loop */
    pp_timer_t deadline_timer;
    pp_timer_t session_timer;
    timer_start(&session_timer);
    if (deadline_sec > 0) timer_start(&deadline_timer);

    int seq = 0;
    int success = 0;
    int failed = 0;
    int refused = 0;
    double total_ms = 0;
    double total_ms2 = 0;  /* sum of squares for jitter */
    double min_ms = 1e9;
    double max_ms = 0;
    double *rtt_samples = NULL;
    int rtt_count = 0;
    int rtt_cap = 0;
    result_t prev_result = RESULT_ERROR;  /* no previous */
    int first_probe = 1;
    int consec_fail = 0;
    int consec_pass = 0;
    int longest_open_streak = 0;
    int longest_fail_streak = 0;
    FILE *logfp = NULL;

    if (log_file) {
        logfp = fopen(log_file, "a");
        if (!logfp)
            fprintf(stderr, "Warning: cannot open log file '%s'\n", log_file);
    }

    if (g_tap && count > 0) printf("1..%d\n", count);

    while (running && (count == 0 || seq < count) &&
           (deadline_sec == 0 || timer_elapsed_ms(&deadline_timer) < deadline_sec * 1000.0)) {
        double ms = 0;
        char banner[256] = {0};
        char http_status[128] = {0};
        int http_code = 0;
        result_t r = RESULT_ERROR;

        for (int attempt = 0; attempt <= g_retry; attempt++) {
            if (use_udp) {
                r = udp_ping(res, timeout_ms, &ms);
            } else if (http_path) {
                SOCKET hs = tcp_connect(res, timeout_ms, &ms);
                if (hs != INVALID_SOCKET) {
                    r = RESULT_OPEN;
                    http_code = http_check(hs, host, http_path, http_status, sizeof(http_status));
                    closesocket(hs);
                } else {
                    r = RESULT_TIMEOUT;
                }
            } else if (banner_grab) {
                r = tcp_ping_ex(res, timeout_ms, &ms, banner, sizeof(banner));
            } else {
                r = tcp_ping(res, timeout_ms, &ms);
            }
            if (r == RESULT_OPEN || attempt >= g_retry) break;
            /* Brief pause before retry */
            struct timespec rts = { .tv_sec = 0, .tv_nsec = 100000000L };
            nanosleep(&rts, NULL);
        }

        /* Re-resolve DNS each attempt if requested */
        if (g_resolve_each && running) {
            freeaddrinfo(res);
            if (resolve(host, port, af, &res) != 0) {
                fprintf(stderr, "DNS re-resolve failed\n");
                break;
            }
        }
        seq++;

        /* Progress indicator */
        if (g_progress && count > 0 && !quiet && !csv && !json_stream) {
            fprintf(stderr, "\r[%d/%d] %.0f%%", seq, count, (double)seq / count * 100.0);
            if (seq >= count) fprintf(stderr, "\n");
        }

        switch (r) {
        case RESULT_OPEN:
            if (json_stream) {
                struct timespec jts;
                clock_gettime(CLOCK_REALTIME, &jts);
                long long epoch_ms = (long long)jts.tv_sec * 1000 + jts.tv_nsec / 1000000;
                printf("{\"seq\":%d,\"ts\":%lld,\"host\":\"%s\",\"port\":\"%s\",\"ip\":\"%s\",\"status\":\"open\",\"ms\":%.1f",
                       seq, epoch_ms, host, port, ipstr, ms);
                if (http_path && http_code > 0) printf(",\"http\":%d", http_code);
                printf("}\n");
                fflush(stdout);
            } else if (g_tap) {
                printf("ok %d - %s:%s open (%.1f ms)\n", seq, host, port, ms);
            } else if (csv) {
                if (http_path)
                    printf("%d,%s,%s,%s,open,%.1f,%d\n", seq, host, port, ipstr, ms, http_code);
                else
                    printf("%d,%s,%s,%s,open,%.1f\n", seq, host, port, ipstr, ms);
            } else if (!quiet && g_compact) {
                printf("%s.%s", C_GREEN, C_RESET);
                fflush(stdout);
            } else if (!quiet && !show_loss_only && (rtt_threshold <= 0 || ms >= rtt_threshold)) {
                if (show_timestamp) print_timestamp();
                {
                    const char *rtt_color = C_GREEN;
                    const char *rtt_tag = "";
                    if (g_latency_crit > 0 && ms >= g_latency_crit) {
                        rtt_color = C_RED; rtt_tag = " CRITICAL";
                    } else if (g_latency_warn > 0 && ms >= g_latency_warn) {
                        rtt_color = C_YELLOW; rtt_tag = " SLOW";
                    }
                    printf("  %s[%d]%s %s:%s  %sopen%s  %s%.1f ms%s%s",
                           C_BOLD, seq, C_RESET, host, port,
                           C_GREEN, C_RESET, rtt_color, ms, rtt_tag, C_RESET);
                }
                if (http_path && http_status[0]) {
                    const char *hc = (http_code >= 200 && http_code < 400) ? C_GREEN : C_RED;
                    printf("  %sHTTP %s%s", hc, http_status, C_RESET);
                }
                if (banner[0])
                    printf("  [%s]", banner);
                printf("\n");
            }
            success++;
            total_ms += ms;
            total_ms2 += ms * ms;
            if (ms < min_ms) min_ms = ms;
            if (ms > max_ms) max_ms = ms;
            /* Store sample for percentiles */
            if (rtt_count < MAX_RTT_SAMPLES) {
                if (rtt_count >= rtt_cap) {
                    rtt_cap = rtt_cap ? rtt_cap * 2 : 64;
                    if (rtt_cap > MAX_RTT_SAMPLES) rtt_cap = MAX_RTT_SAMPLES;
                    rtt_samples = realloc(rtt_samples, rtt_cap * sizeof(double));
                }
                if (rtt_samples) rtt_samples[rtt_count++] = ms;
            }
            break;

        case RESULT_REFUSED:
            if (json_stream) {
                struct timespec jts;
                clock_gettime(CLOCK_REALTIME, &jts);
                long long epoch_ms = (long long)jts.tv_sec * 1000 + jts.tv_nsec / 1000000;
                printf("{\"seq\":%d,\"ts\":%lld,\"host\":\"%s\",\"port\":\"%s\",\"ip\":\"%s\",\"status\":\"refused\",\"ms\":%.1f}\n", seq, epoch_ms, host, port, ipstr, ms);
            }
            else if (g_tap)
                printf("not ok %d - %s:%s refused (%.1f ms)\n", seq, host, port, ms);
            else if (csv)
                printf("%d,%s,%s,%s,refused,%.1f\n", seq, host, port, ipstr, ms);
            else if (!quiet && g_compact) {
                printf("%sx%s", C_RED, C_RESET);
                fflush(stdout);
            } else if (!quiet) {
                if (show_timestamp) print_timestamp();
                printf("  %s[%d]%s %s:%s  %srefused%s  %.1f ms\n",
                       C_BOLD, seq, C_RESET, host, port,
                       C_RED, C_RESET, ms);
            }
            if (seq > g_grace_probes) refused++;
            break;

        case RESULT_TIMEOUT:
            if (json_stream) {
                struct timespec jts;
                clock_gettime(CLOCK_REALTIME, &jts);
                long long epoch_ms = (long long)jts.tv_sec * 1000 + jts.tv_nsec / 1000000;
                printf("{\"seq\":%d,\"ts\":%lld,\"host\":\"%s\",\"port\":\"%s\",\"ip\":\"%s\",\"status\":\"timeout\"}\n", seq, epoch_ms, host, port, ipstr);
            }
            else if (g_tap)
                printf("not ok %d - %s:%s timeout (>%d ms)\n", seq, host, port, timeout_ms);
            else if (csv)
                printf("%d,%s,%s,%s,timeout,\n", seq, host, port, ipstr);
            else if (!quiet && g_compact) {
                printf("%s!%s", C_YELLOW, C_RESET);
                fflush(stdout);
            } else if (!quiet) {
                if (show_timestamp) print_timestamp();
                printf("  %s[%d]%s %s:%s  %stimeout%s  >%d ms\n",
                       C_BOLD, seq, C_RESET, host, port,
                       C_YELLOW, C_RESET, timeout_ms);
            }
            if (seq > g_grace_probes) failed++;
            break;

        case RESULT_ERROR:
            if (csv)
                printf("%d,%s,%s,%s,error,\n", seq, host, port, ipstr);
            else if (!quiet && g_compact) {
                printf("%sE%s", C_RED, C_RESET);
                fflush(stdout);
            } else if (!quiet) {
                if (show_timestamp) print_timestamp();
                printf("  %s[%d]%s %s:%s  %serror%s\n",
                       C_BOLD, seq, C_RESET, host, port,
                       C_RED, C_RESET);
            }
            if (seq > g_grace_probes) failed++;
            break;
        }

        /* Alert on state change */
        if (alert_change && !first_probe && r != prev_result) {
            const char *from = (prev_result == RESULT_OPEN) ? "OPEN" :
                               (prev_result == RESULT_REFUSED) ? "REFUSED" : "DOWN";
            const char *to   = (r == RESULT_OPEN) ? "OPEN" :
                               (r == RESULT_REFUSED) ? "REFUSED" : "DOWN";
            fprintf(stderr, "\a*** STATE CHANGE: %s -> %s (seq %d) ***\n", from, to, seq);

            if (exec_cmd) {
                char cmd_buf[1024];
                snprintf(cmd_buf, sizeof(cmd_buf), "%s %s %s %s %s",
                         exec_cmd, host, port, from, to);
                system(cmd_buf);
            }
        }
        prev_result = r;
        first_probe = 0;

        /* Consecutive pass/fail tracking */
        if (r == RESULT_OPEN) {
            consec_pass++;
            consec_fail = 0;
            if (consec_pass > longest_open_streak) longest_open_streak = consec_pass;
        } else {
            consec_fail++;
            consec_pass = 0;
            if (consec_fail > longest_fail_streak) longest_fail_streak = consec_fail;
        }
        if (fail_count > 0 && consec_fail >= fail_count) {
            if (!quiet) fprintf(stderr, "Exiting: %d consecutive failures\n", fail_count);
            running = 0;
        }
        if (pass_count > 0 && consec_pass >= pass_count) {
            if (!quiet) fprintf(stderr, "Exiting: %d consecutive successes\n", pass_count);
            running = 0;
        }
        if (until_open && r == RESULT_OPEN) running = 0;
        if (until_closed && r != RESULT_OPEN) running = 0;

        /* Log to file */
        if (logfp) {
            time_t now = time(NULL);
            char tbuf[32];
            strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", localtime(&now));
            const char *st = (r == RESULT_OPEN) ? "open" :
                             (r == RESULT_REFUSED) ? "refused" :
                             (r == RESULT_TIMEOUT) ? "timeout" : "error";
            fprintf(logfp, "%s %s:%s %s %.1f\n", tbuf, host, port, st, ms);
            fflush(logfp);
        }

        if (flood_mode) {
            putchar(r == RESULT_OPEN ? '.' : 'X');
            if (seq % 70 == 0) putchar('\n');
            fflush(stdout);
        } else if (!quiet) {
            fflush(stdout);
        }

        if (running && (count == 0 || seq < count)) {
            if (flood_mode) {
                /* no delay */
            } else {
                int sleep_time = interval_ms;
                if (exp_backoff && r != RESULT_OPEN) {
                    sleep_time = interval_ms * (1 << (consec_fail < 6 ? consec_fail : 6));
                    if (sleep_time > 60000) sleep_time = 60000;
                } else if (g_adaptive) {
                    /* Adaptive: halve interval on success (min 100ms), double on fail (max 30s) */
                    if (r == RESULT_OPEN) {
                        sleep_time = interval_ms / 2;
                        if (sleep_time < 100) sleep_time = 100;
                    } else {
                        sleep_time = interval_ms * 2;
                        if (sleep_time > 30000) sleep_time = 30000;
                    }
                    interval_ms = sleep_time;
                }
                sleep_ms(sleep_time);
            }
        }
    }

    if (logfp) fclose(logfp);

    /* Summary */
    int total = success + failed + refused;
    double loss = total > 0 ? (double)(failed + refused) / total * 100.0 : 0;
    double avg = success > 0 ? total_ms / success : 0;

    double session_secs = timer_elapsed_ms(&session_timer) / 1000.0;

    if (csv || no_summary) goto cleanup;

    if (g_prometheus) {
        printf("portping_attempts{host=\"%s\",port=\"%s\"} %d\n", host, port, total);
        printf("portping_success{host=\"%s\",port=\"%s\"} %d\n", host, port, success);
        printf("portping_refused{host=\"%s\",port=\"%s\"} %d\n", host, port, refused);
        printf("portping_failed{host=\"%s\",port=\"%s\"} %d\n", host, port, failed);
        printf("portping_loss_pct{host=\"%s\",port=\"%s\"} %.1f\n", host, port, loss);
        if (success > 0) {
            printf("portping_rtt_min{host=\"%s\",port=\"%s\"} %.1f\n", host, port, min_ms);
            printf("portping_rtt_avg{host=\"%s\",port=\"%s\"} %.1f\n", host, port, avg);
            printf("portping_rtt_max{host=\"%s\",port=\"%s\"} %.1f\n", host, port, max_ms);
        }
        goto cleanup;
    }

    if (g_shell_output) {
        printf("PP_HOST='%s'\n", host);
        printf("PP_PORT=%s\n", port);
        printf("PP_IP='%s'\n", ipstr);
        printf("PP_ATTEMPTS=%d\n", total);
        printf("PP_SUCCESS=%d\n", success);
        printf("PP_REFUSED=%d\n", refused);
        printf("PP_FAILED=%d\n", failed);
        printf("PP_LOSS=%.1f\n", loss);
        if (success > 0) {
            printf("PP_RTT_MIN=%.1f\n", min_ms);
            printf("PP_RTT_AVG=%.1f\n", avg);
            printf("PP_RTT_MAX=%.1f\n", max_ms);
        }
        goto cleanup;
    }

    if (g_nagios) {
        const char *state;
        int nagios_code;
        if (success == 0) { state = "CRITICAL"; nagios_code = 2; }
        else if (loss > 50) { state = "WARNING"; nagios_code = 1; }
        else { state = "OK"; nagios_code = 0; }
        printf("TCP %s - %s:%s %d/%d open (%.0f%% loss) | rtt=%.1fms loss=%.0f%% open=%d\n",
               state, host, port, success, total, loss, avg, loss, success);
        (void)nagios_code;
        goto cleanup;
    }

    if (g_avg_only) {
        if (success > 0)
            printf("%.1f\n", avg);
        else
            printf("-1\n");
        goto cleanup;
    }

    if (json) {
        double jitter = 0;
        if (success > 1) {
            double variance = (total_ms2 / success) - (avg * avg);
            jitter = sqrt(variance > 0 ? variance : 0);
        }
        if (rtt_samples && rtt_count > 1)
            qsort(rtt_samples, rtt_count, sizeof(double), cmp_double);
        printf("{\n");
        printf("  \"host\": \"%s\",\n", host);
        printf("  \"port\": %s,\n", port);
        printf("  \"ip\": \"%s\",\n", ipstr);
        printf("  \"attempts\": %d,\n", total);
        printf("  \"open\": %d,\n", success);
        printf("  \"refused\": %d,\n", refused);
        printf("  \"failed\": %d,\n", failed);
        printf("  \"loss_pct\": %.1f,\n", loss);
        printf("  \"longest_open_streak\": %d,\n", longest_open_streak);
        printf("  \"longest_fail_streak\": %d,\n", longest_fail_streak);
        printf("  \"duration_sec\": %.1f,\n", session_secs);
        if (success > 0) {
            printf("  \"rtt_min\": %.1f,\n", min_ms);
            printf("  \"rtt_avg\": %.1f,\n", avg);
            printf("  \"rtt_max\": %.1f,\n", max_ms);
            printf("  \"rtt_jitter\": %.1f,\n", jitter);
            if (rtt_samples && rtt_count > 1) {
                printf("  \"rtt_p50\": %.1f,\n", percentile(rtt_samples, rtt_count, 50));
                printf("  \"rtt_p90\": %.1f,\n", percentile(rtt_samples, rtt_count, 90));
                printf("  \"rtt_p95\": %.1f,\n", percentile(rtt_samples, rtt_count, 95));
                printf("  \"rtt_p99\": %.1f\n", percentile(rtt_samples, rtt_count, 99));
            } else {
                printf("  \"rtt_p50\": %.1f\n", avg);
            }
        } else {
            printf("  \"rtt_min\": null,\n");
            printf("  \"rtt_avg\": null,\n");
            printf("  \"rtt_max\": null,\n");
            printf("  \"rtt_jitter\": null\n");
        }
        printf("}\n");
        goto cleanup;
    }

    if (g_compact) printf("\n");
    printf("\n--- %s:%s portping statistics ---\n", host, port);
    printf("%d attempts, %s%d open%s, %d refused, %d timeout/error",
           total, C_GREEN, success, C_RESET, refused, failed);

    if (total > 0) {
        const char *lc = (loss == 0) ? C_GREEN : (loss < 50) ? C_YELLOW : C_RED;
        printf(" (%s%.0f%% loss%s)", lc, loss, C_RESET);
    }

    printf(", time %.1fs\n", session_secs);

    if (success > 0) {
        double jitter = 0;
        if (success > 1) {
            double variance = (total_ms2 / success) - (avg * avg);
            jitter = sqrt(variance > 0 ? variance : 0);
        }
        printf("rtt min/avg/max/jitter = %.1f/%.1f/%.1f/%.1f ms\n",
               min_ms, avg, max_ms, jitter);

        if (g_latency_warn > 0 || g_latency_crit > 0) {
            int cnt_warn = 0, cnt_crit = 0;
            int j;
            for (j = 0; j < rtt_count; j++) {
                if (g_latency_crit > 0 && rtt_samples[j] >= g_latency_crit) cnt_crit++;
                else if (g_latency_warn > 0 && rtt_samples[j] >= g_latency_warn) cnt_warn++;
            }
            if (cnt_warn > 0 || cnt_crit > 0)
                printf("latency: %s%d slow%s, %s%d critical%s (warn=%.0f ms, crit=%.0f ms)\n",
                       C_YELLOW, cnt_warn, C_RESET, C_RED, cnt_crit, C_RESET,
                       g_latency_warn, g_latency_crit);
        }

        if (rtt_samples && rtt_count > 1) {
            qsort(rtt_samples, rtt_count, sizeof(double), cmp_double);
            printf("rtt p50/p90/p95/p99   = %.1f/%.1f/%.1f/%.1f ms\n",
                   percentile(rtt_samples, rtt_count, 50),
                   percentile(rtt_samples, rtt_count, 90),
                   percentile(rtt_samples, rtt_count, 95),
                   percentile(rtt_samples, rtt_count, 99));

            if (show_histogram && rtt_count >= 3) {
                int bins[10] = {0};
                double range = max_ms - min_ms;
                int max_bin = 0, b;
                if (range < 0.001) range = 1.0;
                for (b = 0; b < rtt_count; b++) {
                    int idx = (int)((rtt_samples[b] - min_ms) / range * 9.999);
                    if (idx > 9) idx = 9;
                    bins[idx]++;
                    if (bins[idx] > max_bin) max_bin = bins[idx];
                }
                printf("\nRTT distribution:\n");
                for (b = 0; b < 10; b++) {
                    double lo = min_ms + range * b / 10.0;
                    double hi = min_ms + range * (b + 1) / 10.0;
                    int bar_len = max_bin > 0 ? bins[b] * 30 / max_bin : 0;
                    printf("  %6.1f-%6.1f ms |", lo, hi);
                    int k;
                    for (k = 0; k < bar_len; k++) printf("#");
                    printf(" %d\n", bins[b]);
                }
            }
        }
    }

    printf("\n");

    free(rtt_samples);

cleanup:
    /* Cleanup */
    freeaddrinfo(res);
    net_cleanup();

    if (expect_closed)
        return (success == 0) ? 0 : 1;
    if (max_jitter_threshold > 0 && success > 1) {
        double variance = (total_ms2 / success) - (avg * avg);
        double jitter_final = sqrt(variance > 0 ? variance : 0);
        if (jitter_final > max_jitter_threshold) return 2;
    }
    if (max_rtt_threshold > 0 && success > 0 && avg > max_rtt_threshold) return 3;
    if (max_loss_threshold >= 0 && total > 0 && loss > max_loss_threshold) return 4;
    if (g_latency_crit > 0 && success > 0 && max_ms >= g_latency_crit) return 5;
    if (g_latency_warn > 0 && success > 0 && avg >= g_latency_warn) return 6;
    if (g_min_success_rate > 0 && total > 0) {
        double rate = (double)success / total * 100.0;
        if (rate < g_min_success_rate) return 7;
    }
    return (success > 0) ? 0 : 1;
}
