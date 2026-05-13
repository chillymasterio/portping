/*
 * portping - TCP port connectivity checker
 * Like ping, but for TCP ports.
 *
 * License: MIT
 */

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

#define PORTPING_VERSION "2.0.0"
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

/* ── TCP connect with timeout ── */

typedef enum {
    RESULT_OPEN,
    RESULT_REFUSED,
    RESULT_TIMEOUT,
    RESULT_ERROR
} result_t;

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

static void print_timestamp(void) {
#ifdef _WIN32
    SYSTEMTIME st;
    GetLocalTime(&st);
    printf("%02d:%02d:%02d ", st.wHour, st.wMinute, st.wSecond);
#else
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    printf("%02d:%02d:%02d ", tm->tm_hour, tm->tm_min, tm->tm_sec);
#endif
}

/* ── Usage ── */

static void usage(const char *prog) {
    fprintf(stderr,
        "portping - TCP port connectivity checker\n"
        "\n"
        "Usage: %s [options] <host> <port>\n"
        "\n"
        "Options:\n"
        "  -c <count>     Number of attempts (default: infinite)\n"
        "  -t <ms>        Timeout per attempt in ms (default: 2000)\n"
        "  -i <ms>        Interval between attempts in ms (default: 1000)\n"
        "  -4             Force IPv4\n"
        "  -6             Force IPv6\n"
        "  -T             Show timestamp on each line\n"
        "  -q             Quiet mode — only show summary\n"
        "  -b             Grab service banner after connect\n"
        "  -H <path>      HTTP health check (GET path, show status)\n"
        "  -w <sec>       Stop after <sec> seconds total (deadline)\n"
        "  --csv          Output in CSV format\n"
        "  -A             Alert (beep) on state change\n"
        "  --json         Output summary as JSON\n"
        "  --no-color     Disable colored output\n"
        "  -V, --version  Show version\n"
        "  -h             Show this help\n"
        "\n"
        "Examples:\n"
        "  %s google.com 443\n"
        "  %s -c 5 -t 500 192.168.1.1 22\n"
        "  %s -c 10 -i 500 db-server 5432\n"
        "\n", prog, prog, prog, prog);
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

/* ── Port scan (comma-separated ports) ── */

typedef enum {
    SCAN_ALL,
    SCAN_OPEN,
    SCAN_CLOSED
} scan_filter_t;

static scan_filter_t scan_filter = SCAN_ALL;

static int scan_ports(const char *host, const char *portlist, int af,
                      int timeout_ms, int csv) {
    char buf[1024];
    char *tok, *save;
    int open_count = 0, total = 0;

    strncpy(buf, portlist, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    if (csv)
        printf("host,port,ip,status,ms\n");
    else
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
            int show = 1;
            if (scan_filter == SCAN_OPEN && r != RESULT_OPEN) show = 0;
            if (scan_filter == SCAN_CLOSED && r == RESULT_OPEN) show = 0;

            if (show) {
                switch (r) {
                case RESULT_OPEN:
                    printf("  %s%-6s%s %s:%s  %sopen%s     %.1f ms\n",
                           C_GREEN, tok, C_RESET, host, tok, C_GREEN, C_RESET, ms);
                    break;
                case RESULT_REFUSED:
                    printf("  %s%-6s%s %s:%s  %srefused%s  %.1f ms\n",
                           C_RED, tok, C_RESET, host, tok, C_RED, C_RESET, ms);
                    break;
                case RESULT_TIMEOUT:
                    printf("  %s%-6s%s %s:%s  %stimeout%s\n",
                           C_YELLOW, tok, C_RESET, host, tok, C_YELLOW, C_RESET);
                    break;
                case RESULT_ERROR:
                    printf("  %s%-6s%s %s:%s  %serror%s\n",
                           C_RED, tok, C_RESET, host, tok, C_RED, C_RESET);
                    break;
                }
            }
            if (r == RESULT_OPEN) open_count++;
        }

        freeaddrinfo(res);
    }

    if (!csv)
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
    int alert_change = 0;
    int show_service = 0;
    int fail_count = 0;   /* exit after N consecutive failures */
    int pass_count = 0;   /* exit after N consecutive successes */
    const char *log_file = NULL;
    int show_histogram = 0;
    const char *exec_cmd = NULL;
    int i;

    /* Parse args */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-V") == 0 || strcmp(argv[i], "--version") == 0) {
            printf("portping %s\n", PORTPING_VERSION);
            return 0;
        } else if (strcmp(argv[i], "--no-color") == 0) {
            use_color = 0;
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
        } else if (strcmp(argv[i], "--exec") == 0 && i + 1 < argc) {
            exec_cmd = argv[++i];
        } else if (strcmp(argv[i], "-g") == 0) {
            show_histogram = 1;
        } else if (strcmp(argv[i], "--only-open") == 0) {
            scan_filter = SCAN_OPEN;
        } else if (strcmp(argv[i], "--only-closed") == 0) {
            scan_filter = SCAN_CLOSED;
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
                        char pbuf[8];
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

        int ret = scan_ports(host, expanded, af, timeout_ms, csv);
        net_cleanup();
        return ret;
    }

    /* Resolve */
    pp_timer_t dns_timer;
    timer_start(&dns_timer);
    struct addrinfo *res;
    int rc = resolve(host, port, af, &res);
    double dns_ms = timer_elapsed_ms(&dns_timer);
    if (rc != 0) {
        fprintf(stderr, "Cannot resolve %s: %s\n", host, gai_strerror(rc));
        net_cleanup();
        return 1;
    }

    char ipstr[INET6_ADDRSTRLEN];
    format_addr(res, ipstr, sizeof(ipstr));

    const char *svc_name = show_service ? lookup_service(port) : NULL;

    if (csv)
        printf("seq,host,port,ip,status,ms\n");
    else if (!quiet) {
        printf("\n%sPORTPING%s %s%s:%s%s", C_BOLD, C_RESET, C_BOLD, host, port, C_RESET);
        if (svc_name) printf(" (%s/%s)", ipstr, svc_name);
        else printf(" (%s)", ipstr);
        printf(" — DNS %.1f ms\n\n", dns_ms);
    }

    /* Ping loop */
    pp_timer_t deadline_timer;
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
    FILE *logfp = NULL;

    if (log_file) {
        logfp = fopen(log_file, "a");
        if (!logfp)
            fprintf(stderr, "Warning: cannot open log file '%s'\n", log_file);
    }

    while (running && (count == 0 || seq < count) &&
           (deadline_sec == 0 || timer_elapsed_ms(&deadline_timer) < deadline_sec * 1000.0)) {
        double ms = 0;
        char banner[256] = {0};
        char http_status[128] = {0};
        int http_code = 0;
        result_t r;

        if (http_path) {
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
        seq++;

        switch (r) {
        case RESULT_OPEN:
            if (csv) {
                if (http_path)
                    printf("%d,%s,%s,%s,open,%.1f,%d\n", seq, host, port, ipstr, ms, http_code);
                else
                    printf("%d,%s,%s,%s,open,%.1f\n", seq, host, port, ipstr, ms);
            } else if (!quiet) {
                if (show_timestamp) print_timestamp();
                printf("  %s[%d]%s %s:%s  %sopen%s  %.1f ms",
                       C_BOLD, seq, C_RESET, host, port,
                       C_GREEN, C_RESET, ms);
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
            if (csv)
                printf("%d,%s,%s,%s,refused,%.1f\n", seq, host, port, ipstr, ms);
            else if (!quiet) {
                if (show_timestamp) print_timestamp();
                printf("  %s[%d]%s %s:%s  %srefused%s  %.1f ms\n",
                       C_BOLD, seq, C_RESET, host, port,
                       C_RED, C_RESET, ms);
            }
            refused++;
            break;

        case RESULT_TIMEOUT:
            if (csv)
                printf("%d,%s,%s,%s,timeout,\n", seq, host, port, ipstr);
            else if (!quiet) {
                if (show_timestamp) print_timestamp();
                printf("  %s[%d]%s %s:%s  %stimeout%s  >%d ms\n",
                       C_BOLD, seq, C_RESET, host, port,
                       C_YELLOW, C_RESET, timeout_ms);
            }
            failed++;
            break;

        case RESULT_ERROR:
            if (csv)
                printf("%d,%s,%s,%s,error,\n", seq, host, port, ipstr);
            else if (!quiet) {
                if (show_timestamp) print_timestamp();
                printf("  %s[%d]%s %s:%s  %serror%s\n",
                       C_BOLD, seq, C_RESET, host, port,
                       C_RED, C_RESET);
            }
            failed++;
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
        } else {
            consec_fail++;
            consec_pass = 0;
        }
        if (fail_count > 0 && consec_fail >= fail_count) {
            if (!quiet) fprintf(stderr, "Exiting: %d consecutive failures\n", fail_count);
            running = 0;
        }
        if (pass_count > 0 && consec_pass >= pass_count) {
            if (!quiet) fprintf(stderr, "Exiting: %d consecutive successes\n", pass_count);
            running = 0;
        }

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

        if (!quiet) fflush(stdout);

        if (running && (count == 0 || seq < count))
            sleep_ms(interval_ms);
    }

    if (logfp) fclose(logfp);

    /* Summary */
    int total = success + failed + refused;
    double loss = total > 0 ? (double)(failed + refused) / total * 100.0 : 0;
    double avg = success > 0 ? total_ms / success : 0;

    if (csv) goto cleanup;

    if (json) {
        double jitter = 0;
        if (success > 1) {
            double variance = (total_ms2 / success) - (avg * avg);
            jitter = sqrt(variance > 0 ? variance : 0);
        }
        printf("{\n");
        printf("  \"host\": \"%s\",\n", host);
        printf("  \"port\": %s,\n", port);
        printf("  \"ip\": \"%s\",\n", ipstr);
        printf("  \"attempts\": %d,\n", total);
        printf("  \"open\": %d,\n", success);
        printf("  \"refused\": %d,\n", refused);
        printf("  \"failed\": %d,\n", failed);
        printf("  \"loss_pct\": %.1f,\n", loss);
        if (success > 0) {
            printf("  \"rtt_min\": %.1f,\n", min_ms);
            printf("  \"rtt_avg\": %.1f,\n", avg);
            printf("  \"rtt_max\": %.1f,\n", max_ms);
            printf("  \"rtt_jitter\": %.1f\n", jitter);
        } else {
            printf("  \"rtt_min\": null,\n");
            printf("  \"rtt_avg\": null,\n");
            printf("  \"rtt_max\": null,\n");
            printf("  \"rtt_jitter\": null\n");
        }
        printf("}\n");
        goto cleanup;
    }

    printf("\n--- %s:%s portping statistics ---\n", host, port);
    printf("%d attempts, %s%d open%s, %d refused, %d timeout/error",
           total, C_GREEN, success, C_RESET, refused, failed);

    if (total > 0)
        printf(" (%.0f%% loss)", loss);

    printf("\n");

    if (success > 0) {
        double jitter = 0;
        if (success > 1) {
            double variance = (total_ms2 / success) - (avg * avg);
            jitter = sqrt(variance > 0 ? variance : 0);
        }
        printf("rtt min/avg/max/jitter = %.1f/%.1f/%.1f/%.1f ms\n",
               min_ms, avg, max_ms, jitter);

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

    return (success > 0) ? 0 : 1;
}
