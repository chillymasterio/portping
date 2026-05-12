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

/* ── TCP connect with timeout ── */

typedef enum {
    RESULT_OPEN,
    RESULT_REFUSED,
    RESULT_TIMEOUT,
    RESULT_ERROR
} result_t;

static result_t tcp_ping(struct addrinfo *ai, int timeout_ms, double *elapsed) {
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
    closesocket(s);

    if (err == 0)
        ret = RESULT_OPEN;
#ifdef _WIN32
    else if (err == WSAECONNREFUSED)
        ret = RESULT_REFUSED;
#else
    else if (err == ECONNREFUSED)
        ret = RESULT_REFUSED;
#endif
    else
        ret = RESULT_TIMEOUT;

    return ret;
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
        "  -h             Show this help\n"
        "\n"
        "Examples:\n"
        "  %s google.com 443\n"
        "  %s -c 5 -t 500 192.168.1.1 22\n"
        "  %s -c 10 -i 500 db-server 5432\n"
        "\n", prog, prog, prog, prog);
}

/* ── Main ── */

int main(int argc, char **argv) {
    const char *host = NULL;
    const char *port = NULL;
    int count = 0;  /* 0 = infinite */
    int timeout_ms = 2000;
    int interval_ms = 1000;
    int af = AF_UNSPEC;
    int i;

    /* Parse args */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
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

    if (!host || !port) {
        usage(argv[0]);
        return 1;
    }

    /* Init */
    detect_color();
    timer_init();
    signal(SIGINT, handle_signal);
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif

    if (net_init() != 0) {
        fprintf(stderr, "Failed to initialize networking.\n");
        return 1;
    }

    /* Resolve */
    struct addrinfo *res;
    int rc = resolve(host, port, af, &res);
    if (rc != 0) {
        fprintf(stderr, "Cannot resolve %s: %s\n", host, gai_strerror(rc));
        net_cleanup();
        return 1;
    }

    char ipstr[INET6_ADDRSTRLEN];
    format_addr(res, ipstr, sizeof(ipstr));

    printf("\n%sPORTPING%s %s%s:%s%s (%s)\n\n",
           C_BOLD, C_RESET, C_BOLD, host, port, C_RESET, ipstr);

    /* Ping loop */
    int seq = 0;
    int success = 0;
    int failed = 0;
    int refused = 0;
    double total_ms = 0;
    double min_ms = 1e9;
    double max_ms = 0;

    while (running && (count == 0 || seq < count)) {
        double ms = 0;
        result_t r = tcp_ping(res, timeout_ms, &ms);
        seq++;

        switch (r) {
        case RESULT_OPEN:
            printf("  %s[%d]%s %s:%s  %sopen%s  %.1f ms\n",
                   C_BOLD, seq, C_RESET, host, port,
                   C_GREEN, C_RESET, ms);
            success++;
            total_ms += ms;
            if (ms < min_ms) min_ms = ms;
            if (ms > max_ms) max_ms = ms;
            break;

        case RESULT_REFUSED:
            printf("  %s[%d]%s %s:%s  %srefused%s  %.1f ms\n",
                   C_BOLD, seq, C_RESET, host, port,
                   C_RED, C_RESET, ms);
            refused++;
            break;

        case RESULT_TIMEOUT:
            printf("  %s[%d]%s %s:%s  %stimeout%s  >%d ms\n",
                   C_BOLD, seq, C_RESET, host, port,
                   C_YELLOW, C_RESET, timeout_ms);
            failed++;
            break;

        case RESULT_ERROR:
            printf("  %s[%d]%s %s:%s  %serror%s\n",
                   C_BOLD, seq, C_RESET, host, port,
                   C_RED, C_RESET);
            failed++;
            break;
        }

        fflush(stdout);

        if (running && (count == 0 || seq < count))
            sleep_ms(interval_ms);
    }

    /* Summary */
    int total = success + failed + refused;
    double loss = total > 0 ? (double)(failed + refused) / total * 100.0 : 0;
    double avg = success > 0 ? total_ms / success : 0;

    printf("\n--- %s:%s portping statistics ---\n", host, port);
    printf("%d attempts, %s%d open%s, %d refused, %d timeout/error",
           total, C_GREEN, success, C_RESET, refused, failed);

    if (total > 0)
        printf(" (%.0f%% loss)", loss);

    printf("\n");

    if (success > 0) {
        printf("rtt min/avg/max = %.1f/%.1f/%.1f ms\n",
               min_ms, avg, max_ms);
    }

    printf("\n");

    /* Cleanup */
    freeaddrinfo(res);
    net_cleanup();

    return (success > 0) ? 0 : 1;
}
