/*
 * libhostenc - Client fuer hostencd. Beschreibung der Schnittstelle: hostenc.h, Protokoll: ../PROTOCOL.md
 *
 * Aufbau: Alle Sockets sind nicht blockierend; jede Wartestelle laeuft ueber wait_sock() mit einer festen Frist
 * (monotone Uhr). Es gibt keine Stelle, die ohne Frist wartet, und keine Namensaufloesung.
 */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_WARNINGS)
#define _CRT_SECURE_NO_WARNINGS /* getenv, fopen: hier unbedenklich */
#endif

#include "hostenc.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#if defined(_MSC_VER)
#pragma comment(lib, "ws2_32.lib")
#endif
typedef SOCKET sock_t;
#define SOCK_NONE INVALID_SOCKET
#define sock_close closesocket
#define sock_errno() WSAGetLastError()
#define ERR_WOULDBLOCK(e) ((e) == WSAEWOULDBLOCK)
#define ERR_INPROGRESS(e) ((e) == WSAEWOULDBLOCK || (e) == WSAEINPROGRESS)
#define ERR_INTR(e) ((e) == WSAEINTR)
#define ERR_RESET(e) ((e) == WSAECONNRESET || (e) == WSAECONNABORTED || (e) == WSAESHUTDOWN || (e) == WSAENOTCONN || (e) == WSAENETRESET)
#else
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>
typedef int sock_t;
#define SOCK_NONE (-1)
#define sock_close close
#define sock_errno() errno
#define ERR_WOULDBLOCK(e) ((e) == EAGAIN || (e) == EWOULDBLOCK)
#define ERR_INPROGRESS(e) ((e) == EINPROGRESS)
#define ERR_INTR(e) ((e) == EINTR)
#define ERR_RESET(e) ((e) == ECONNRESET || (e) == EPIPE || (e) == ENOTCONN)
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#endif

/* --- Protokoll (PROTOCOL.md) ----------------------------------------------------------------------------- */

#define P_VERSION 1
#define P_HEADER 32
#define T_HELLO 1
#define T_OPEN 2
#define T_OPEN_ACK 3
#define T_FRAME 4
#define T_PACKET 5
#define T_SET_BITRATE 6
#define T_CLOSE 7
#define T_ERROR 8
#define F_KEY 1u
#define F_REOPENED 2u
#define P_OPEN_SIZE 40
#define P_OPEN_ACK_SIZE 48
#define P_SET_BITRATE_SIZE 8
#define P_MAX_ERROR_TEXT 255
#define P_MIN_DIM 16u
#define P_MAX_DIM 8192u
#define P_PACKET_SLACK (1u << 20)

#define CHUNK_BYTES (256u * 1024u)       /* Zwischenpuffer fuer Bilder mit Zeilenabstand != Breite */
#define PKT_START_BYTES (256u * 1024u)   /* Anfangsgroesse des Paketpuffers, waechst bis max_packet */
#define WIN_SNDBUF_DEFAULT (8 * 1024 * 1024)

typedef struct {
    uint16_t version, type;
    uint32_t seq, flags;
    int64_t pts;
    uint32_t length, aux;
} p_header;

struct hostenc {
    sock_t sock;
    hostenc_options opt; /* address/token zeigen auf die Kopien unten */
    char address[64];
    char token[HOSTENC_MAX_TOKEN + 1];
    size_t token_len;
    uint32_t seq;
    size_t y_bytes, uv_bytes;
    uint32_t max_packet;
    hostenc_info info;
    uint8_t *pkt_buf;
    size_t pkt_cap;
    uint8_t *chunk;
    uint32_t server_error;
    int wsa;
    char err[400];
};

static void wr16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}
static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}
static void wr64(uint8_t *p, uint64_t v) {
    wr32(p, (uint32_t)v);
    wr32(p + 4, (uint32_t)(v >> 32));
}
static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t rd64(const uint8_t *p) { return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32); }

static void header_write(uint8_t *b, uint16_t type, uint32_t seq, uint32_t flags, int64_t pts, uint32_t length) {
    memcpy(b, "HENC", 4);
    wr16(b + 4, P_VERSION);
    wr16(b + 6, type);
    wr32(b + 8, seq);
    wr32(b + 12, flags);
    wr64(b + 16, (uint64_t)pts);
    wr32(b + 24, length);
    wr32(b + 28, 0);
}

static int header_read(const uint8_t *b, p_header *h) {
    if (memcmp(b, "HENC", 4) != 0) return 0;
    h->version = rd16(b + 4);
    h->type = rd16(b + 6);
    h->seq = rd32(b + 8);
    h->flags = rd32(b + 12);
    h->pts = (int64_t)rd64(b + 16);
    h->length = rd32(b + 24);
    h->aux = rd32(b + 28);
    return 1;
}

/* --- Hilfen ---------------------------------------------------------------------------------------------- */

#if defined(__GNUC__)
static void set_err(hostenc_t *h, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
#endif
static void set_err(hostenc_t *h, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(h->err, sizeof(h->err), fmt, ap);
    va_end(ap);
}

static void copy_str(char *dst, size_t size, const char *src) {
    if (!dst || size == 0) return;
    snprintf(dst, size, "%s", src ? src : "");
}

/* Monotone Uhr in Mikrosekunden. */
static int64_t now_us(void) {
#if defined(_WIN32)
    LARGE_INTEGER f, c;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&c);
    return (int64_t)((c.QuadPart / f.QuadPart) * 1000000 + (c.QuadPart % f.QuadPart) * 1000000 / f.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
#endif
}

static void sock_errtext(int e, char *buf, size_t size) {
#if defined(_WIN32)
    snprintf(buf, size, "Winsock-Fehler %d", e);
#else
    snprintf(buf, size, "%s", strerror(e));
#endif
}

/* Wartet bis zur Frist auf Lesbarkeit bzw. Schreibbarkeit. 1 = bereit, 0 = Frist erreicht, -1 = Fehler. */
static int wait_sock(sock_t s, int for_write, int64_t deadline_us) {
    for (;;) {
        int64_t rest = deadline_us - now_us();
        if (rest <= 0) return 0;
#if defined(_WIN32)
        fd_set rd, wr, ex;
        struct timeval tv;
        int r;
        FD_ZERO(&rd);
        FD_ZERO(&wr);
        FD_ZERO(&ex);
        if (for_write) {
            FD_SET(s, &wr);
            FD_SET(s, &ex); /* ein gescheiterter Verbindungsaufbau meldet sich hier, nicht in wr */
        } else {
            FD_SET(s, &rd);
        }
        tv.tv_sec = (long)(rest / 1000000);
        tv.tv_usec = (long)(rest % 1000000);
        r = select(0, for_write ? NULL : &rd, for_write ? &wr : NULL, for_write ? &ex : NULL, &tv);
        if (r > 0) return 1;
        if (r == 0) continue; /* Frist oben neu pruefen */
        if (ERR_INTR(WSAGetLastError())) continue;
        return -1;
#else
        struct pollfd p;
        int ms = (int)((rest + 999) / 1000);
        int r;
        p.fd = s;
        p.events = for_write ? POLLOUT : POLLIN;
        p.revents = 0;
        r = poll(&p, 1, ms);
        if (r > 0) return 1; /* auch POLLERR/POLLHUP: der folgende Aufruf liefert den Grund */
        if (r == 0) continue;
        if (errno == EINTR) continue;
        return -1;
#endif
    }
}

static void drop(hostenc_t *h) {
    if (h->sock != SOCK_NONE) {
        sock_close(h->sock);
        h->sock = SOCK_NONE;
    }
}

typedef struct {
    const uint8_t *p;
    size_t n;
} hbuf;

/* Ein Sendeversuch ueber bis zu drei Puffer. Rueckgabe: gesendete Byte (> 0) oder -1. */
static long sys_sendv(sock_t s, const hbuf *b, int nb) {
#if defined(_WIN32)
    WSABUF w[3];
    DWORD sent = 0;
    int i;
    for (i = 0; i < nb && i < 3; i++) {
        w[i].buf = (CHAR *)(uintptr_t)b[i].p;
        w[i].len = (ULONG)(b[i].n > 0x10000000u ? 0x10000000u : b[i].n);
    }
    if (WSASend(s, w, (DWORD)i, &sent, 0, NULL, NULL) != 0) return -1;
    return (long)sent;
#else
    struct iovec v[3];
    struct msghdr m;
    int i;
    for (i = 0; i < nb && i < 3; i++) {
        v[i].iov_base = (void *)(uintptr_t)b[i].p;
        v[i].iov_len = b[i].n > 0x10000000u ? 0x10000000u : b[i].n;
    }
    memset(&m, 0, sizeof(m));
    m.msg_iov = v;
    m.msg_iovlen = (size_t)i;
    return (long)sendmsg(s, &m, MSG_NOSIGNAL);
#endif
}

/* Sendet alle Puffer vollstaendig oder gibt einen Fehlercode zurueck. Veraendert b. */
static int send_bufs(hostenc_t *h, hbuf *b, int nb, int64_t deadline_us) {
    int i = 0;
    while (i < nb) {
        long r;
        if (b[i].n == 0) {
            i++;
            continue;
        }
        r = sys_sendv(h->sock, b + i, nb - i);
        if (r > 0) {
            size_t done = (size_t)r;
            while (done > 0 && i < nb) {
                if (done >= b[i].n) {
                    done -= b[i].n;
                    b[i].n = 0;
                    i++;
                } else {
                    b[i].p += done;
                    b[i].n -= done;
                    done = 0;
                }
            }
            if (i < nb && now_us() >= deadline_us) return HOSTENC_ERR_TIMEOUT;
            continue;
        }
        {
            int e = sock_errno();
            if (r < 0 && ERR_INTR(e)) continue;
            if (r < 0 && ERR_WOULDBLOCK(e)) {
                int w = wait_sock(h->sock, 1, deadline_us);
                if (w == 0) return HOSTENC_ERR_TIMEOUT;
                if (w < 0) return HOSTENC_ERR_IO;
                continue;
            }
            if (r < 0 && ERR_RESET(e)) return HOSTENC_ERR_CLOSED;
            return HOSTENC_ERR_IO;
        }
    }
    return HOSTENC_OK;
}

static int send_one(hostenc_t *h, const uint8_t *p, size_t n, int64_t deadline_us) {
    hbuf b;
    b.p = p;
    b.n = n;
    return send_bufs(h, &b, 1, deadline_us);
}

static int recv_all(hostenc_t *h, uint8_t *p, size_t n, int64_t deadline_us) {
    size_t got = 0;
    while (got < n) {
        size_t want = n - got;
        int r;
        if (want > 0x40000000u) want = 0x40000000u;
#if defined(_WIN32)
        r = recv(h->sock, (char *)p + got, (int)want, 0);
#else
        r = (int)recv(h->sock, p + got, want, 0);
#endif
        if (r > 0) {
            got += (size_t)r;
            if (got < n && now_us() >= deadline_us) return HOSTENC_ERR_TIMEOUT;
            continue;
        }
        if (r == 0) return HOSTENC_ERR_CLOSED;
        {
            int e = sock_errno();
            if (ERR_INTR(e)) continue;
            if (ERR_WOULDBLOCK(e)) {
                int w = wait_sock(h->sock, 0, deadline_us);
                if (w == 0) return HOSTENC_ERR_TIMEOUT;
                if (w < 0) return HOSTENC_ERR_IO;
                continue;
            }
            if (ERR_RESET(e)) return HOSTENC_ERR_CLOSED;
            return HOSTENC_ERR_IO;
        }
    }
    return HOSTENC_OK;
}

/* Liest die Nutzdaten einer ERROR-Nachricht und legt Code und Text ab. Rueckgabe immer ein Fehlercode. */
static int read_error(hostenc_t *h, const p_header *hd, int64_t deadline_us) {
    uint8_t buf[4 + P_MAX_ERROR_TEXT + 1];
    size_t i, n;
    int r;
    if (hd->length < 4 || hd->length > 4 + P_MAX_ERROR_TEXT) {
        set_err(h, "ERROR-Nachricht mit unzulaessiger Laenge %u", (unsigned)hd->length);
        return HOSTENC_ERR_PROTOCOL;
    }
    r = recv_all(h, buf, hd->length, deadline_us);
    if (r != HOSTENC_OK) {
        set_err(h, "ERROR-Nachricht unvollstaendig (%s)", hostenc_strerror(r));
        return r;
    }
    n = hd->length - 4;
    for (i = 0; i < n; i++)
        if (buf[4 + i] < 0x20) buf[4 + i] = ' '; /* nichts Steuerndes in Protokolle uebernehmen */
    buf[4 + n] = 0;
    h->server_error = rd32(buf);
    set_err(h, "Dienst meldet Fehler %u: %s", (unsigned)h->server_error, (const char *)(buf + 4));
    return HOSTENC_ERR_SERVER;
}

/* Liest einen Kopf und prueft magic und Version. */
static int recv_header(hostenc_t *h, p_header *hd, int64_t deadline_us, const char *was) {
    uint8_t raw[P_HEADER];
    int r = recv_all(h, raw, sizeof(raw), deadline_us);
    if (r != HOSTENC_OK) {
        if (r == HOSTENC_ERR_TIMEOUT) set_err(h, "%s: keine Antwort innerhalb der Frist", was);
        else if (r == HOSTENC_ERR_CLOSED) set_err(h, "%s: Dienst hat die Verbindung getrennt", was);
        else set_err(h, "%s: Lesefehler", was);
        return r;
    }
    if (!header_read(raw, hd) || hd->version != P_VERSION) {
        set_err(h, "%s: Antwort ist kein hostenc-Kopf der Version 1", was);
        return HOSTENC_ERR_PROTOCOL;
    }
    return HOSTENC_OK;
}

/* Verbindet, meldet an und oeffnet den Encoder. Bei Fehler ist die Verbindung wieder zu. */
static int do_open(hostenc_t *h) {
    struct addrinfo hints, *res = NULL;
    char port[16];
    uint8_t msg[P_HEADER + HOSTENC_MAX_TOKEN + P_HEADER + P_OPEN_SIZE];
    uint8_t ack[P_OPEN_ACK_SIZE];
    uint8_t *o;
    size_t n;
    p_header hd;
    int64_t deadline;
    int r, one = 1;
    const hostenc_options *op = &h->opt;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV; /* keine Namensaufloesung: die kann beliebig lange dauern */
    snprintf(port, sizeof(port), "%u", (unsigned)op->port);
    if (getaddrinfo(h->address, port, &hints, &res) != 0 || !res) {
        set_err(h, "Adresse \"%s\" ist keine IP-Adresse", h->address);
        return HOSTENC_ERR_ADDRESS;
    }
    h->sock = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP);
    if (h->sock == SOCK_NONE) {
        freeaddrinfo(res);
        set_err(h, "Socket laesst sich nicht anlegen");
        return HOSTENC_ERR_IO;
    }
#if defined(_WIN32)
    {
        u_long nb = 1;
        int sndbuf = op->sndbuf_bytes > 0 ? op->sndbuf_bytes : WIN_SNDBUF_DEFAULT;
        ioctlsocket(h->sock, FIONBIO, &nb);
        setsockopt(h->sock, SOL_SOCKET, SO_SNDBUF, (const char *)&sndbuf, sizeof(sndbuf));
    }
#else
    {
        int fl = fcntl(h->sock, F_GETFL, 0);
        fcntl(h->sock, F_SETFL, (fl < 0 ? 0 : fl) | O_NONBLOCK);
        fcntl(h->sock, F_SETFD, FD_CLOEXEC);
        if (op->sndbuf_bytes > 0) setsockopt(h->sock, SOL_SOCKET, SO_SNDBUF, &op->sndbuf_bytes, sizeof(op->sndbuf_bytes));
    }
#endif
    setsockopt(h->sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof(one));

    deadline = now_us() + (int64_t)op->connect_timeout_ms * 1000;
    r = connect(h->sock, res->ai_addr, (int)res->ai_addrlen);
    freeaddrinfo(res);
    if (r != 0) {
        int e = sock_errno();
        char et[96];
        if (ERR_INPROGRESS(e) || ERR_INTR(e)) {
            int w = wait_sock(h->sock, 1, deadline);
            int serr = 0;
#if defined(_WIN32)
            int sl = sizeof(serr);
#else
            socklen_t sl = sizeof(serr);
#endif
            if (w == 0) {
                set_err(h, "Verbindungsaufbau zu %s Port %u nicht innerhalb von %d ms", h->address, (unsigned)op->port, op->connect_timeout_ms);
                drop(h);
                return HOSTENC_ERR_TIMEOUT;
            }
            if (w < 0 || getsockopt(h->sock, SOL_SOCKET, SO_ERROR, (char *)&serr, &sl) != 0) serr = -1;
            if (serr != 0) {
                sock_errtext(serr, et, sizeof(et));
                set_err(h, "Verbindung zu %s Port %u gescheitert: %s", h->address, (unsigned)op->port, serr == -1 ? "Socketfehler" : et);
                drop(h);
                return HOSTENC_ERR_CONNECT;
            }
        } else {
            sock_errtext(e, et, sizeof(et));
            set_err(h, "Verbindung zu %s Port %u gescheitert: %s", h->address, (unsigned)op->port, et);
            drop(h);
            return HOSTENC_ERR_CONNECT;
        }
    }

    /* HELLO und OPEN in einem Zug, dann auf OPEN_ACK warten. */
    deadline = now_us() + (int64_t)op->open_timeout_ms * 1000;
    h->seq = 1;
    header_write(msg, T_HELLO, 0, 0, 0, (uint32_t)h->token_len);
    memcpy(msg + P_HEADER, h->token, h->token_len);
    n = P_HEADER + h->token_len;
    header_write(msg + n, T_OPEN, h->seq, 0, 0, P_OPEN_SIZE);
    o = msg + n + P_HEADER;
    wr32(o, (uint32_t)op->codec);
    wr32(o + 4, op->width);
    wr32(o + 8, op->height);
    wr32(o + 12, op->fps_num);
    wr32(o + 16, op->fps_den);
    wr32(o + 20, op->bitrate);
    wr32(o + 24, op->max_bitrate);
    wr32(o + 28, op->gop);
    wr32(o + 32, (uint32_t)op->rc_mode);
    wr32(o + 36, op->qp);
    n += P_HEADER + P_OPEN_SIZE;

    r = send_one(h, msg, n, deadline);
    if (r == HOSTENC_OK) r = recv_header(h, &hd, deadline, "OPEN");
    else set_err(h, "OPEN: Senden gescheitert (%s)", hostenc_strerror(r));
    if (r == HOSTENC_OK) {
        if (hd.type == T_ERROR) {
            r = read_error(h, &hd, deadline);
        } else if (hd.type != T_OPEN_ACK || hd.length != P_OPEN_ACK_SIZE || hd.seq != h->seq) {
            set_err(h, "OPEN: unerwartete Antwort (Typ %u, Laenge %u)", (unsigned)hd.type, (unsigned)hd.length);
            r = HOSTENC_ERR_PROTOCOL;
        } else {
            r = recv_all(h, ack, sizeof(ack), deadline);
            if (r != HOSTENC_OK) set_err(h, "OPEN_ACK unvollstaendig (%s)", hostenc_strerror(r));
        }
    }
    if (r != HOSTENC_OK) {
        drop(h);
        return r;
    }

    h->info.codec = (int)rd32(ack);
    h->info.width = rd32(ack + 4);
    h->info.height = rd32(ack + 8);
    h->info.fps_num = rd32(ack + 12);
    h->info.fps_den = rd32(ack + 16);
    h->info.bitrate = rd32(ack + 20);
    h->info.max_bitrate = rd32(ack + 24);
    h->info.gop = rd32(ack + 28);
    h->info.rc_mode = (int)rd32(ack + 32);
    h->info.qp = rd32(ack + 36);
    h->info.backend = (int)rd32(ack + 40);
    h->info.max_packet = rd32(ack + 44);
    h->info.open_us = hd.aux;
    /* Der Client vertraut der Grenze des Dienstes nur bis zu dem, was das Protokoll fuer diese Groesse zulaesst. */
    if (h->info.width != op->width || h->info.height != op->height || h->info.max_packet == 0 ||
        (uint64_t)h->info.max_packet > (uint64_t)h->y_bytes + h->uv_bytes + P_PACKET_SLACK) {
        set_err(h, "OPEN_ACK passt nicht zur Anfrage (%ux%u, max_packet %u)", (unsigned)h->info.width, (unsigned)h->info.height,
                (unsigned)h->info.max_packet);
        drop(h);
        return HOSTENC_ERR_PROTOCOL;
    }
    h->max_packet = h->info.max_packet;
    return HOSTENC_OK;
}

/* --- oeffentliche Schnittstelle -------------------------------------------------------------------------- */

void hostenc_options_init(hostenc_options *o) {
    if (!o) return;
    memset(o, 0, sizeof(*o));
    o->port = HOSTENC_DEFAULT_PORT;
    o->codec = HOSTENC_CODEC_HEVC;
    o->fps_num = 30;
    o->fps_den = 1;
    o->rc_mode = HOSTENC_RC_DEFAULT;
    o->connect_timeout_ms = 300;
    o->open_timeout_ms = 700;
    o->frame_timeout_ms = 250;
    o->reconnect = 1;
}

int hostenc_open(const hostenc_options *o, hostenc_t **out, char *errbuf, size_t errbuf_size) {
    hostenc_t *h;
    size_t tl;
    int r;

    if (errbuf && errbuf_size) errbuf[0] = 0;
    if (!out) return HOSTENC_ERR_ARG;
    *out = NULL;
    if (!o || !o->address || !o->token) {
        copy_str(errbuf, errbuf_size, "Adresse oder Token fehlt");
        return HOSTENC_ERR_ARG;
    }
    tl = strlen(o->token);
    if (strlen(o->address) >= sizeof(h->address) || tl < 1 || tl > HOSTENC_MAX_TOKEN) {
        copy_str(errbuf, errbuf_size, "Adresse zu lang oder Token nicht 1 bis 256 Byte");
        return HOSTENC_ERR_ARG;
    }
    if ((o->codec != HOSTENC_CODEC_H264 && o->codec != HOSTENC_CODEC_HEVC) || o->width < P_MIN_DIM || o->height < P_MIN_DIM ||
        o->width > P_MAX_DIM || o->height > P_MAX_DIM || (o->width & 1) || (o->height & 1) || o->fps_num < 1 || o->fps_den < 1 ||
        o->rc_mode < HOSTENC_RC_DEFAULT || o->rc_mode > HOSTENC_RC_CQP || (o->rc_mode != HOSTENC_RC_CQP && o->bitrate == 0) ||
        o->port == 0) {
        copy_str(errbuf, errbuf_size, "Codec, Groesse (gerade, 16 bis 8192), Bildrate, Bitrate oder Port unzulaessig");
        return HOSTENC_ERR_ARG;
    }

    h = (hostenc_t *)calloc(1, sizeof(*h));
    if (!h) return HOSTENC_ERR_NOMEM;
    h->sock = SOCK_NONE;
    h->opt = *o;
    if (h->opt.connect_timeout_ms <= 0) h->opt.connect_timeout_ms = 300;
    if (h->opt.open_timeout_ms <= 0) h->opt.open_timeout_ms = 700;
    if (h->opt.frame_timeout_ms <= 0) h->opt.frame_timeout_ms = 250;
    copy_str(h->address, sizeof(h->address), o->address);
    memcpy(h->token, o->token, tl);
    h->token_len = tl;
    h->opt.address = h->address;
    h->opt.token = h->token;
    h->y_bytes = (size_t)o->width * o->height;
    h->uv_bytes = h->y_bytes / 2;
    h->chunk = (uint8_t *)malloc(CHUNK_BYTES);
    h->pkt_cap = PKT_START_BYTES;
    h->pkt_buf = (uint8_t *)malloc(h->pkt_cap);
    if (!h->chunk || !h->pkt_buf) {
        hostenc_close(h);
        return HOSTENC_ERR_NOMEM;
    }
#if defined(_WIN32)
    {
        WSADATA wd;
        if (WSAStartup(MAKEWORD(2, 2), &wd) != 0) {
            copy_str(errbuf, errbuf_size, "WSAStartup gescheitert");
            hostenc_close(h);
            return HOSTENC_ERR_IO;
        }
        h->wsa = 1;
    }
#endif
    r = do_open(h);
    if (r != HOSTENC_OK) {
        copy_str(errbuf, errbuf_size, h->err);
        hostenc_close(h);
        return r;
    }
    *out = h;
    return HOSTENC_OK;
}

/* Sendet eine Ebene. Stimmt der Zeilenabstand mit der Zeilenlaenge ueberein, geht sie ohne Kopie hinaus; sonst
 * werden die Zeilen stueckweise in den Zwischenpuffer gepackt (fill = schon belegte Byte darin, z. B. der Kopf). */
static int send_plane_rows(hostenc_t *h, const uint8_t *p, ptrdiff_t stride, size_t row_bytes, uint32_t rows, size_t *fill,
                           int64_t deadline_us) {
    uint32_t y;
    for (y = 0; y < rows; y++) {
        if (*fill + row_bytes > CHUNK_BYTES) {
            int r = send_one(h, h->chunk, *fill, deadline_us);
            if (r != HOSTENC_OK) return r;
            *fill = 0;
        }
        memcpy(h->chunk + *fill, p + (ptrdiff_t)y * stride, row_bytes);
        *fill += row_bytes;
    }
    return HOSTENC_OK;
}

int hostenc_encode(hostenc_t *h, const uint8_t *y, int y_stride, const uint8_t *uv, int uv_stride, int64_t pts, int keyframe,
                   hostenc_packet *pkt) {
    uint8_t head[P_HEADER];
    p_header hd;
    int64_t deadline, t0;
    uint32_t seq, w, ht;
    int r;

    if (!h) return HOSTENC_ERR_ARG;
    if (pkt) memset(pkt, 0, sizeof(*pkt));
    w = h->opt.width;
    ht = h->opt.height;
    if (!y || !uv || !pkt || (y_stride < 0 ? -(int64_t)y_stride : (int64_t)y_stride) < (int64_t)w ||
        (uv_stride < 0 ? -(int64_t)uv_stride : (int64_t)uv_stride) < (int64_t)w) {
        set_err(h, "Bildzeiger fehlt oder Zeilenabstand kleiner als die Breite");
        return HOSTENC_ERR_ARG;
    }
    h->server_error = 0;

    if (h->sock == SOCK_NONE) {
        if (!h->opt.reconnect) {
            set_err(h, "nicht verbunden");
            return HOSTENC_ERR_CLOSED;
        }
        r = do_open(h); /* eigene Fristen; das erste Bild danach ist ohnehin ein Keyframe */
        if (r != HOSTENC_OK) return r;
    }

    t0 = now_us();
    deadline = t0 + (int64_t)h->opt.frame_timeout_ms * 1000;
    seq = ++h->seq;
    header_write(head, T_FRAME, seq, keyframe ? F_KEY : 0, pts, (uint32_t)(h->y_bytes + h->uv_bytes));

    if (y_stride == (int)w && uv_stride == (int)w) {
        hbuf b[3];
        b[0].p = head;
        b[0].n = sizeof(head);
        b[1].p = y;
        b[1].n = h->y_bytes;
        b[2].p = uv;
        b[2].n = h->uv_bytes;
        r = send_bufs(h, b, 3, deadline);
    } else {
        size_t fill = sizeof(head);
        memcpy(h->chunk, head, sizeof(head));
        r = send_plane_rows(h, y, y_stride, w, ht, &fill, deadline);
        if (r == HOSTENC_OK) r = send_plane_rows(h, uv, uv_stride, w, ht / 2, &fill, deadline);
        if (r == HOSTENC_OK && fill > 0) r = send_one(h, h->chunk, fill, deadline);
    }
    if (r != HOSTENC_OK) {
        if (r == HOSTENC_ERR_TIMEOUT) {
            set_err(h, "FRAME seq %u: Senden nicht innerhalb von %d ms", (unsigned)seq, h->opt.frame_timeout_ms);
        } else {
            /* Hat der Dienst vor dem Trennen noch einen Fehler geschickt, ist der aufschlussreicher. */
            int64_t kurz = now_us() + 20000;
            int rr;
            set_err(h, "FRAME seq %u: Senden gescheitert (%s)", (unsigned)seq, hostenc_strerror(r));
            rr = recv_header(h, &hd, kurz < deadline ? kurz : deadline, "FRAME");
            if (rr == HOSTENC_OK && hd.type == T_ERROR) r = read_error(h, &hd, kurz < deadline ? kurz : deadline);
            else set_err(h, "FRAME seq %u: Senden gescheitert (%s)", (unsigned)seq, hostenc_strerror(r));
        }
        drop(h);
        return r;
    }

    r = recv_header(h, &hd, deadline, "FRAME");
    if (r == HOSTENC_OK) {
        if (hd.type == T_ERROR) {
            r = read_error(h, &hd, deadline);
        } else if (hd.type != T_PACKET || hd.seq != seq || hd.length == 0 || hd.length > h->max_packet) {
            set_err(h, "FRAME seq %u: unerwartete Antwort (Typ %u, seq %u, Laenge %u)", (unsigned)seq, (unsigned)hd.type, (unsigned)hd.seq,
                    (unsigned)hd.length);
            r = HOSTENC_ERR_PROTOCOL;
        }
    } else if (r == HOSTENC_ERR_TIMEOUT) {
        set_err(h, "FRAME seq %u: kein Paket innerhalb von %d ms", (unsigned)seq, h->opt.frame_timeout_ms);
    }
    if (r == HOSTENC_OK && hd.length > h->pkt_cap) {
        size_t cap = h->pkt_cap * 2;
        uint8_t *nb;
        if (cap < hd.length) cap = hd.length;
        if (cap > h->max_packet) cap = h->max_packet;
        nb = (uint8_t *)realloc(h->pkt_buf, cap);
        if (!nb) {
            set_err(h, "kein Speicher fuer ein Paket mit %u Byte", (unsigned)hd.length);
            r = HOSTENC_ERR_NOMEM;
        } else {
            h->pkt_buf = nb;
            h->pkt_cap = cap;
        }
    }
    if (r == HOSTENC_OK) {
        r = recv_all(h, h->pkt_buf, hd.length, deadline);
        if (r == HOSTENC_ERR_TIMEOUT) set_err(h, "FRAME seq %u: Paket nicht innerhalb von %d ms vollstaendig", (unsigned)seq, h->opt.frame_timeout_ms);
        else if (r != HOSTENC_OK) set_err(h, "FRAME seq %u: Verbindung beim Lesen des Pakets getrennt", (unsigned)seq);
    }
    if (r != HOSTENC_OK) {
        drop(h);
        return r;
    }

    pkt->data = h->pkt_buf;
    pkt->size = hd.length;
    pkt->keyframe = (hd.flags & F_KEY) != 0;
    pkt->reopened = (hd.flags & F_REOPENED) != 0;
    pkt->pts = hd.pts;
    pkt->server_us = hd.aux;
    return HOSTENC_OK;
}

int hostenc_set_bitrate(hostenc_t *h, uint32_t bitrate, uint32_t max_bitrate) {
    uint8_t msg[P_HEADER + P_SET_BITRATE_SIZE];
    int r;
    if (!h || bitrate == 0) return HOSTENC_ERR_ARG;
    /* Auch fuer einen spaeteren Neuaufbau merken. */
    h->opt.bitrate = bitrate;
    h->opt.max_bitrate = max_bitrate;
    if (h->sock == SOCK_NONE) return HOSTENC_OK;
    header_write(msg, T_SET_BITRATE, ++h->seq, 0, 0, P_SET_BITRATE_SIZE);
    wr32(msg + P_HEADER, bitrate);
    wr32(msg + P_HEADER + 4, max_bitrate);
    r = send_one(h, msg, sizeof(msg), now_us() + (int64_t)h->opt.frame_timeout_ms * 1000);
    if (r != HOSTENC_OK) {
        set_err(h, "SET_BITRATE: Senden gescheitert (%s)", hostenc_strerror(r));
        drop(h);
    }
    return r;
}

void hostenc_close(hostenc_t *h) {
    if (!h) return;
    if (h->sock != SOCK_NONE) {
        /* CLOSE ist eine Hoeflichkeit: ein Versuch, kein Warten. Das Schliessen allein genuegt dem Dienst auch. */
        uint8_t msg[P_HEADER];
        hbuf b;
        header_write(msg, T_CLOSE, ++h->seq, 0, 0, 0);
        b.p = msg;
        b.n = sizeof(msg);
        (void)sys_sendv(h->sock, &b, 1);
        drop(h);
    }
#if defined(_WIN32)
    if (h->wsa) WSACleanup();
#endif
    free(h->chunk);
    free(h->pkt_buf);
    memset(h->token, 0, sizeof(h->token));
    free(h);
}

int hostenc_get_info(const hostenc_t *h, hostenc_info *info) {
    if (!h || !info) return HOSTENC_ERR_ARG;
    *info = h->info;
    return HOSTENC_OK;
}

const char *hostenc_last_error(const hostenc_t *h) { return h ? h->err : ""; }

uint32_t hostenc_server_error(const hostenc_t *h) { return h ? h->server_error : 0; }

const char *hostenc_strerror(int err) {
    switch (err) {
        case HOSTENC_OK: return "in Ordnung";
        case HOSTENC_ERR_ARG: return "Argument ungueltig";
        case HOSTENC_ERR_NOMEM: return "kein Speicher";
        case HOSTENC_ERR_ADDRESS: return "Adresse ist keine IP-Adresse";
        case HOSTENC_ERR_CONNECT: return "Verbindung gescheitert";
        case HOSTENC_ERR_TIMEOUT: return "Frist ueberschritten";
        case HOSTENC_ERR_CLOSED: return "Verbindung getrennt";
        case HOSTENC_ERR_IO: return "Socketfehler";
        case HOSTENC_ERR_PROTOCOL: return "Protokollfehler";
        case HOSTENC_ERR_SERVER: return "Fehler vom Dienst";
        case HOSTENC_ERR_CONFIG: return "Konfiguration fehlt oder ist unvollstaendig";
        default: return "unbekannter Fehler";
    }
}

/* --- Konfigurationsdatei --------------------------------------------------------------------------------- */

int hostenc_config_default_path(char *buf, size_t size) {
    const char *env = getenv("HOSTENC_CONFIG");
    int n;
    if (!buf || size == 0) return HOSTENC_ERR_ARG;
    if (env && env[0]) {
        n = snprintf(buf, size, "%s", env);
    } else {
#if defined(_WIN32)
        const char *pd = getenv("ProgramData");
        n = snprintf(buf, size, "%s\\hostenc\\config.toml", pd && pd[0] ? pd : "C:\\ProgramData");
#else
        n = snprintf(buf, size, "/etc/hostenc/client.toml");
#endif
    }
    return (n < 0 || (size_t)n >= size) ? HOSTENC_ERR_ARG : HOSTENC_OK;
}

static char *trim(char *s) {
    char *e;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n')) e--;
    *e = 0;
    return s;
}

static int parse_int(const char *v, long min, long max, long *out) {
    char *end = NULL;
    long x;
    if (!v[0]) return 0;
    x = strtol(v, &end, 10);
    if (*end != 0 || x < min || x > max) return 0;
    *out = x;
    return 1;
}

int hostenc_config_load(const char *path, hostenc_config *cfg, char *errbuf, size_t errbuf_size) {
    char pfad[512], line[1024], msg[700];
    FILE *f;
    int nr = 0, rc = HOSTENC_OK;

    if (errbuf && errbuf_size) errbuf[0] = 0;
    if (!cfg) return HOSTENC_ERR_ARG;
    memset(cfg, 0, sizeof(*cfg));
    cfg->port = HOSTENC_DEFAULT_PORT;
    cfg->enabled = 1;
    if (path) {
        if (strlen(path) >= sizeof(pfad)) return HOSTENC_ERR_ARG;
        copy_str(pfad, sizeof(pfad), path);
    } else if (hostenc_config_default_path(pfad, sizeof(pfad)) != HOSTENC_OK) {
        return HOSTENC_ERR_ARG;
    }
    f = fopen(pfad, "rb");
    if (!f) {
        snprintf(msg, sizeof(msg), "%s laesst sich nicht lesen", pfad);
        copy_str(errbuf, errbuf_size, msg);
        return HOSTENC_ERR_CONFIG;
    }
    while (rc == HOSTENC_OK && fgets(line, sizeof(line), f)) {
        char *s = line, *eq, *k, *v;
        long x = 0;
        size_t len = strlen(line);
        nr++;
        if (len == sizeof(line) - 1 && line[len - 1] != '\n') {
            snprintf(msg, sizeof(msg), "%s Zeile %d: zu lang", pfad, nr);
            rc = HOSTENC_ERR_CONFIG;
            break;
        }
        if (nr == 1 && (unsigned char)s[0] == 0xEF && (unsigned char)s[1] == 0xBB && (unsigned char)s[2] == 0xBF) s += 3; /* BOM */
        s = trim(s);
        if (!s[0] || s[0] == '#' || s[0] == '[') continue;
        eq = strchr(s, '=');
        if (!eq) {
            snprintf(msg, sizeof(msg), "%s Zeile %d: '=' fehlt", pfad, nr);
            rc = HOSTENC_ERR_CONFIG;
            break;
        }
        *eq = 0;
        k = trim(s);
        v = trim(eq + 1);
        if (v[0] == '"' || v[0] == '\'') {
            char *zu = strchr(v + 1, v[0]);
            if (!zu) {
                snprintf(msg, sizeof(msg), "%s Zeile %d: Anfuehrungszeichen nicht geschlossen", pfad, nr);
                rc = HOSTENC_ERR_CONFIG;
                break;
            }
            *zu = 0;
            v++;
        } else {
            char *raute = strchr(v, '#');
            if (raute) *raute = 0;
            v = trim(v);
        }
        if (strcmp(k, "adresse") == 0) {
            if (strlen(v) >= sizeof(cfg->address)) rc = HOSTENC_ERR_CONFIG;
            else copy_str(cfg->address, sizeof(cfg->address), v);
        } else if (strcmp(k, "port") == 0) {
            if (parse_int(v, 1, 65535, &x)) cfg->port = (uint16_t)x;
            else rc = HOSTENC_ERR_CONFIG;
        } else if (strcmp(k, "token") == 0) {
            if (strlen(v) > HOSTENC_MAX_TOKEN) rc = HOSTENC_ERR_CONFIG;
            else copy_str(cfg->token, sizeof(cfg->token), v);
        } else if (strcmp(k, "aktiv") == 0) {
            if (strcmp(v, "true") == 0 || strcmp(v, "ja") == 0 || strcmp(v, "1") == 0) cfg->enabled = 1;
            else if (strcmp(v, "false") == 0 || strcmp(v, "nein") == 0 || strcmp(v, "0") == 0) cfg->enabled = 0;
            else rc = HOSTENC_ERR_CONFIG;
        } else if (strcmp(k, "verbindung_timeout_ms") == 0) {
            if (parse_int(v, 1, 60000, &x)) cfg->connect_timeout_ms = (int)x;
            else rc = HOSTENC_ERR_CONFIG;
        } else if (strcmp(k, "oeffnen_timeout_ms") == 0) {
            if (parse_int(v, 1, 60000, &x)) cfg->open_timeout_ms = (int)x;
            else rc = HOSTENC_ERR_CONFIG;
        } else if (strcmp(k, "bild_timeout_ms") == 0) {
            if (parse_int(v, 1, 60000, &x)) cfg->frame_timeout_ms = (int)x;
            else rc = HOSTENC_ERR_CONFIG;
        }
        /* unbekannte Schluessel werden uebergangen, damit neuere Dateien mit aelteren Clients gehen */
        if (rc != HOSTENC_OK) snprintf(msg, sizeof(msg), "%s Zeile %d: Wert fuer %s unzulaessig", pfad, nr, k);
    }
    fclose(f);
    memset(line, 0, sizeof(line)); /* kann das Token enthalten */
    if (rc == HOSTENC_OK && (!cfg->address[0] || !cfg->token[0])) {
        snprintf(msg, sizeof(msg), "%s: adresse oder token fehlt", pfad);
        rc = HOSTENC_ERR_CONFIG;
    }
    if (rc != HOSTENC_OK) copy_str(errbuf, errbuf_size, msg);
    return rc;
}

void hostenc_options_from_config(hostenc_options *o, const hostenc_config *cfg) {
    if (!o || !cfg) return;
    o->address = cfg->address;
    o->port = cfg->port;
    o->token = cfg->token;
    if (cfg->connect_timeout_ms > 0) o->connect_timeout_ms = cfg->connect_timeout_ms;
    if (cfg->open_timeout_ms > 0) o->open_timeout_ms = cfg->open_timeout_ms;
    if (cfg->frame_timeout_ms > 0) o->frame_timeout_ms = cfg->frame_timeout_ms;
}
