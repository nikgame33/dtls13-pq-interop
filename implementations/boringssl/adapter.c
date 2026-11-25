/* DTLS 1.3 / TLS 1.3 interop adapter for BoringSSL, implementing docs/shim-interface.md. */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <openssl/base.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#ifndef BSSL_COMMIT
#define BSSL_COMMIT "unknown"
#endif

enum { EXIT_OK = 0, EXIT_FAIL = 1, EXIT_UNSUPPORTED = 2, EXIT_USAGE = 64 };

#define SERVER_NAME "localhost"
#define MAX_GROUPS 16
#define TEARDOWN_MS 2000
/* The contract forbids adapter timeouts below 60 s; this only ends a run whose peer vanished. */
#define HANDSHAKE_MS 60000
/* --mtu is the IP path MTU; the contract reserves IPv6 + UDP headers for every address family. */
#define IP_UDP_OVERHEAD 48
/* BoringSSL's kMinMTU (ssl/d1_both.cc): SSL_set_mtu rejects smaller payloads. */
#define BSSL_MIN_PAYLOAD (256 - 28)
#define DTLS_HM_HEADER_LEN 12
#define DTLS_PLAINTEXT_HEADER_LEN 13
#define TLS_HM_HEADER_LEN 4
#define TLS_RECORD_HEADER_LEN 5

enum { HRR_SEEN = 1, HRR_COOKIE = 2, HRR_GROUP = 4 };

enum { OPT_ROLE, OPT_VARIANT, OPT_HOST, OPT_PORT, OPT_GROUPS, OPT_MTU, OPT_CA, OPT_KEY_SHARE,
    OPT_VALIDATE, OPT_CERT, OPT_KEY, OPT_TRANSPORT, OPT_RESUME, OPT_COUNT };

static const struct option LONGOPTS[] = {
    { "role", required_argument, NULL, OPT_ROLE },
    { "variant", required_argument, NULL, OPT_VARIANT },
    { "host", required_argument, NULL, OPT_HOST },
    { "port", required_argument, NULL, OPT_PORT },
    { "groups", required_argument, NULL, OPT_GROUPS },
    { "mtu", required_argument, NULL, OPT_MTU },
    { "ca", required_argument, NULL, OPT_CA },
    { "key-share", required_argument, NULL, OPT_KEY_SHARE },
    { "validate", required_argument, NULL, OPT_VALIDATE },
    { "cert", required_argument, NULL, OPT_CERT },
    { "key", required_argument, NULL, OPT_KEY },
    { "transport", required_argument, NULL, OPT_TRANSPORT },
    { "resume", required_argument, NULL, OPT_RESUME },
    { NULL, 0, NULL, 0 },
};

static const bool CLIENT_OPT[OPT_COUNT] = {
    [OPT_ROLE] = true, [OPT_VARIANT] = true, [OPT_HOST] = true, [OPT_PORT] = true,
    [OPT_GROUPS] = true, [OPT_MTU] = true, [OPT_CA] = true, [OPT_KEY_SHARE] = true,
    [OPT_TRANSPORT] = true, [OPT_RESUME] = true,
};
static const bool SERVER_OPT[OPT_COUNT] = {
    [OPT_ROLE] = true, [OPT_VARIANT] = true, [OPT_HOST] = true, [OPT_PORT] = true,
    [OPT_GROUPS] = true, [OPT_MTU] = true, [OPT_CA] = true, [OPT_VALIDATE] = true,
    [OPT_CERT] = true, [OPT_KEY] = true, [OPT_TRANSPORT] = true, [OPT_RESUME] = true,
};

struct options {
    const char *val[OPT_COUNT];
    bool server;
    bool cookie;
    bool tls;    /* --transport=tls: TLS 1.3 over TCP */
    bool resume; /* --resume=ticket: a second connection resumes the first */
    long mtu;
    long payload; /* largest UDP payload: mtu - IP_UDP_OVERHEAD, or 0 for --mtu=default */
};

static struct options g_opts;
static uint16_t g_groups[MAX_GROUPS];
static size_t g_ngroups;
static int g_fd = -1;
static unsigned g_hrr;     /* HRR_* bits, set by the message callback */
static bool g_started;     /* the handshake has begun, so hrr fields are known */
static int g_conn;         /* connection number for error prefixes; 0 with --resume=off */
static bool g_last = true; /* this connection's success ends the run, so it prints the result */
/* DTLS server: the peer of the current connection; the socket stays unconnected so that the
 * next connection's first datagram is never refused, and other sources are ignored. */
static struct sockaddr_storage g_peer;
static socklen_t g_peer_len;
static SSL_SESSION *g_ticket; /* client: the latest resumable session from a NewSessionTicket */

/* SHA-256("HelloRetryRequest"), RFC 9846 section 4.2.3. */
static const uint8_t HRR_RANDOM[32] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
};

/* IANA names and code points; BoringSSL implements a subset (SSL_get_group_name tells which). */
static const struct { const char *name; uint16_t id; } IANA_GROUPS[] = {
    { "secp256r1", 23 }, { "secp384r1", 24 }, { "secp521r1", 25 }, { "X25519", 29 },
    { "X448", 30 }, { "ffdhe2048", 256 }, { "ffdhe3072", 257 }, { "ffdhe4096", 258 },
    { "ffdhe6144", 259 }, { "ffdhe8192", 260 }, { "MLKEM512", 0x0200 }, { "MLKEM768", 0x0201 },
    { "MLKEM1024", 0x0202 }, { "MLKEM512X25519", 0x11EA }, { "SecP256r1MLKEM768", 0x11EB },
    { "X25519MLKEM768", 0x11EC }, { "SecP384r1MLKEM1024", 0x11ED },
};

static const char *group_name(uint16_t id)
{
    for (size_t i = 0; i < sizeof(IANA_GROUPS) / sizeof(IANA_GROUPS[0]); i++)
        if (IANA_GROUPS[i].id == id)
            return IANA_GROUPS[i].name;
    return SSL_get_group_name(id);
}

static bool group_id(const char *name, uint16_t *out)
{
    for (size_t i = 0; i < sizeof(IANA_GROUPS) / sizeof(IANA_GROUPS[0]); i++) {
        if (strcasecmp(name, IANA_GROUPS[i].name) == 0) {
            *out = IANA_GROUPS[i].id;
            return true;
        }
    }
    return false;
}

static void json_string(const char *s)
{
    if (s == NULL) {
        fputs("null", stdout);
        return;
    }
    putchar('"');
    for (; *s != '\0'; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\')
            printf("\\%c", c);
        else if (c < 0x20)
            printf("\\u%04x", c);
        else
            putchar(c);
    }
    putchar('"');
}

static void json_bool(bool known, bool value)
{
    fputs(!known ? "null" : value ? "true" : "false", stdout);
}

/* Emits the result line and returns code so callers can "return finish(...)". */
static int finish(int code, SSL *ssl, bool handshake_done, const char *error)
{
    bool known = g_started && code != EXIT_UNSUPPORTED && code != EXIT_USAGE;
    unsigned hrr = g_hrr;

    if (code == EXIT_OK && !g_last)
        return code;

    /* The message callback and the library must agree; trust the library for hrr itself. */
    if (known && ssl != NULL && SSL_used_hello_retry_request(ssl))
        hrr |= HRR_SEEN;
    printf("{\"event\": \"result\", \"ok\": %s, \"version\": ", code == EXIT_OK ? "true" : "false");
    json_string(handshake_done ? SSL_get_version(ssl) : NULL);
    fputs(", \"group\": ", stdout);
    json_string(handshake_done ? group_name(SSL_get_group_id(ssl)) : NULL);
    fputs(", \"hrr\": ", stdout);
    json_bool(known, hrr & HRR_SEEN);
    fputs(", \"hrr_cookie\": ", stdout);
    json_bool(known, (hrr & HRR_SEEN) && (hrr & HRR_COOKIE));
    fputs(", \"hrr_group\": ", stdout);
    json_bool(known, (hrr & HRR_SEEN) && (hrr & HRR_GROUP));
    fputs(", \"resumed\": ", stdout);
    json_bool(known && handshake_done, handshake_done && SSL_session_reused(ssl));
    fputs(", \"error\": ", stdout);
    if (error != NULL && g_conn > 0) {
        char prefixed[320];

        snprintf(prefixed, sizeof(prefixed), "connection %d: %s", g_conn, error);
        json_string(prefixed);
    } else
        json_string(error);
    puts("}");
    fflush(stdout);
    return code;
}

static int fail_msg(int code, SSL *ssl, const char *fmt, ...)
{
    char buf[256];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    fprintf(stderr, "error: %s\n", buf);
    ERR_print_errors_fp(stderr);
    return finish(code, ssl, false, buf);
}

/* Library failure: report the last BoringSSL reason string, else the SSL_get_error class. */
static int fail_ssl(SSL *ssl, int ret, const char *what)
{
    char buf[256];
    int saved_errno = errno;
    uint32_t e = ERR_peek_last_error();
    int err = ssl != NULL ? SSL_get_error(ssl, ret) : SSL_ERROR_SSL;
    const char *reason = e != 0 ? ERR_reason_error_string(e) : NULL;

    if (reason != NULL)
        snprintf(buf, sizeof(buf), "%s: %s", what, reason);
    else if (err == SSL_ERROR_SYSCALL && saved_errno != 0)
        snprintf(buf, sizeof(buf), "%s: %s", what, strerror(saved_errno));
    else
        snprintf(buf, sizeof(buf), "%s: %s", what, SSL_error_description(err));
    fprintf(stderr, "error: %s\n", buf);
    ERR_print_errors_fp(stderr);
    return finish(EXIT_FAIL, ssl, false, buf);
}

static unsigned read_u16(const uint8_t *p)
{
    return (unsigned)p[0] << 8 | p[1];
}

static unsigned read_u24(const uint8_t *p)
{
    return (unsigned)p[0] << 16 | (unsigned)p[1] << 8 | p[2];
}

static const char *hs_name(uint8_t type)
{
    switch (type) {
    case SSL3_MT_CLIENT_HELLO: return "ClientHello";
    case SSL3_MT_SERVER_HELLO: return "ServerHello";
    case SSL3_MT_NEW_SESSION_TICKET: return "NewSessionTicket";
    case SSL3_MT_ENCRYPTED_EXTENSIONS: return "EncryptedExtensions";
    case SSL3_MT_CERTIFICATE: return "Certificate";
    case SSL3_MT_CERTIFICATE_VERIFY: return "CertificateVerify";
    case SSL3_MT_FINISHED: return "Finished";
    case SSL3_MT_KEY_UPDATE: return "KeyUpdate";
    default: return "other";
    }
}

/* Walks the HRR extensions (RFC 9846 section 4.2.3 layout) for cookie and key_share. */
static size_t hm_header_len(void)
{
    return g_opts.tls ? TLS_HM_HEADER_LEN : DTLS_HM_HEADER_LEN;
}

static unsigned hrr_flags(const uint8_t *p, size_t len)
{
    size_t off = hm_header_len() + 2 + sizeof(HRR_RANDOM), end;
    unsigned flags = HRR_SEEN;

    if (off >= len)
        return flags;
    off += 1 + p[off] + 2 + 1; /* session id echo, cipher suite, compression */
    if (off + 2 > len)
        return flags;
    end = off + 2 + read_u16(p + off);
    end = end < len ? end : len;
    for (off += 2; off + 4 <= end; off += 4 + read_u16(p + off + 2)) {
        if (read_u16(p + off) == TLSEXT_TYPE_cookie)
            flags |= HRR_COOKIE;
        else if (read_u16(p + off) == TLSEXT_TYPE_key_share)
            flags |= HRR_GROUP;
    }
    return flags;
}

/* Writes the groups of a complete ClientHello's key_share extension to out, e.g. "X25519". */
static void ch_key_shares(const uint8_t *p, size_t len, char *out, size_t out_len)
{
    size_t off = hm_header_len() + 2 + 32, end;

    snprintf(out, out_len, "none");
    if (off + 1 > len)
        return;
    off += 1 + p[off]; /* session id */
    if (off + 1 > len)
        return;
    if (!g_opts.tls)
        off += 1 + p[off]; /* legacy DTLS cookie */
    if (off + 2 > len)
        return;
    off += 2 + read_u16(p + off); /* cipher suites */
    if (off + 1 > len)
        return;
    off += 1 + p[off]; /* compression methods */
    if (off + 2 > len)
        return;
    end = off + 2 + read_u16(p + off);
    end = end < len ? end : len;
    for (off += 2; off + 4 <= end; off += 4 + read_u16(p + off + 2)) {
        size_t ext_end = off + 4 + read_u16(p + off + 2), used = 0;

        if (read_u16(p + off) != TLSEXT_TYPE_key_share || ext_end > end || off + 6 > ext_end)
            continue;
        out[0] = '\0';
        for (size_t k = off + 6; k + 4 <= ext_end; k += 4 + read_u16(p + k + 2)) {
            const char *name = group_name((uint16_t)read_u16(p + k));
            int n = name != NULL ? snprintf(out + used, out_len - used, "%s%s", used ? "," : "", name)
                                 : snprintf(out + used, out_len - used, "%s0x%04x", used ? "," : "",
                                       read_u16(p + k));
            if (n < 0 || (size_t)n >= out_len - used)
                break;
            used += (size_t)n;
        }
        if (used == 0)
            snprintf(out, out_len, "empty");
        return;
    }
}

/* DTLS: sent handshake data arrives per fragment (12-byte header each), received as whole
 * messages; HRR always fits one fragment. TLS: whole messages with a 4-byte header. */
static void msg_cb(int write_p, int version, int content_type, const void *buf, size_t len,
    SSL *ssl, void *arg)
{
    const uint8_t *p = buf;
    const char *dir = write_p ? ">>" : "<<";
    unsigned offset, frag_len, msg_len;

    (void)version, (void)ssl, (void)arg;
    if (content_type == SSL3_RT_HEADER) {
        /* Plaintext (epoch 0) record headers show how ClientHello and ServerHello were cut. */
        if (len == DTLS_PLAINTEXT_HEADER_LEN && p[0] == SSL3_RT_HANDSHAKE && !g_opts.tls)
            fprintf(stderr, "%s plaintext handshake record (%u bytes)\n", dir, read_u16(p + 11));
        else if (len == TLS_RECORD_HEADER_LEN && p[0] == SSL3_RT_HANDSHAKE && g_opts.tls)
            fprintf(stderr, "%s plaintext handshake record (%u bytes)\n", dir, read_u16(p + 3));
        return;
    }
    if (content_type == SSL3_RT_ACK) {
        fprintf(stderr, "%s ACK (%zu bytes)\n", dir, len);
        return;
    }
    if (content_type == SSL3_RT_ALERT && len == 2) {
        fprintf(stderr, "%s alert %s\n", dir, SSL_alert_desc_string_long(p[1]));
        return;
    }
    if (content_type != SSL3_RT_HANDSHAKE || len < hm_header_len())
        return;
    msg_len = read_u24(p + 1);
    offset = g_opts.tls ? 0 : read_u24(p + 6);
    frag_len = g_opts.tls ? msg_len : read_u24(p + 9);
    if (p[0] == SSL3_MT_SERVER_HELLO && offset == 0
        && len >= hm_header_len() + 2 + sizeof(HRR_RANDOM)
        && memcmp(p + hm_header_len() + 2, HRR_RANDOM, sizeof(HRR_RANDOM)) == 0) {
        g_hrr = hrr_flags(p, len);
        fprintf(stderr, "%s HelloRetryRequest (%u bytes, cookie=%d, selected_group=%d)\n", dir,
            msg_len, (g_hrr & HRR_COOKIE) != 0, (g_hrr & HRR_GROUP) != 0);
        return;
    }
    if (p[0] == SSL3_MT_CLIENT_HELLO && offset == 0 && frag_len == msg_len) {
        char shares[128];

        ch_key_shares(p, len, shares, sizeof(shares));
        fprintf(stderr, "%s ClientHello (%u bytes, key_share=%s)\n", dir, msg_len, shares);
    }
    if (write_p)
        fprintf(stderr, ">> %s (%u bytes, fragment %u+%u)\n", hs_name(p[0]), msg_len, offset,
            frag_len);
    else if (p[0] != SSL3_MT_CLIENT_HELLO)
        fprintf(stderr, "<< %s (%u bytes)\n", hs_name(p[0]), msg_len);
}

/* BoringSSL has no datagram BIO; this one does send/recv on the non-blocking socket (UDP or TCP)
 * and logs each call. It answers no MTU query, so --mtu=default gets the library default. */
static const char *unit(void)
{
    return g_opts.tls ? "tcp" : "datagram";
}

static int udp_write(BIO *b, const char *buf, int len)
{
    ssize_t n;

    BIO_clear_retry_flags(b);
    if (g_peer_len != 0)
        n = sendto(g_fd, buf, (size_t)len, 0, (struct sockaddr *)&g_peer, g_peer_len);
    else
        n = send(g_fd, buf, (size_t)len, MSG_NOSIGNAL);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            BIO_set_retry_write(b);
        return -1;
    }
    fprintf(stderr, ">> %s (%zd bytes)\n", unit(), n);
    return (int)n;
}

static int udp_read(BIO *b, char *buf, int len)
{
    struct sockaddr_storage from;
    socklen_t from_len;
    ssize_t n;

    BIO_clear_retry_flags(b);
    for (;;) {
        from_len = sizeof(from);
        n = recvfrom(g_fd, buf, (size_t)len, 0, (struct sockaddr *)&from, &from_len);
        if (n < 0 || g_peer_len == 0
            || (from_len == g_peer_len && memcmp(&from, &g_peer, from_len) == 0))
            break;
        fprintf(stderr, "<< ignored datagram (%zd bytes) from another peer\n", n);
    }
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            BIO_set_retry_read(b);
        return -1;
    }
    fprintf(stderr, "<< %s (%zd bytes)\n", unit(), n);
    return (int)n;
}

static long udp_ctrl(BIO *b, int cmd, long larg, void *parg)
{
    (void)b, (void)larg, (void)parg;
    return cmd == BIO_CTRL_FLUSH;
}

static int udp_create(BIO *b)
{
    BIO_set_init(b, 1);
    return 1;
}

static BIO *new_udp_bio(void)
{
    static BIO_METHOD *method;

    if (method == NULL) {
        method = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "udp");
        if (method == NULL || !BIO_meth_set_write(method, udp_write)
            || !BIO_meth_set_read(method, udp_read) || !BIO_meth_set_ctrl(method, udp_ctrl)
            || !BIO_meth_set_create(method, udp_create))
            return NULL;
    }
    return BIO_new(method);
}

static long ms_until(const struct timespec *deadline)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return (deadline->tv_sec - now.tv_sec) * 1000 + (deadline->tv_nsec - now.tv_nsec) / 1000000;
}

static struct timespec deadline_in(long ms)
{
    struct timespec t;

    clock_gettime(CLOCK_MONOTONIC, &t);
    t.tv_sec += ms / 1000;
    t.tv_nsec += (ms % 1000) * 1000000;
    if (t.tv_nsec >= 1000000000) {
        t.tv_sec++;
        t.tv_nsec -= 1000000000;
    }
    return t;
}

/* BoringSSL leaves DTLS retransmission timers to the caller: wait for the socket or the next
 * timer (DTLSv1_get_timeout) and fire it (DTLSv1_handle_timeout). False at the deadline. */
static bool wait_io(SSL *ssl, bool want_write, const struct timespec *deadline)
{
    struct pollfd p = { .fd = g_fd, .events = want_write ? POLLOUT : POLLIN };
    struct timeval tv;
    long left = ms_until(deadline), timer = -1, wait;
    int n;

    if (left <= 0)
        return false;
    if (DTLSv1_get_timeout(ssl, &tv))
        timer = (long)tv.tv_sec * 1000 + ((long)tv.tv_usec + 999) / 1000;
    wait = timer >= 0 && timer < left ? timer : left;
    n = poll(&p, 1, (int)wait);
    if (n < 0 && errno != EINTR)
        return false;
    if (n == 0 && timer >= 0 && timer <= left && DTLSv1_handle_timeout(ssl) < 0)
        fprintf(stderr, "retransmission failed: %s\n", strerror(errno));
    return true;
}

enum op { OP_HANDSHAKE, OP_READ, OP_WRITE, OP_SHUTDOWN };

/* Repeats op while it only wants I/O. Returns its last return value; *timed_out tells a
 * deadline apart from a library error. SSL_shutdown is done once close_notify is sent (0). */
static int drive(SSL *ssl, enum op op, void *buf, int len, const struct timespec *deadline,
    bool *timed_out)
{
    int ret, err;

    *timed_out = false;
    for (;;) {
        switch (op) {
        case OP_HANDSHAKE: ret = SSL_do_handshake(ssl); break;
        case OP_READ: ret = SSL_read(ssl, buf, len); break;
        case OP_WRITE: ret = SSL_write(ssl, buf, len); break;
        default: ret = SSL_shutdown(ssl); break;
        }
        if (ret > 0 || (op == OP_SHUTDOWN && ret == 0))
            return ret;
        err = SSL_get_error(ssl, ret);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
            return ret;
        if (!wait_io(ssl, err == SSL_ERROR_WANT_WRITE, deadline)) {
            *timed_out = true;
            return ret;
        }
    }
}

/* Like fail_ssl, but names a deadline that passed instead of a library error. */
static int fail_drive(SSL *ssl, int ret, bool timed_out, const char *what, long ms)
{
    if (timed_out)
        return fail_msg(EXIT_FAIL, ssl, "%s: no progress within %ld ms", what, ms);
    return fail_ssl(ssl, ret, what);
}

/* Waits up to TEARDOWN_MS for the peer's close_notify with SSL_read: BoringSSL's DTLS
 * SSL_shutdown never waits for it (ssl/ssl_lib.cc). Errors only go to stderr. */
static void await_close_notify(SSL *ssl)
{
    struct timespec deadline = deadline_in(TEARDOWN_MS);
    char buf[64];
    bool timed_out;
    int ret;

    do
        ret = drive(ssl, OP_READ, buf, sizeof(buf), &deadline, &timed_out);
    while (ret > 0);
    if (timed_out)
        fprintf(stderr, "teardown: no close_notify within %d ms\n", TEARDOWN_MS);
    else if (SSL_get_error(ssl, ret) != SSL_ERROR_ZERO_RETURN) {
        fprintf(stderr, "teardown: SSL_read: %s\n", SSL_error_description(SSL_get_error(ssl, ret)));
        ERR_print_errors_fp(stderr);
    }
    fprintf(stderr, "teardown done\n");
    ERR_clear_error();
}

static void send_close_notify(SSL *ssl)
{
    struct timespec deadline = deadline_in(TEARDOWN_MS);
    bool timed_out;

    if (drive(ssl, OP_SHUTDOWN, NULL, 0, &deadline, &timed_out) < 0) {
        fprintf(stderr, "teardown: sending close_notify failed\n");
        ERR_print_errors_fp(stderr);
    }
    ERR_clear_error();
}

/* Creates the connection on g_fd and applies --mtu. */
static SSL *new_connection(SSL_CTX *ctx)
{
    SSL *ssl = SSL_new(ctx);
    BIO *bio = new_udp_bio();

    if (ssl == NULL || bio == NULL)
        return NULL;
    SSL_set_bio(ssl, bio, bio);
    if (g_opts.payload != 0) {
        /* d1->mtu is the whole datagram ("max DTLS packet size"), so it takes the payload. */
        SSL_set_options(ssl, SSL_OP_NO_QUERY_MTU);
        if (!SSL_set_mtu(ssl, (unsigned)g_opts.payload))
            return NULL;
    }
    return ssl;
}

static bool set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL);

    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static int echo_and_close(SSL *ssl, bool server)
{
    struct timespec deadline = deadline_in(HANDSHAKE_MS);
    char buf[64];
    bool timed_out, need_ticket;
    int ret;

    if (!server && (ret = drive(ssl, OP_WRITE, "ping", 4, &deadline, &timed_out)) <= 0)
        return fail_drive(ssl, ret, timed_out, "writing ping", HANDSHAKE_MS);
    if ((ret = drive(ssl, OP_READ, buf, sizeof(buf), &deadline, &timed_out)) <= 0)
        return fail_drive(ssl, ret, timed_out, server ? "reading ping" : "reading pong",
            HANDSHAKE_MS);
    if (ret != 4 || memcmp(buf, server ? "ping" : "pong", 4) != 0)
        return fail_msg(EXIT_FAIL, ssl, "unexpected %s (%d bytes)", server ? "message" : "echo",
            ret);
    need_ticket = !server && g_opts.resume && g_conn == 1 && g_ticket == NULL;
    if (server && (ret = drive(ssl, OP_WRITE, "pong", 4, &deadline, &timed_out)) <= 0)
        return fail_drive(ssl, ret, timed_out, "writing pong", HANDSHAKE_MS);

    /* The client's verdict is final after pong; teardown problems are only logged. */
    if (server) {
        await_close_notify(ssl);
        send_close_notify(ssl);
    } else {
        send_close_notify(ssl);
        await_close_notify(ssl);
    }
    if (need_ticket)
        return fail_msg(EXIT_FAIL, ssl, "no session ticket received");
    return finish(EXIT_OK, ssl, true, NULL);
}

static int handshake(SSL *ssl)
{
    struct timespec deadline = deadline_in(HANDSHAKE_MS);
    bool timed_out;
    int ret;

    g_started = true;
    if ((ret = drive(ssl, OP_HANDSHAKE, NULL, 0, &deadline, &timed_out)) != 1)
        return fail_drive(ssl, ret, timed_out, "handshake", HANDSHAKE_MS);
    fprintf(stderr, "handshake done: %s %s\n", SSL_get_version(ssl),
        group_name(SSL_get_group_id(ssl)));
    return EXIT_OK;
}

/* Connects a new socket (UDP or TCP) to --host/--port; a new source port per connection. */
static int connect_socket(void)
{
    int type = g_opts.tls ? SOCK_STREAM : SOCK_DGRAM, fd = -1, gai;
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = type }, *res, *ai;

    if ((gai = getaddrinfo(g_opts.val[OPT_HOST], g_opts.val[OPT_PORT], &hints, &res)) != 0) {
        fprintf(stderr, "resolving --host: %s\n", gai_strerror(gai));
        return -1;
    }
    for (ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, type, 0);
        if (fd >= 0 && connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
            break;
        if (fd >= 0)
            close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd >= 0 && !set_nonblocking(fd)) {
        close(fd);
        fd = -1;
    }
    return fd;
}

/* Keeps the latest resumable session; BoringSSL reports TLS 1.3 tickets only through this. */
static int new_session_cb(SSL *ssl, SSL_SESSION *session)
{
    (void)ssl;
    if (!SSL_SESSION_is_resumable(session))
        return 0;
    SSL_SESSION_free(g_ticket);
    g_ticket = session;
    fprintf(stderr, "session ticket received\n");
    return 1;
}

/* One client lifecycle on a new socket; offer is the session to resume, or NULL. */
static int client_connection(SSL_CTX *ctx, SSL_SESSION *offer)
{
    const char *share = g_opts.val[OPT_KEY_SHARE];
    uint16_t share_id;
    SSL *ssl;
    int rc;

    g_hrr = 0;
    g_started = false;
    if ((g_fd = connect_socket()) < 0)
        return fail_msg(EXIT_FAIL, NULL, "connecting %s socket: %s", g_opts.tls ? "TCP" : "UDP",
            strerror(errno));
    if ((ssl = new_connection(ctx)) == NULL)
        return fail_ssl(NULL, 0, "creating connection");
    SSL_set_connect_state(ssl);
    if (!SSL_set1_host(ssl, SERVER_NAME) || !SSL_set_tlsext_host_name(ssl, SERVER_NAME))
        return fail_ssl(ssl, 0, "setting server name");
    /* An empty list is BoringSSL's documented way to send an empty key_share. */
    if (strcmp(share, "default") != 0
        && !SSL_set1_client_key_shares(ssl, &share_id, group_id(share, &share_id) ? 1 : 0))
        return fail_ssl(ssl, 0, "SSL_set1_client_key_shares");
    if (offer != NULL && !SSL_set_session(ssl, offer))
        return fail_ssl(ssl, 0, "SSL_set_session");

    if ((rc = handshake(ssl)) != EXIT_OK)
        return rc;
    rc = echo_and_close(ssl, false);
    SSL_free(ssl);
    close(g_fd);
    return rc;
}

static int run_client(SSL_CTX *ctx)
{
    int rc;

    g_last = !g_opts.resume;
    if ((rc = client_connection(ctx, NULL)) != EXIT_OK || !g_opts.resume)
        return rc;
    g_conn = 2;
    g_last = true;
    return client_connection(ctx, g_ticket);
}

/* Contract rule 1 ("key share first"): BoringSSL itself picks the first server group the client
 * supports and sends an HRR if it has no share for it, so the best shared group is moved first. */
static enum ssl_select_cert_result_t select_group_cb(const SSL_CLIENT_HELLO *ch)
{
    const uint8_t *p;
    size_t len, end, best = g_ngroups, n = 1;
    uint16_t order[MAX_GROUPS];

    if (!SSL_early_callback_ctx_extension_get(ch, TLSEXT_TYPE_key_share, &p, &len) || len < 2)
        return ssl_select_cert_success;
    end = 2 + read_u16(p);
    end = end < len ? end : len;
    for (size_t off = 2; off + 4 <= end; off += 4 + read_u16(p + off + 2)) {
        for (size_t i = 0; i < best; i++) {
            if (g_groups[i] == read_u16(p + off)) {
                best = i;
                break;
            }
        }
    }
    if (best == 0 || best == g_ngroups)
        return ssl_select_cert_success;
    order[0] = g_groups[best];
    for (size_t i = 0; i < g_ngroups; i++)
        if (i != best)
            order[n++] = g_groups[i];
    fprintf(stderr, "key share first: selecting %s\n", group_name(order[0]));
    return SSL_set1_group_ids(ch->ssl, order, g_ngroups) ? ssl_select_cert_success
                                                         : ssl_select_cert_error;
}

static int bind_server_socket(void)
{
    int type = g_opts.tls ? SOCK_STREAM : SOCK_DGRAM, fd, one = 1;
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = type, .ai_flags = AI_PASSIVE },
                    *res;
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);

    if (getaddrinfo(g_opts.val[OPT_HOST], g_opts.val[OPT_PORT], &hints, &res) != 0)
        return -1;
    fd = socket(res->ai_family, type, 0);
    if (fd >= 0 && g_opts.tls)
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (fd >= 0 && (bind(fd, res->ai_addr, res->ai_addrlen) != 0 || (g_opts.tls && listen(fd, 4) != 0))) {
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0 || getsockname(fd, (struct sockaddr *)&addr, &len) != 0)
        return -1;
    printf("{\"event\": \"ready\", \"port\": %u}\n",
        ntohs(addr.ss_family == AF_INET6 ? ((struct sockaddr_in6 *)&addr)->sin6_port
                                         : ((struct sockaddr_in *)&addr)->sin_port));
    fflush(stdout);
    return fd;
}

/* BoringSSL has no DTLS listener: the first datagram from a new source starts a connection,
 * and the unconnected socket then only exchanges datagrams with that peer. */
static bool await_dtls_peer(int fd)
{
    struct sockaddr_storage prev = g_peer, from;
    socklen_t prev_len = g_peer_len, from_len;
    struct pollfd p = { .fd = fd, .events = POLLIN };
    unsigned char byte;

    for (;;) {
        if (poll(&p, 1, -1) < 0 && errno != EINTR)
            return false;
        from_len = sizeof(from);
        if (recvfrom(fd, &byte, 1, MSG_PEEK, (struct sockaddr *)&from, &from_len) < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            return false;
        }
        if (prev_len == 0 || from_len != prev_len || memcmp(&from, &prev, from_len) != 0)
            break;
        recv(fd, &byte, 1, 0);
        fprintf(stderr, "<< ignored datagram from the previous connection's peer\n");
    }
    g_peer = from;
    g_peer_len = from_len;
    return true;
}

static int server_connection(SSL_CTX *ctx, int listen_fd)
{
    SSL *ssl;
    int rc;

    g_hrr = 0;
    g_started = false;
    if (g_opts.tls) {
        if ((g_fd = accept(listen_fd, NULL, NULL)) < 0 || !set_nonblocking(g_fd))
            return fail_msg(EXIT_FAIL, NULL, "accepting TCP connection: %s", strerror(errno));
    } else if (!await_dtls_peer(listen_fd))
        return fail_msg(EXIT_FAIL, NULL, "waiting for the first datagram: %s", strerror(errno));
    if ((ssl = new_connection(ctx)) == NULL)
        return fail_ssl(NULL, 0, "creating connection");
    SSL_set_accept_state(ssl);

    if ((rc = handshake(ssl)) != EXIT_OK)
        return rc;
    rc = echo_and_close(ssl, true);
    SSL_free(ssl);
    if (g_opts.tls)
        close(g_fd);
    return rc;
}

static int run_server(SSL_CTX *ctx)
{
    int listen_fd, rc;

    /* BoringSSL servers never put a cookie into an HRR (ssl/tls13_server.cc). */
    if (g_opts.cookie)
        return fail_msg(EXIT_UNSUPPORTED, NULL,
            "BoringSSL servers have no HRR cookie (do_send_hello_retry_request in "
            "ssl/tls13_server.cc); --validate=cookie not possible");
    if (SSL_CTX_use_certificate_chain_file(ctx, g_opts.val[OPT_CERT]) != 1
        || SSL_CTX_use_PrivateKey_file(ctx, g_opts.val[OPT_KEY], SSL_FILETYPE_PEM) != 1
        || SSL_CTX_check_private_key(ctx) != 1)
        return fail_ssl(NULL, 0, "loading --cert/--key");
    SSL_CTX_set_select_certificate_cb(ctx, select_group_cb);

    if ((listen_fd = bind_server_socket()) < 0)
        return fail_msg(EXIT_FAIL, NULL, "binding %s socket: %s", g_opts.tls ? "TCP" : "UDP",
            strerror(errno));
    if (!g_opts.tls) {
        if (!set_nonblocking(listen_fd))
            return fail_msg(EXIT_FAIL, NULL, "socket: %s", strerror(errno));
        g_fd = listen_fd;
    }
    g_last = !g_opts.resume;
    if ((rc = server_connection(ctx, listen_fd)) != EXIT_OK || !g_opts.resume)
        return rc;
    g_conn = 2;
    g_last = true;
    return server_connection(ctx, listen_fd);
}

/* Rejects groups this build lacks (exit 2) and sets the group list in --groups order. */
static int configure_groups(SSL_CTX *ctx)
{
    char *copy = strdup(g_opts.val[OPT_GROUPS]);
    int rc = EXIT_OK;

    if (copy == NULL)
        return fail_msg(EXIT_FAIL, NULL, "out of memory");
    for (char *tok = strtok(copy, ","); tok != NULL; tok = strtok(NULL, ",")) {
        uint16_t id;

        if (!group_id(tok, &id) || SSL_get_group_name(id) == NULL) {
            rc = fail_msg(EXIT_UNSUPPORTED, NULL, "group %s not implemented by BoringSSL", tok);
            goto out;
        }
        for (size_t i = 0; i < g_ngroups; i++) {
            if (g_groups[i] == id) {
                rc = fail_msg(EXIT_USAGE, NULL, "usage: --groups lists %s twice", tok);
                goto out;
            }
        }
        g_groups[g_ngroups++] = id;
    }
    if (!SSL_CTX_set1_group_ids(ctx, g_groups, g_ngroups))
        rc = fail_ssl(NULL, 0, "SSL_CTX_set1_group_ids");
out:
    free(copy);
    return rc;
}

static int usage(const char *fmt, const char *arg)
{
    char msg[256];

    snprintf(msg, sizeof(msg), fmt, arg);
    fprintf(stderr,
        "usage: run --role=client --variant=default --host=HOST --port=PORT\n"
        "           --groups=G1[,G2...] --transport=dtls|tls --resume=off|ticket\n"
        "           --mtu=N|default --ca=FILE --key-share=GROUP|empty|default\n"
        "       run --role=server --variant=default --host=HOST --port=PORT\n"
        "           --groups=G1[,G2...] --transport=dtls|tls --resume=off|ticket\n"
        "           --mtu=N|default --ca=FILE --validate=off|cookie --cert=FILE --key=FILE\n");
    return fail_msg(EXIT_USAGE, NULL, "usage: %s", msg);
}

static bool in_list(const char *word, const char *list)
{
    size_t len = strlen(word);

    for (const char *p = list; *p != '\0'; p += strcspn(p, ",") + (p[strcspn(p, ",")] == ',')) {
        if (strcspn(p, ",") == len && strncasecmp(p, word, len) == 0)
            return true;
    }
    return false;
}

static bool valid_groups(const char *s)
{
    size_t count = 1;

    if (*s == '\0' || *s == ',' || s[strlen(s) - 1] == ',' || strstr(s, ",,") != NULL)
        return false;
    for (; *s != '\0'; s++)
        count += *s == ',';
    return count <= MAX_GROUPS;
}

/* Every option of the role is required; anything missing, foreign, repeated or malformed is 64. */
static int parse_options(int argc, char **argv)
{
    const bool *allowed;
    const char *v;
    char *end;
    long port;
    int c;

    /* getopt_long accepts unambiguous abbreviations; the contract wants exact names. */
    for (int i = 1; i < argc; i++) {
        size_t len = strcspn(argv[i] + 2, "=");
        bool known = false;

        if (strncmp(argv[i], "--", 2) != 0)
            continue;
        for (int k = 0; k < OPT_COUNT && !known; k++)
            known = strlen(LONGOPTS[k].name) == len && strncmp(LONGOPTS[k].name, argv[i] + 2, len) == 0;
        if (!known)
            return usage("unknown option %s", argv[i]);
        if (argv[i][2 + len] == '\0')
            i++; /* "--opt value": skip the value */
    }
    opterr = 0;
    while ((c = getopt_long(argc, argv, "", LONGOPTS, NULL)) != -1) {
        if (c < 0 || c >= OPT_COUNT)
            return usage("unknown option or missing value: %s", argv[optind - 1]);
        if (g_opts.val[c] != NULL)
            return usage("--%s given twice", LONGOPTS[c].name);
        g_opts.val[c] = optarg;
    }
    if (optind != argc)
        return usage("unexpected argument %s", argv[optind]);
    if ((v = g_opts.val[OPT_ROLE]) == NULL || (strcmp(v, "client") != 0 && strcmp(v, "server") != 0))
        return usage("--role must be client or server", NULL);
    g_opts.server = strcmp(v, "server") == 0;
    allowed = g_opts.server ? SERVER_OPT : CLIENT_OPT;
    for (int i = 0; i < OPT_COUNT; i++) {
        if (allowed[i] && g_opts.val[i] == NULL)
            return usage("--%s is required", LONGOPTS[i].name);
        if (!allowed[i] && g_opts.val[i] != NULL)
            return usage("--%s is not an option of this role", LONGOPTS[i].name);
    }

    /* No variants file: BoringSSL offers one client and one server code path. */
    if (strcmp(g_opts.val[OPT_VARIANT], "default") != 0)
        return usage("--variant=%s is not a variant of this role", g_opts.val[OPT_VARIANT]);
    if (*g_opts.val[OPT_HOST] == '\0')
        return usage("--host must not be empty", NULL);
    errno = 0;
    port = strtol(g_opts.val[OPT_PORT], &end, 10);
    if (errno != 0 || *g_opts.val[OPT_PORT] == '\0' || *end != '\0' || port < !g_opts.server
        || port > 65535)
        return usage("malformed --port=%s", g_opts.val[OPT_PORT]);
    if (!valid_groups(g_opts.val[OPT_GROUPS]))
        return usage("malformed --groups=%s", g_opts.val[OPT_GROUPS]);
    if (strcmp(g_opts.val[OPT_MTU], "default") != 0) {
        errno = 0;
        g_opts.mtu = strtol(g_opts.val[OPT_MTU], &end, 10);
        if (errno != 0 || *g_opts.val[OPT_MTU] == '\0' || *end != '\0'
            || g_opts.mtu <= IP_UDP_OVERHEAD || g_opts.mtu > 65535)
            return usage("--mtu=%s must be default or an integer from 49 to 65535",
                g_opts.val[OPT_MTU]);
        g_opts.payload = g_opts.mtu - IP_UDP_OVERHEAD;
    }
    for (int i = OPT_CA; i < OPT_COUNT; i++) {
        if (g_opts.val[i] != NULL && *g_opts.val[i] == '\0')
            return usage("--%s must not be empty", LONGOPTS[i].name);
    }
    v = g_opts.val[OPT_TRANSPORT];
    if (strcmp(v, "dtls") != 0 && strcmp(v, "tls") != 0)
        return usage("--transport must be dtls or tls", NULL);
    g_opts.tls = strcmp(v, "tls") == 0;
    v = g_opts.val[OPT_RESUME];
    if (strcmp(v, "off") != 0 && strcmp(v, "ticket") != 0)
        return usage("--resume must be off or ticket", NULL);
    g_opts.resume = strcmp(v, "ticket") == 0;
    if (g_opts.tls && g_opts.payload != 0)
        return usage("--mtu=%s: only default is valid with --transport=tls", g_opts.val[OPT_MTU]);
    if (g_opts.server) {
        v = g_opts.val[OPT_VALIDATE];
        if (strcmp(v, "off") != 0 && strcmp(v, "cookie") != 0)
            return usage("--validate must be off or cookie", NULL);
        g_opts.cookie = strcmp(v, "cookie") == 0;
    } else {
        v = g_opts.val[OPT_KEY_SHARE];
        if (strcmp(v, "empty") != 0 && strcmp(v, "default") != 0
            && !in_list(v, g_opts.val[OPT_GROUPS]))
            return usage("--key-share=%s is not in --groups", v);
    }
    return EXIT_OK;
}

int main(int argc, char **argv)
{
    SSL_CTX *ctx;
    int rc;

    if ((rc = parse_options(argc, argv)) != EXIT_OK)
        return rc;
    g_conn = g_opts.resume ? 1 : 0;
    fprintf(stderr, "BoringSSL %s (API %d), role=%s variant=%s transport=%s resume=%s groups=%s "
        "mtu=%s key-share=%s validate=%s\n", BSSL_COMMIT, BORINGSSL_API_VERSION,
        g_opts.val[OPT_ROLE], g_opts.val[OPT_VARIANT], g_opts.val[OPT_TRANSPORT],
        g_opts.val[OPT_RESUME], g_opts.val[OPT_GROUPS], g_opts.val[OPT_MTU],
        g_opts.server ? "-" : g_opts.val[OPT_KEY_SHARE],
        g_opts.server ? g_opts.val[OPT_VALIDATE] : "-");
    if (g_opts.payload != 0 && g_opts.payload < BSSL_MIN_PAYLOAD)
        return fail_msg(EXIT_UNSUPPORTED, NULL, "--mtu=%ld rejected by SSL_set_mtu(%ld)",
            g_opts.mtu, g_opts.payload);

    {
        uint16_t version = g_opts.tls ? TLS1_3_VERSION : DTLS1_3_VERSION;

        ctx = SSL_CTX_new(g_opts.tls ? TLS_method() : DTLS_method());
        if (ctx == NULL || !SSL_CTX_set_min_proto_version(ctx, version)
            || !SSL_CTX_set_max_proto_version(ctx, version))
            return fail_ssl(NULL, 0, "creating the 1.3 context");
    }
    SSL_CTX_set_msg_callback(ctx, msg_cb);
    if ((rc = configure_groups(ctx)) != EXIT_OK)
        return rc;
    /* Only the client verifies; the server takes --ca because the contract gives it to both. */
    if (!g_opts.server) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        if (!SSL_CTX_load_verify_locations(ctx, g_opts.val[OPT_CA], NULL))
            return fail_ssl(NULL, 0, "loading --ca");
        if (g_opts.resume) {
            SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL);
            SSL_CTX_sess_set_new_cb(ctx, new_session_cb);
        }
    }

    rc = g_opts.server ? run_server(ctx) : run_client(ctx);
    SSL_CTX_free(ctx);
    return rc;
}
