/* wolfSSL adapter for the DTLS 1.3 interop harness (docs/shim-interface.md). */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define EXIT_FAIL 1
#define EXIT_UNSUPPORTED 2
#define EXIT_USAGE 64
/* Safety net only; the runner owns timeouts and the contract forbids any below 60 s. */
#define DEADLINE_SECONDS 60
#define CLOSE_NOTIFY_WAIT_MS 2000
#define SERVER_NAME "localhost"
#define MAX_GROUPS 16
#define GROUPS_BUF 512
/* --mtu is the IP path MTU; IPv6 (40) + UDP (8) headers leave the datagram payload. */
#define IP_UDP_OVERHEAD 48
/* TLS 1.3 record payloads are at most 2^14 + 256 bytes (RFC 9846 sec 5.2). */
#define TLS_RECORD_HEADER 5
#define TLS_MAX_RECORD (16384 + 256)
#define TLS_HS_HEADER 4
#define EXT_COOKIE 44
#define EXT_KEY_SHARE 51
#define SEEN_COOKIE 1u
#define SEEN_KEY_SHARE 2u

struct group {
    const char *iana;
    int id;
    const char *wolf_name; /* what wolfSSL_get_curve_name() returns */
};

/* wolfSSL 5.9.4 has no code point for MLKEM512X25519 (0x11EA); it is rejected as unknown. */
static const struct group GROUPS[] = {
    {"X25519", WOLFSSL_ECC_X25519, "X25519"},
    {"secp256r1", WOLFSSL_ECC_SECP256R1, "SECP256R1"},
    {"secp384r1", WOLFSSL_ECC_SECP384R1, "SECP384R1"},
    {"X25519MLKEM768", WOLFSSL_X25519MLKEM768, "X25519MLKEM768"},
    {"SecP256r1MLKEM768", WOLFSSL_SECP256R1MLKEM768, "SecP256r1MLKEM768"},
    {"SecP384r1MLKEM1024", WOLFSSL_SECP384R1MLKEM1024, "SecP384r1MLKEM1024"},
    {"MLKEM768", WOLFSSL_ML_KEM_768, "ML_KEM_768"},
};

/* "default" plus the entries of implementations/wolfssl/variants, with their roles. */
static const struct variant {
    const char *name, *role; /* role: "client", "server" or "both" */
} VARIANTS[] = {{"default", "both"}, {"accept-tls13", "server"}};

/* RFC 9846 4.2.3: ServerHello.random of a HelloRetryRequest. */
static const unsigned char HRR_RANDOM[32] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
};

/* Per-connection state of the result line; the SIGALRM handler reads it too. */
static volatile sig_atomic_t g_hrr, g_hrr_cookie, g_hrr_group;
/* Client --key-share=GROUP: its code point, and whether wolfSSL tried to send another CH1 share. */
static unsigned g_want_share;
static int g_share_replaced;
/* HRR fields are unknown (null) until the handshake has started, e.g. on usage errors. */
static volatile sig_atomic_t g_handshake_started;
static volatile sig_atomic_t g_resumed = -1; /* -1: unknown (null) */
/* 0 before the first connection; errors after that carry "connection N: " with --resume=ticket. */
static volatile sig_atomic_t g_conn;
static const char *volatile g_version, *volatile g_group;
static int g_is_client, g_tls, g_ticket;

struct options {
    const char *role, *variant, *host, *port, *groups, *transport, *resume, *mtu, *ca;
    const char *key_share, *validate, *cert, *key;
    int mtu_bytes; /* 0: --mtu=default */
};

static const char *json_bool(int b) { return b ? "true" : "false"; }

static void log_msg(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fputs("[wolfssl-adapter] ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

static void print_json_string(const char *s)
{
    if (s == NULL) {
        fputs("null", stdout);
        return;
    }
    putchar('"');
    for (; *s; s++) {
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

static const char *hrr_json(int v) { return g_handshake_started ? json_bool(v) : "null"; }
static const char *resumed_json(void) { return g_resumed < 0 ? "null" : json_bool(g_resumed); }

static const char *conn_prefix(void)
{
    if (!g_ticket || g_conn == 0)
        return "";
    return g_conn == 1 ? "connection 1: " : "connection 2: ";
}

/* Describes the current connection, i.e. the last one attempted. */
static void emit_result(int ok, const char *error)
{
    fputs("{\"event\": \"result\", \"ok\": ", stdout);
    fputs(json_bool(ok), stdout);
    fputs(", \"version\": ", stdout);
    print_json_string(g_version);
    fputs(", \"group\": ", stdout);
    print_json_string(g_group);
    printf(", \"hrr\": %s, \"hrr_cookie\": %s, \"hrr_group\": %s, \"resumed\": %s, \"error\": ",
           hrr_json(g_hrr), hrr_json(g_hrr_cookie), hrr_json(g_hrr_group), resumed_json());
    print_json_string(error);
    fputs("}\n", stdout);
    fflush(stdout);
}

_Noreturn static void vfail(int code, const char *prefix, const char *fmt, va_list ap)
{
    char msg[320];
    size_t n = (size_t)snprintf(msg, sizeof(msg), "%s%s", conn_prefix(), prefix);
    vsnprintf(msg + n, sizeof(msg) - n, fmt, ap);
    log_msg("%s", msg);
    emit_result(0, msg);
    exit(code);
}

_Noreturn static void fail(int code, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfail(code, "", fmt, ap);
    va_end(ap);
}

_Noreturn static void usage_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfail(EXIT_USAGE, "usage: ", fmt, ap);
    va_end(ap);
}

static void write_str(const char *s)
{
    ssize_t r = write(STDOUT_FILENO, s, strlen(s));
    (void)r;
}

/* The strings are library or table constants without characters that need JSON escaping. */
static void write_json_name(const char *s)
{
    if (s == NULL) {
        write_str("null");
        return;
    }
    write_str("\"");
    write_str(s);
    write_str("\"");
}

static void on_deadline(int sig)
{
    (void)sig;
    /* Async-signal-safe: write(2) of constant strings only. */
    write_str("{\"event\": \"result\", \"ok\": false, \"version\": ");
    write_json_name(g_version);
    write_str(", \"group\": ");
    write_json_name(g_group);
    write_str(", \"hrr\": ");
    write_str(hrr_json(g_hrr));
    write_str(", \"hrr_cookie\": ");
    write_str(hrr_json(g_hrr_cookie));
    write_str(", \"hrr_group\": ");
    write_str(hrr_json(g_hrr_group));
    write_str(", \"resumed\": ");
    write_str(resumed_json());
    write_str(", \"error\": \"");
    write_str(conn_prefix());
    write_str("timeout\"}\n");
    _exit(EXIT_FAIL);
}

static unsigned get16(const unsigned char *p) { return (unsigned)p[0] << 8 | p[1]; }
static unsigned get24(const unsigned char *p) { return (unsigned)p[0] << 16 | p[1] << 8 | p[2]; }

/* Log extension types/lengths of a (first fragment of a) ClientHello or ServerHello/HRR and the
 * key_share groups; returns which of cookie/key_share were seen (SEEN_* bits). */
static unsigned log_hello_exts(const unsigned char *p, unsigned n, unsigned msg_type)
{
    unsigned i = 34, end, seen = 0;
    if (i + 1 > n)
        return 0;
    i += 1 + p[i]; /* legacy_session_id */
    if (msg_type == 1) {
        if (!g_tls) {
            if (i + 1 > n)
                return 0;
            i += 1 + p[i]; /* DTLS legacy_cookie */
        }
        if (i + 2 > n)
            return 0;
        i += 2 + get16(p + i); /* cipher_suites */
        if (i + 1 > n)
            return 0;
        i += 1 + p[i]; /* legacy_compression_methods */
    }
    else {
        i += 3; /* cipher_suite, legacy_compression_method */
    }
    if (i + 2 > n)
        return 0;
    end = i + 2 + get16(p + i);
    fputs(" exts=", stderr);
    for (i += 2; i + 4 <= n && i + 4 <= end; i += 4 + get16(p + i + 2)) {
        unsigned type = get16(p + i), len = get16(p + i + 2), j;
        fprintf(stderr, "%u:%u", type, len);
        if (type == EXT_COOKIE)
            seen |= SEEN_COOKIE;
        if (type == EXT_KEY_SHARE)
            seen |= SEEN_KEY_SHARE;
        if (type == EXT_KEY_SHARE && msg_type == 1 && i + 6 <= n) {
            fputs("(", stderr);
            for (j = i + 6; j + 4 <= n && j + 4 <= i + 4 + len; j += 4 + get16(p + j + 2))
                fprintf(stderr, "%s0x%04x", j == i + 6 ? "" : ",", get16(p + j));
            fputs(")", stderr);
        }
        else if (type == EXT_KEY_SHARE && msg_type == 2 && len >= 2 && i + 6 <= n) {
            fprintf(stderr, "(0x%04x)", get16(p + i + 4));
        }
        fputs(",", stderr);
    }
    if (n < end)
        fputs("...", stderr);
    return seen;
}

static void record_hrr(unsigned seen)
{
    g_hrr = 1;
    g_hrr_cookie = (seen & SEEN_COOKIE) != 0;
    g_hrr_group = (seen & SEEN_KEY_SHARE) != 0;
}

/* Log the plaintext records of one datagram and record a HelloRetryRequest and its reasons. */
static void inspect_datagram(const char *dir, const unsigned char *b, int n, int count_hrr)
{
    int off = 0;
    fprintf(stderr, "[wolfssl-adapter] %s %dB", dir, n);
    while (off + 13 <= n) {
        unsigned type = b[off];
        unsigned len = (unsigned)b[off + 11] << 8 | b[off + 12];
        unsigned body = (unsigned)off + 13, h;
        if ((type & 0xE0) == 0x20) {
            fputs(" | ciphertext", stderr);
            break;
        }
        if (body + len > (unsigned)n)
            break;
        fprintf(stderr, " | rec=%u epoch=%u", type, (unsigned)b[off + 3] << 8 | b[off + 4]);
        for (h = body; type == 22 && h + 12 <= body + len;) {
            unsigned msg_len = get24(b + h + 1), frag_off = get24(b + h + 6);
            unsigned frag_len = get24(b + h + 9), seen = 0;
            int is_hrr = b[h] == 2 && frag_off == 0 && frag_len >= 34 &&
                         h + 12 + 34 <= body + len && memcmp(b + h + 14, HRR_RANDOM, 32) == 0;
            fprintf(stderr, " hs=%u%s seq=%u frag=%u+%u/%u", b[h], is_hrr ? "(HRR)" : "",
                    (unsigned)b[h + 4] << 8 | b[h + 5], frag_off, frag_len, msg_len);
            if ((b[h] == 1 || b[h] == 2) && frag_off == 0) {
                unsigned avail = body + len - (h + 12);
                seen = log_hello_exts(b + h + 12, frag_len < avail ? frag_len : avail, b[h]);
            }
            if (is_hrr && count_hrr)
                record_hrr(seen);
            h += 12 + frag_len;
        }
        off = (int)(body + len);
    }
    fputc('\n', stderr);
}

/* Offset of an extension's data in a (first fragment of a) ClientHello body, or 0 if absent. */
static unsigned client_hello_ext(const unsigned char *p, unsigned n, unsigned type, unsigned *len)
{
    unsigned i = 34, end;
    if (i + 1 > n)
        return 0;
    i += 1 + p[i]; /* legacy_session_id */
    if (i + 1 > n)
        return 0;
    i += 1 + p[i]; /* legacy_cookie */
    if (i + 2 > n)
        return 0;
    i += 2 + get16(p + i); /* cipher_suites */
    if (i + 1 > n)
        return 0;
    i += 1 + p[i]; /* legacy_compression_methods */
    if (i + 2 > n)
        return 0;
    end = i + 2 + get16(p + i);
    for (i += 2; i + 4 <= n && i + 4 <= end; i += 4 + get16(p + i + 2)) {
        if (get16(p + i) == type) {
            *len = get16(p + i + 2);
            return i + 4;
        }
    }
    return 0;
}

/* Whether a datagram carries a CH1 whose key_share is not exactly the requested one. */
static int ch1_has_other_share(const unsigned char *b, int n)
{
    int off = 0;
    while (off + 13 <= n && (b[off] & 0xE0) != 0x20) {
        unsigned len = get16(b + off + 11), body = (unsigned)off + 13, h;
        if (body + len > (unsigned)n)
            break;
        for (h = body; b[off] == 22 && h + 12 <= body + len; h += 12 + get24(b + h + 9)) {
            const unsigned char *p = b + h + 12;
            unsigned avail = body + len - (h + 12), frag_len = get24(b + h + 9), ext, ext_len = 0;
            if (b[h] != 1 || get16(b + h + 4) != 0 || get24(b + h + 6) != 0)
                continue;
            ext = client_hello_ext(p, frag_len < avail ? frag_len : avail, EXT_KEY_SHARE, &ext_len);
            /* One entry: 2-byte list length, group, 2-byte key length, key. */
            return ext == 0 || ext_len < 6 || get16(p + ext) != ext_len - 2 ||
                   get16(p + ext + 2) != g_want_share || get16(p + ext + 4) != ext_len - 6;
        }
        off = (int)(body + len);
    }
    return 0;
}

/* TCP splits and coalesces records, so each direction reassembles records and handshake
 * messages until the first encrypted record. */
struct stream {
    const char *dir;
    unsigned char rec[TLS_RECORD_HEADER + TLS_MAX_RECORD];
    size_t rec_len;
    unsigned char hs[1 << 16];
    size_t hs_len;
    int done;
};

static struct stream g_rx = {.dir = "rx"}, g_tx = {.dir = "tx"};

static void stream_reset(struct stream *s)
{
    s->rec_len = s->hs_len = 0;
    s->done = 0;
}

static void inspect_hs_messages(struct stream *s, int count_hrr)
{
    size_t off = 0;
    while (s->hs_len - off >= TLS_HS_HEADER) {
        const unsigned char *m = s->hs + off;
        unsigned len = get24(m + 1), seen = 0;
        int is_hrr;
        if (s->hs_len - off < TLS_HS_HEADER + len)
            break;
        is_hrr = m[0] == 2 && len >= 34 && memcmp(m + TLS_HS_HEADER + 2, HRR_RANDOM, 32) == 0;
        fprintf(stderr, " hs=%u%s len=%u", m[0], is_hrr ? "(HRR)" : "", len);
        if (m[0] == 1 || m[0] == 2)
            seen = log_hello_exts(m + TLS_HS_HEADER, len, m[0]);
        if (is_hrr && count_hrr)
            record_hrr(seen);
        off += TLS_HS_HEADER + len;
    }
    memmove(s->hs, s->hs + off, s->hs_len - off);
    s->hs_len -= off;
}

static void inspect_record(struct stream *s, int count_hrr)
{
    unsigned type = s->rec[0], len = get16(s->rec + 3);
    fprintf(stderr, "[wolfssl-adapter] %s record %uB type=%u", s->dir, TLS_RECORD_HEADER + len, type);
    if (type == 23) {
        fputs(" | ciphertext", stderr);
        s->done = 1;
    }
    else if (type == 22) {
        if (s->hs_len + len > sizeof(s->hs)) {
            fputs(" | handshake message too large to inspect", stderr);
            s->done = 1;
        }
        else {
            memcpy(s->hs + s->hs_len, s->rec + TLS_RECORD_HEADER, len);
            s->hs_len += len;
            inspect_hs_messages(s, count_hrr);
        }
    }
    fputc('\n', stderr);
}

static void inspect_stream(struct stream *s, const unsigned char *p, size_t n, int count_hrr)
{
    while (n > 0 && !s->done) {
        size_t want = s->rec_len < TLS_RECORD_HEADER
                          ? TLS_RECORD_HEADER - s->rec_len
                          : TLS_RECORD_HEADER + get16(s->rec + 3) - s->rec_len;
        size_t take = want < n ? want : n;
        memcpy(s->rec + s->rec_len, p, take);
        s->rec_len += take;
        p += take;
        n -= take;
        if (s->rec_len < TLS_RECORD_HEADER)
            continue;
        if (get16(s->rec + 3) > TLS_MAX_RECORD) {
            log_msg("%s: record length %u is not TLS, stopping inspection", s->dir,
                    get16(s->rec + 3));
            s->done = 1;
        }
        else if (s->rec_len == TLS_RECORD_HEADER + get16(s->rec + 3)) {
            inspect_record(s, count_hrr);
            s->rec_len = 0;
        }
    }
}

static int dtls_recv_cb(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    int r = EmbedReceiveFrom(ssl, buf, sz, ctx);
    if (r > 0)
        inspect_datagram("rx", (const unsigned char *)buf, r, g_is_client);
    return r;
}

static int dtls_send_cb(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    int r;
    /* WOLFSSL_DTLS_CH_FRAG empties a CH1 key_share that does not fit the MTU (src/tls13.c). */
    if (g_want_share != 0 && ch1_has_other_share((const unsigned char *)buf, sz)) {
        g_share_replaced = 1;
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    r = EmbedSendTo(ssl, buf, sz, ctx);
    if (r > 0)
        inspect_datagram("tx", (const unsigned char *)buf, r, !g_is_client);
    return r;
}

static int tls_recv_cb(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    int r = EmbedReceive(ssl, buf, sz, ctx);
    if (r > 0)
        inspect_stream(&g_rx, (const unsigned char *)buf, (size_t)r, g_is_client);
    return r;
}

static int tls_send_cb(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    int r = EmbedSend(ssl, buf, sz, ctx);
    if (r > 0)
        inspect_stream(&g_tx, (const unsigned char *)buf, (size_t)r, !g_is_client);
    return r;
}

static const struct group *find_group_by_iana(const char *name)
{
    size_t i;
    for (i = 0; i < sizeof(GROUPS) / sizeof(GROUPS[0]); i++)
        if (strcmp(GROUPS[i].iana, name) == 0)
            return &GROUPS[i];
    return NULL;
}

static const char *negotiated_group(WOLFSSL *ssl)
{
    const char *wolf = wolfSSL_get_curve_name(ssl);
    size_t i;
    if (wolf == NULL)
        return NULL;
    for (i = 0; i < sizeof(GROUPS) / sizeof(GROUPS[0]); i++)
        if (strcmp(GROUPS[i].wolf_name, wolf) == 0)
            return GROUPS[i].iana;
    log_msg("no IANA name for wolfSSL group '%s'", wolf);
    return NULL;
}

static const char *error_string(WOLFSSL *ssl, int ret, char *buf, size_t len)
{
    int err = wolfSSL_get_error(ssl, ret);
    char reason[WOLFSSL_MAX_ERROR_SZ];
    wolfSSL_ERR_error_string_n((unsigned long)err, reason, sizeof(reason));
    snprintf(buf, len, "%d: %s", err, reason);
    return buf;
}

static long parse_long(const char *s, const char *name, long lo, long hi)
{
    char *end;
    long v;
    errno = 0;
    v = strtol(s, &end, 10);
    if (*s == '\0' || *end != '\0' || errno != 0 || v < lo || v > hi)
        usage_error("--%s=%s is not an integer in %ld..%ld", name, s, lo, hi);
    return v;
}

/* Whether a comma-separated list contains name; malformed lists are a usage error. */
static int list_contains(const char *list, const char *name)
{
    size_t n = strlen(name);
    const char *p = list;
    int found = 0;
    for (;;) {
        const char *comma = strchr(p, ',');
        size_t len = comma ? (size_t)(comma - p) : strlen(p);
        if (len == 0)
            usage_error("--groups=%s has an empty entry", list);
        if (len == n && strncmp(p, name, n) == 0)
            found = 1;
        if (comma == NULL)
            return found;
        p = comma + 1;
    }
}

static void require(const char *value, const char *name)
{
    if (value == NULL)
        usage_error("--%s is required", name);
}

static void forbid(const char *value, const char *name, const char *role)
{
    if (value != NULL)
        usage_error("--%s is not a %s option", name, role);
}

static void parse_args(int argc, char **argv, struct options *o)
{
    static const char *const names[] = {"role", "variant", "host", "port", "groups", "transport",
                                        "resume", "mtu",
                                        "ca", "key-share", "validate", "cert", "key"};
    const char **slots[] = {&o->role, &o->variant, &o->host, &o->port, &o->groups,
                            &o->transport, &o->resume, &o->mtu,
                            &o->ca, &o->key_share, &o->validate, &o->cert, &o->key};
    size_t i, c, n_groups;
    int a, known = 0;

    memset(o, 0, sizeof(*o));
    /* Exact names only: getopt_long would also accept abbreviations such as --group. */
    for (a = 1; a < argc; a++) {
        const char *arg = argv[a], *eq = strchr(arg, '=');
        size_t len;
        if (strncmp(arg, "--", 2) != 0)
            usage_error("unexpected argument: %s", arg);
        len = (eq != NULL ? (size_t)(eq - arg) : strlen(arg)) - 2;
        for (c = 0; c < sizeof(names) / sizeof(names[0]); c++)
            if (strlen(names[c]) == len && strncmp(arg + 2, names[c], len) == 0)
                break;
        if (c == sizeof(names) / sizeof(names[0]))
            usage_error("unknown option: %s", arg);
        if (eq == NULL && a + 1 == argc)
            usage_error("missing value for %s", arg);
        if (*slots[c] != NULL)
            usage_error("--%s given twice", names[c]);
        *slots[c] = eq != NULL ? eq + 1 : argv[++a];
        if (**slots[c] == '\0')
            usage_error("--%s must not be empty", names[c]);
    }

    require(o->role, "role");
    if (strcmp(o->role, "client") != 0 && strcmp(o->role, "server") != 0)
        usage_error("--role=%s is not client|server", o->role);
    g_is_client = strcmp(o->role, "client") == 0;
    require(o->variant, "variant");
    require(o->host, "host");
    require(o->port, "port");
    require(o->groups, "groups");
    require(o->transport, "transport");
    require(o->resume, "resume");
    require(o->mtu, "mtu");
    require(o->ca, "ca");
    if (g_is_client) {
        require(o->key_share, "key-share");
        forbid(o->validate, "validate", "client");
        forbid(o->cert, "cert", "client");
        forbid(o->key, "key", "client");
    }
    else {
        require(o->validate, "validate");
        require(o->cert, "cert");
        require(o->key, "key");
        forbid(o->key_share, "key-share", "server");
    }

    for (i = 0; i < sizeof(VARIANTS) / sizeof(VARIANTS[0]); i++)
        known |= strcmp(o->variant, VARIANTS[i].name) == 0 &&
                 (strcmp(VARIANTS[i].role, "both") == 0 || strcmp(VARIANTS[i].role, o->role) == 0);
    if (!known)
        usage_error("--variant=%s is not a %s variant of this adapter", o->variant, o->role);
    parse_long(o->port, "port", g_is_client ? 1 : 0, 65535);
    if (strcmp(o->transport, "dtls") != 0 && strcmp(o->transport, "tls") != 0)
        usage_error("--transport=%s is not dtls|tls", o->transport);
    g_tls = strcmp(o->transport, "tls") == 0;
    if (strcmp(o->resume, "off") != 0 && strcmp(o->resume, "ticket") != 0)
        usage_error("--resume=%s is not off|ticket", o->resume);
    g_ticket = strcmp(o->resume, "ticket") == 0;
    if (strcmp(o->mtu, "default") != 0) {
        if (g_tls)
            usage_error("--mtu=%s with --transport=tls: only \"default\" is valid", o->mtu);
        o->mtu_bytes = (int)parse_long(o->mtu, "mtu", IP_UDP_OVERHEAD + 1, 65535);
    }
    list_contains(o->groups, ""); /* rejects empty entries */
    if (strlen(o->groups) >= GROUPS_BUF)
        usage_error("--groups too long");
    for (i = 0, n_groups = 1; o->groups[i] != '\0'; i++)
        n_groups += o->groups[i] == ',';
    if (n_groups > MAX_GROUPS)
        usage_error("too many groups");
    if (o->key_share != NULL && strcmp(o->key_share, "empty") != 0 &&
        strcmp(o->key_share, "default") != 0 && !list_contains(o->groups, o->key_share))
        usage_error("--key-share=%s is not in --groups", o->key_share);
    if (o->validate != NULL && strcmp(o->validate, "off") != 0 &&
        strcmp(o->validate, "cookie") != 0)
        usage_error("--validate=%s is not off|cookie", o->validate);
}

static void apply_groups(WOLFSSL *ssl, const char *list)
{
    int ids[MAX_GROUPS], n = 0;
    char buf[GROUPS_BUF], *tok, *save = NULL;

    /* parse_args has checked the length and the number of entries. */
    strcpy(buf, list);
    for (tok = strtok_r(buf, ",", &save); tok != NULL; tok = strtok_r(NULL, ",", &save)) {
        const struct group *g = find_group_by_iana(tok);
        if (g == NULL)
            fail(EXIT_UNSUPPORTED, "unsupported group: %s", tok);
        /* wolfSSL_set_groups rejects the whole list, so probe each group for a precise error. */
        if (wolfSSL_UseSupportedCurve(ssl, (word16)g->id) != WOLFSSL_SUCCESS)
            fail(EXIT_UNSUPPORTED, "unsupported group in this build: %s", tok);
        ids[n++] = g->id;
    }
    if (wolfSSL_set_groups(ssl, ids, n) != WOLFSSL_SUCCESS)
        fail(EXIT_UNSUPPORTED, "wolfSSL_set_groups rejected: %s", list);
}

static void apply_key_share(WOLFSSL *ssl, const char *key_share)
{
    const struct group *g;
    int ret;
    if (strcmp(key_share, "default") == 0)
        return;
    if (strcmp(key_share, "empty") == 0) {
        if (wolfSSL_NoKeyShares(ssl) != WOLFSSL_SUCCESS)
            fail(EXIT_UNSUPPORTED, "wolfSSL_NoKeyShares failed");
        return;
    }
    g = find_group_by_iana(key_share);
    if (g == NULL)
        fail(EXIT_UNSUPPORTED, "unsupported key share group: %s", key_share);
    ret = wolfSSL_UseKeyShare(ssl, (word16)g->id);
    if (ret != WOLFSSL_SUCCESS)
        fail(EXIT_UNSUPPORTED, "wolfSSL_UseKeyShare(%s) failed: %d", key_share, ret);
    g_want_share = (unsigned)g->id;
}

static int resolve_and_open(const struct options *o, struct sockaddr_storage *addr,
                            socklen_t *addrlen)
{
    struct addrinfo hints, *res;
    int fd, rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = g_tls ? SOCK_STREAM : SOCK_DGRAM;
    hints.ai_flags = g_is_client ? 0 : AI_PASSIVE;
    rc = getaddrinfo(o->host, o->port, &hints, &res);
    if (rc != 0)
        fail(EXIT_FAIL, "getaddrinfo(%s, %s): %s", o->host, o->port, gai_strerror(rc));
    fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0)
        fail(EXIT_FAIL, "socket: %s", strerror(errno));
    memcpy(addr, res->ai_addr, res->ai_addrlen);
    *addrlen = res->ai_addrlen;
    freeaddrinfo(res);
    return fd;
}

/* Server: the UDP socket, or the TCP listening socket, bound once for all connections. */
static int open_server_socket(const struct options *o, int *bound_port)
{
    struct sockaddr_storage addr, local;
    socklen_t addrlen, local_len = sizeof(local);
    int fd = resolve_and_open(o, &addr, &addrlen), one = 1;

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(fd, (struct sockaddr *)&addr, addrlen) != 0)
        fail(EXIT_FAIL, "bind %s:%s: %s", o->host, o->port, strerror(errno));
    if (g_tls && listen(fd, 4) != 0)
        fail(EXIT_FAIL, "listen: %s", strerror(errno));
    if (getsockname(fd, (struct sockaddr *)&local, &local_len) != 0)
        fail(EXIT_FAIL, "getsockname: %s", strerror(errno));
    *bound_port = local.ss_family == AF_INET6 ? ntohs(((struct sockaddr_in6 *)&local)->sin6_port)
                                              : ntohs(((struct sockaddr_in *)&local)->sin_port);
    return fd;
}

/* Client: a new socket per connection, so connection 2 has a new UDP source port. */
static int open_client_socket(const struct options *o, WOLFSSL *ssl)
{
    struct sockaddr_storage addr;
    socklen_t addrlen;
    int fd = resolve_and_open(o, &addr, &addrlen);

    if (g_tls) {
        while (connect(fd, (struct sockaddr *)&addr, addrlen) != 0)
            if (errno != EINTR)
                fail(EXIT_FAIL, "connect %s:%s: %s", o->host, o->port, strerror(errno));
    }
    else if (wolfSSL_dtls_set_peer(ssl, &addr, addrlen) != WOLFSSL_SUCCESS) {
        fail(EXIT_FAIL, "wolfSSL_dtls_set_peer failed");
    }
    return fd;
}

static WOLFSSL_CTX *make_ctx(const struct options *o)
{
    WOLFSSL_METHOD *method;
    WOLFSSL_CTX *ctx;
    if (g_tls)
        method = g_is_client ? wolfTLSv1_3_client_method() : wolfTLSv1_3_server_method();
    else
        method = g_is_client ? wolfDTLSv1_3_client_method() : wolfDTLSv1_3_server_method();
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL)
        fail(EXIT_FAIL, "wolfSSL_CTX_new failed");
    if (g_is_client) {
        if (wolfSSL_CTX_load_verify_locations(ctx, o->ca, NULL) != WOLFSSL_SUCCESS)
            fail(EXIT_FAIL, "cannot load CA %s", o->ca);
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    }
    else {
        /* No client authentication, so the server does not load --ca. */
        if (wolfSSL_CTX_use_certificate_chain_file(ctx, o->cert) != WOLFSSL_SUCCESS)
            fail(EXIT_FAIL, "cannot load certificate %s", o->cert);
        if (wolfSSL_CTX_use_PrivateKey_file(ctx, o->key, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
            fail(EXIT_FAIL, "cannot load key %s", o->key);
    }
    wolfSSL_CTX_SetIORecv(ctx, g_tls ? tls_recv_cb : dtls_recv_cb);
    wolfSSL_CTX_SetIOSend(ctx, g_tls ? tls_send_cb : dtls_send_cb);
    return ctx;
}

static void configure_ssl(WOLFSSL *ssl, const struct options *o)
{
    /* wolfSSL's MTU bounds each datagram it writes (record headers included). */
    if (o->mtu_bytes > 0 &&
        wolfSSL_dtls_set_mtu(ssl, (unsigned short)(o->mtu_bytes - IP_UDP_OVERHEAD)) !=
            WOLFSSL_SUCCESS)
        fail(EXIT_UNSUPPORTED, "unsupported: --mtu=%d", o->mtu_bytes);
    apply_groups(ssl, o->groups);
    if (g_is_client) {
        apply_key_share(ssl, o->key_share);
        if (wolfSSL_check_domain_name(ssl, SERVER_NAME) != WOLFSSL_SUCCESS)
            fail(EXIT_FAIL, "wolfSSL_check_domain_name failed");
    }
    else if (strcmp(o->validate, "off") == 0) {
        if (wolfSSL_disable_hrr_cookie(ssl) != WOLFSSL_SUCCESS)
            fail(EXIT_FAIL, "wolfSSL_disable_hrr_cookie failed");
    }
    else if (wolfSSL_send_hrr_cookie(ssl, NULL, 0) != WOLFSSL_SUCCESS) {
        fail(EXIT_FAIL, "wolfSSL_send_hrr_cookie failed");
    }
}

_Noreturn static void finish_fail(WOLFSSL *ssl, int ret, const char *what)
{
    char err[256];
    fail(EXIT_FAIL, "%s: %s", what, error_string(ssl, ret, err, sizeof(err)));
}

static int handshake(WOLFSSL *ssl, int accept_tls13)
{
    g_handshake_started = 1;
    for (;;) {
        int ret = g_is_client     ? wolfSSL_connect(ssl)
                  : accept_tls13 ? wolfSSL_accept_TLSv13(ssl)
                                 : wolfSSL_accept(ssl);
        int err;
        if (ret == WOLFSSL_SUCCESS)
            return ret;
        err = wolfSSL_get_error(ssl, ret);
        if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE)
            return ret;
    }
}

static long long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Returns 1 once fd is readable, 0 when the deadline passes first. */
static int wait_readable(int fd, long long deadline)
{
    for (;;) {
        struct pollfd p = {.fd = fd, .events = POLLIN};
        long long left = deadline - now_ms();
        int r;
        if (left <= 0)
            return 0;
        r = poll(&p, 1, (int)left);
        if (r != 0 && !(r < 0 && errno == EINTR))
            return r > 0;
    }
}

static void set_blocking(int fd, int blocking)
{
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 ||
        fcntl(fd, F_SETFL, blocking ? flags & ~O_NONBLOCK : flags | O_NONBLOCK) < 0)
        log_msg("fcntl: %s", strerror(errno));
}

/* Teardown is bounded by poll(), so wolfSSL must not block in recv. */
static void set_nonblocking(WOLFSSL *ssl, int fd)
{
    set_blocking(fd, 0);
    if (!g_tls)
        wolfSSL_dtls_set_using_nonblock(ssl, 1);
}

/* Client, after pong: send close_notify, then wait up to 2 s for the server's. */
static void client_teardown(WOLFSSL *ssl, int fd)
{
    long long deadline = now_ms() + CLOSE_NOTIFY_WAIT_MS;
    int ret;
    set_nonblocking(ssl, fd);
    for (ret = wolfSSL_shutdown(ssl); ret != WOLFSSL_SUCCESS; ret = wolfSSL_shutdown(ssl)) {
        int err = wolfSSL_get_error(ssl, ret);
        if (ret != WOLFSSL_SHUTDOWN_NOT_DONE && err != WOLFSSL_ERROR_WANT_READ &&
            err != WOLFSSL_ERROR_WANT_WRITE) {
            log_msg("teardown: wolfSSL_shutdown error %d", err);
            return;
        }
        if (!wait_readable(fd, deadline)) {
            log_msg("teardown: no close_notify from the server within 2 s");
            return;
        }
    }
    log_msg("teardown: received the server's close_notify");
}

/* Server, after pong: wait up to 2 s for the client's close_notify, then send its own. */
static void server_teardown(WOLFSSL *ssl, int fd)
{
    long long deadline = now_ms() + CLOSE_NOTIFY_WAIT_MS;
    char buf[64];
    int ret;
    set_nonblocking(ssl, fd);
    for (;;) {
        int err;
        ret = wolfSSL_read(ssl, buf, sizeof(buf));
        if (ret > 0) {
            log_msg("teardown: ignoring %d bytes of application data", ret);
            continue;
        }
        err = wolfSSL_get_error(ssl, ret);
        if (err == WOLFSSL_ERROR_ZERO_RETURN) {
            log_msg("teardown: received the client's close_notify");
            break;
        }
        if (err != WOLFSSL_ERROR_WANT_READ) {
            log_msg("teardown: read error %d", err);
            break;
        }
        if (!wait_readable(fd, deadline)) {
            log_msg("teardown: no close_notify from the client within 2 s");
            break;
        }
    }
    ret = wolfSSL_shutdown(ssl);
    if (ret != WOLFSSL_SUCCESS && ret != WOLFSSL_SHUTDOWN_NOT_DONE)
        log_msg("teardown: wolfSSL_shutdown error %d", wolfSSL_get_error(ssl, ret));
}

static int same_addr(const struct sockaddr_storage *a, const struct sockaddr_storage *b)
{
    if (a->ss_family != b->ss_family)
        return 0;
    if (a->ss_family == AF_INET6) {
        const struct sockaddr_in6 *x = (const void *)a, *y = (const void *)b;
        return x->sin6_port == y->sin6_port && memcmp(&x->sin6_addr, &y->sin6_addr, 16) == 0;
    }
    const struct sockaddr_in *x = (const void *)a, *y = (const void *)b;
    return x->sin_port == y->sin_port && x->sin_addr.s_addr == y->sin_addr.s_addr;
}

/* DTLS server before connection 2: a late datagram of connection 1 (e.g. an ACK) must not
 * become the new WOLFSSL's peer. */
static void drop_stale_datagrams(int fd, const struct sockaddr_storage *old_peer)
{
    for (;;) {
        struct pollfd p = {.fd = fd, .events = POLLIN};
        struct sockaddr_storage from;
        socklen_t from_len = sizeof(from);
        char b[1];
        ssize_t r;
        if (poll(&p, 1, 0) <= 0)
            return;
        r = recvfrom(fd, b, sizeof(b), MSG_PEEK, (struct sockaddr *)&from, &from_len);
        if (r < 0 || !same_addr(&from, old_peer))
            return;
        recv(fd, b, sizeof(b), 0);
        log_msg("dropped a late datagram from the connection 1 peer");
    }
}

struct session_state {
    WOLFSSL_SESSION *ticket;           /* client: received on connection 1 */
    struct sockaddr_storage peer;      /* DTLS server: connection 1 peer */
    int have_peer;
};

/* Runs one full connection lifecycle; any failure exits with the result line. */
static void run_connection(WOLFSSL_CTX *ctx, const struct options *o, int server_fd,
                           int accept_tls13, struct session_state *st)
{
    WOLFSSL *ssl;
    char buf[64];
    int fd, ret, have_ticket = 0;

    g_hrr = g_hrr_cookie = g_hrr_group = 0;
    g_handshake_started = 0;
    g_resumed = -1;
    g_version = g_group = NULL;
    stream_reset(&g_rx);
    stream_reset(&g_tx);
    alarm(DEADLINE_SECONDS);

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL)
        fail(EXIT_FAIL, "wolfSSL_new failed");
    configure_ssl(ssl, o);
    if (g_is_client) {
        if (st->ticket != NULL && wolfSSL_set_session(ssl, st->ticket) != WOLFSSL_SUCCESS)
            fail(EXIT_FAIL, "wolfSSL_set_session rejected the connection 1 session");
        fd = open_client_socket(o, ssl);
    }
    else if (g_tls) {
        while ((fd = accept(server_fd, NULL, NULL)) < 0)
            if (errno != EINTR)
                fail(EXIT_FAIL, "accept: %s", strerror(errno));
    }
    else {
        fd = server_fd;
        set_blocking(fd, 1); /* connection 1 teardown left it non-blocking */
        if (st->have_peer)
            drop_stale_datagrams(fd, &st->peer);
    }
    if (wolfSSL_set_fd(ssl, fd) != WOLFSSL_SUCCESS)
        fail(EXIT_FAIL, "wolfSSL_set_fd failed");

    ret = handshake(ssl, accept_tls13);
    if (ret != WOLFSSL_SUCCESS && g_share_replaced) {
        g_handshake_started = 0; /* nothing was sent */
        fail(EXIT_UNSUPPORTED,
             "unsupported: CH1 with the --key-share=%s share exceeds the MTU, and wolfSSL "
             "sends an empty key_share instead of fragmenting CH1",
             o->key_share);
    }
    if (ret != WOLFSSL_SUCCESS)
        finish_fail(ssl, ret, "handshake");
    g_version = wolfSSL_get_version(ssl);
    g_group = negotiated_group(ssl);
    g_resumed = wolfSSL_session_reused(ssl) != 0;
    log_msg("connection %d: handshake done: %s, group %s, resumed %s", (int)g_conn, g_version,
            g_group ? g_group : "?", json_bool(g_resumed));

    if (g_is_client && (ret = wolfSSL_write(ssl, "ping", 4)) != 4)
        finish_fail(ssl, ret, "write");
    ret = wolfSSL_read(ssl, buf, sizeof(buf));
    if (ret <= 0)
        finish_fail(ssl, ret, "read");
    if (ret != 4 || memcmp(buf, g_is_client ? "pong" : "ping", 4) != 0)
        fail(EXIT_FAIL, "unexpected application data (%d bytes)", ret);
    if (!g_is_client && (ret = wolfSSL_write(ssl, "pong", 4)) != 4)
        finish_fail(ssl, ret, "write");
    alarm(0);
    /* The contract judges the ticket at the time pong has been read. */
    if (g_is_client && g_ticket && st->ticket == NULL) {
        /* wolfSSL_SESSION_has_ticket() needs OPENSSL_EXTRA; this is the length-only query. */
        word32 ticket_len = 0;
        wolfSSL_get_SessionTicket(ssl, NULL, &ticket_len);
        have_ticket = ticket_len > 0;
        st->ticket = wolfSSL_get1_session(ssl);
        log_msg("connection 1: session ticket of %u bytes", (unsigned)ticket_len);
    }

    /* The verdict is final here; teardown problems are only logged. */
    if (g_is_client)
        client_teardown(ssl, fd);
    else
        server_teardown(ssl, fd);
    if (!g_tls && !g_is_client) {
        unsigned int peer_len = sizeof(st->peer);
        st->have_peer = wolfSSL_dtls_get_peer(ssl, &st->peer, &peer_len) == WOLFSSL_SUCCESS;
    }
    wolfSSL_free(ssl);
    if (g_is_client || g_tls)
        close(fd);
    if (g_is_client && g_ticket && g_conn == 1 && !have_ticket)
        fail(EXIT_FAIL, "no session ticket received");
}

int main(int argc, char **argv)
{
    struct options o;
    struct session_state st;
    WOLFSSL_CTX *ctx;
    WOLFSSL *probe;
    struct sigaction sa;
    int server_fd = -1, port = 0, accept_tls13, connections;

    setvbuf(stdout, NULL, _IOLBF, 0);
    parse_args(argc, argv, &o);
    g_conn = 1;
    accept_tls13 = strcmp(o.variant, "accept-tls13") == 0;
    if (accept_tls13 && g_tls)
        fail(EXIT_UNSUPPORTED, "unsupported: variant accept-tls13 is DTLS-only");

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_deadline;
    sigaction(SIGALRM, &sa, NULL);

    /* Adds wolfSSL's own debug log to stderr; it does not change behaviour. */
    if (getenv("DTLS_INTEROP_WOLFSSL_DEBUG") != NULL)
        wolfSSL_Debugging_ON();
    if (wolfSSL_Init() != WOLFSSL_SUCCESS)
        fail(EXIT_FAIL, "wolfSSL_Init failed");
    log_msg("wolfSSL %s, role %s, variant %s, transport %s, resume %s", LIBWOLFSSL_VERSION_STRING,
            o.role, o.variant, o.transport, o.resume);

    memset(&st, 0, sizeof(st));
    ctx = make_ctx(&o);
    /* Reject an unsupported configuration (exit 2) before binding or connecting. */
    probe = wolfSSL_new(ctx);
    if (probe == NULL)
        fail(EXIT_FAIL, "wolfSSL_new failed");
    configure_ssl(probe, &o);
    wolfSSL_free(probe);
    if (!g_is_client) {
        server_fd = open_server_socket(&o, &port);
        printf("{\"event\": \"ready\", \"port\": %d}\n", port);
    }
    connections = g_ticket ? 2 : 1;
    for (g_conn = 1; g_conn <= connections; g_conn++)
        run_connection(ctx, &o, server_fd, accept_tls13, &st);
    g_conn = connections;
    emit_result(1, NULL);
    if (st.ticket != NULL)
        wolfSSL_SESSION_free(st.ticket);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    if (server_fd >= 0)
        close(server_fd);
    return 0;
}
