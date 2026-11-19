/* wolfSSL adapter for the DTLS 1.3 interop harness (docs/shim-interface.md). */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>

#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define EXIT_FAIL 1
#define EXIT_UNSUPPORTED 2
/* Safety net only; the harness enforces its own, shorter timeout. */
#define DEADLINE_SECONDS 60
#define SERVER_NAME "localhost"
#define MAX_GROUPS 16
/* --mtu is the IP path MTU; IPv6 (40) + UDP (8) headers leave the datagram payload. */
#define IP_UDP_OVERHEAD 48

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

/* RFC 9846 4.2.3: ServerHello.random of a HelloRetryRequest. */
static const unsigned char HRR_RANDOM[32] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
};

static volatile sig_atomic_t g_hrr;
static int g_is_client;

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

static void emit_result(int ok, const char *version, const char *group, const char *error)
{
    fputs("{\"event\": \"result\", \"ok\": ", stdout);
    fputs(json_bool(ok), stdout);
    fputs(", \"version\": ", stdout);
    print_json_string(version);
    fputs(", \"group\": ", stdout);
    print_json_string(group);
    printf(", \"hrr\": %s, \"error\": ", json_bool(g_hrr));
    print_json_string(error);
    fputs("}\n", stdout);
    fflush(stdout);
}

static void fail(int code, const char *fmt, ...)
{
    char msg[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    log_msg("%s", msg);
    emit_result(0, NULL, NULL, msg);
    exit(code);
}

static void on_deadline(int sig)
{
    static const char hrr_line[] = "{\"event\": \"result\", \"ok\": false, \"version\": null, "
                                   "\"group\": null, \"hrr\": true, \"error\": \"timeout\"}\n";
    static const char no_hrr_line[] = "{\"event\": \"result\", \"ok\": false, \"version\": null, "
                                      "\"group\": null, \"hrr\": false, \"error\": \"timeout\"}\n";
    ssize_t r;
    (void)sig;
    /* Async-signal-safe: preformatted lines and write(2) only. */
    if (g_hrr)
        r = write(STDOUT_FILENO, hrr_line, sizeof(hrr_line) - 1);
    else
        r = write(STDOUT_FILENO, no_hrr_line, sizeof(no_hrr_line) - 1);
    (void)r;
    _exit(EXIT_FAIL);
}

static unsigned get16(const unsigned char *p) { return (unsigned)p[0] << 8 | p[1]; }
static unsigned get24(const unsigned char *p) { return (unsigned)p[0] << 16 | p[1] << 8 | p[2]; }

/* Log extension types/lengths of a (first fragment of a) ClientHello or ServerHello/HRR,
 * plus the key_share groups, so cookie echo and key_share content are visible in the log. */
static void log_hello_exts(const unsigned char *p, unsigned n, unsigned msg_type)
{
    unsigned i = 34, end;
    if (i + 1 > n)
        return;
    i += 1 + p[i]; /* legacy_session_id */
    if (msg_type == 1) {
        if (i + 1 > n)
            return;
        i += 1 + p[i]; /* legacy_cookie */
        if (i + 2 > n)
            return;
        i += 2 + get16(p + i); /* cipher_suites */
        if (i + 1 > n)
            return;
        i += 1 + p[i]; /* legacy_compression_methods */
    }
    else {
        i += 3; /* cipher_suite, legacy_compression_method */
    }
    if (i + 2 > n)
        return;
    end = i + 2 + get16(p + i);
    fputs(" exts=", stderr);
    for (i += 2; i + 4 <= n && i + 4 <= end; i += 4 + get16(p + i + 2)) {
        unsigned type = get16(p + i), len = get16(p + i + 2), j;
        fprintf(stderr, "%u:%u", type, len);
        if (type == 51 && msg_type == 1 && i + 6 <= n) {
            fputs("(", stderr);
            for (j = i + 6; j + 4 <= n && j + 4 <= i + 4 + len; j += 4 + get16(p + j + 2))
                fprintf(stderr, "%s0x%04x", j == i + 6 ? "" : ",", get16(p + j));
            fputs(")", stderr);
        }
        else if (type == 51 && msg_type == 2 && len >= 2 && i + 6 <= n) {
            fprintf(stderr, "(0x%04x)", get16(p + i + 4));
        }
        fputs(",", stderr);
    }
    if (n < end)
        fputs("...", stderr);
}

/* Log the plaintext records of one datagram and note a HelloRetryRequest. */
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
            unsigned frag_len = get24(b + h + 9);
            int is_hrr = b[h] == 2 && frag_off == 0 && frag_len >= 34 &&
                         h + 12 + 34 <= body + len && memcmp(b + h + 14, HRR_RANDOM, 32) == 0;
            fprintf(stderr, " hs=%u%s seq=%u frag=%u+%u/%u", b[h], is_hrr ? "(HRR)" : "",
                    (unsigned)b[h + 4] << 8 | b[h + 5], frag_off, frag_len, msg_len);
            if (is_hrr && count_hrr)
                g_hrr = 1;
            if ((b[h] == 1 || b[h] == 2) && frag_off == 0) {
                unsigned avail = body + len - (h + 12);
                log_hello_exts(b + h + 12, frag_len < avail ? frag_len : avail, b[h]);
            }
            h += 12 + frag_len;
        }
        off = (int)(body + len);
    }
    fputc('\n', stderr);
}

static int recv_cb(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    int r = EmbedReceiveFrom(ssl, buf, sz, ctx);
    if (r > 0)
        inspect_datagram("rx", (const unsigned char *)buf, r, g_is_client);
    return r;
}

static int send_cb(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    int r = EmbedSendTo(ssl, buf, sz, ctx);
    if (r > 0)
        inspect_datagram("tx", (const unsigned char *)buf, r, !g_is_client);
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

struct options {
    const char *role, *host, *port, *groups, *key_share, *validate;
    const char *cert, *key, *ca;
    int mtu;
};

static void usage_error(const char *msg) { fail(EXIT_FAIL, "usage: %s", msg); }

static void parse_args(int argc, char **argv, struct options *o)
{
    enum { O_ROLE = 1, O_HOST, O_PORT, O_GROUPS, O_KEY_SHARE, O_MTU, O_VALIDATE,
           O_CERT, O_KEY, O_CA, O_PSK_IN, O_PSK_OUT };
    static const struct option longopts[] = {
        {"role", required_argument, NULL, O_ROLE},
        {"host", required_argument, NULL, O_HOST},
        {"port", required_argument, NULL, O_PORT},
        {"groups", required_argument, NULL, O_GROUPS},
        {"key-share", required_argument, NULL, O_KEY_SHARE},
        {"mtu", required_argument, NULL, O_MTU},
        {"validate", required_argument, NULL, O_VALIDATE},
        {"cert", required_argument, NULL, O_CERT},
        {"key", required_argument, NULL, O_KEY},
        {"ca", required_argument, NULL, O_CA},
        {"psk-in", required_argument, NULL, O_PSK_IN},
        {"psk-out", required_argument, NULL, O_PSK_OUT},
        {NULL, 0, NULL, 0},
    };
    int c;
    char *end;
    long v;

    memset(o, 0, sizeof(*o));
    opterr = 0;
    while ((c = getopt_long(argc, argv, "", longopts, NULL)) != -1) {
        switch (c) {
        case O_ROLE: o->role = optarg; break;
        case O_HOST: o->host = optarg; break;
        case O_PORT: o->port = optarg; break;
        case O_GROUPS: o->groups = optarg; break;
        case O_KEY_SHARE: o->key_share = optarg; break;
        case O_VALIDATE: o->validate = optarg; break;
        case O_CERT: o->cert = optarg; break;
        case O_KEY: o->key = optarg; break;
        case O_CA: o->ca = optarg; break;
        case O_MTU:
            v = strtol(optarg, &end, 10);
            if (*end != '\0' || v <= IP_UDP_OVERHEAD || v > 65535)
                usage_error("--mtu must be an integer in 49..65535");
            o->mtu = (int)v;
            break;
        case O_PSK_IN:
        case O_PSK_OUT:
            /* The contract does not yet define the PSK file format or server ticket-key sharing. */
            fail(EXIT_UNSUPPORTED, "unsupported: --psk-in/--psk-out not implemented");
            break;
        default:
            fail(EXIT_UNSUPPORTED, "unsupported option: %s", argv[optind - 1]);
        }
    }
    if (optind != argc)
        usage_error("unexpected positional argument");
    if (o->role == NULL || (strcmp(o->role, "client") != 0 && strcmp(o->role, "server") != 0))
        usage_error("--role client|server is required");
    if (o->host == NULL || o->port == NULL)
        usage_error("--host and --port are required");
    if (o->validate != NULL && strcmp(o->validate, "off") != 0 &&
        strcmp(o->validate, "cookie") != 0)
        fail(EXIT_UNSUPPORTED, "unsupported: --validate %s", o->validate);
}

static void apply_groups(WOLFSSL *ssl, const char *list)
{
    int ids[MAX_GROUPS], n = 0;
    char buf[512], *tok, *save = NULL;

    if (strlen(list) >= sizeof(buf))
        usage_error("--groups too long");
    strcpy(buf, list);
    for (tok = strtok_r(buf, ",", &save); tok != NULL; tok = strtok_r(NULL, ",", &save)) {
        const struct group *g = find_group_by_iana(tok);
        if (g == NULL)
            fail(EXIT_UNSUPPORTED, "unsupported group: %s", tok);
        if (n == MAX_GROUPS)
            usage_error("too many groups");
        /* wolfSSL_set_groups rejects the whole list, so probe each group for a precise error. */
        if (wolfSSL_UseSupportedCurve(ssl, (word16)g->id) != WOLFSSL_SUCCESS)
            fail(EXIT_UNSUPPORTED, "unsupported group in this build: %s", tok);
        ids[n++] = g->id;
    }
    if (n == 0)
        usage_error("--groups is empty");
    if (wolfSSL_set_groups(ssl, ids, n) != WOLFSSL_SUCCESS)
        fail(EXIT_UNSUPPORTED, "wolfSSL_set_groups rejected: %s", list);
}

static void apply_key_share(WOLFSSL *ssl, const char *key_share)
{
    const struct group *g;
    int ret;
    if (strcmp(key_share, "empty") == 0) {
        if (wolfSSL_NoKeyShares(ssl) != WOLFSSL_SUCCESS)
            fail(EXIT_FAIL, "wolfSSL_NoKeyShares failed");
        return;
    }
    g = find_group_by_iana(key_share);
    if (g == NULL)
        fail(EXIT_UNSUPPORTED, "unsupported key share group: %s", key_share);
    ret = wolfSSL_UseKeyShare(ssl, (word16)g->id);
    if (ret != WOLFSSL_SUCCESS)
        fail(EXIT_UNSUPPORTED, "wolfSSL_UseKeyShare(%s) failed: %d", key_share, ret);
}

static int open_socket(const struct options *o, struct sockaddr_storage *addr, socklen_t *addrlen)
{
    struct addrinfo hints, *res;
    int fd, rc, one = 1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
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
    if (!g_is_client) {
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (bind(fd, (struct sockaddr *)addr, *addrlen) != 0)
            fail(EXIT_FAIL, "bind %s:%s: %s", o->host, o->port, strerror(errno));
    }
    return fd;
}

static WOLFSSL_CTX *make_ctx(const struct options *o)
{
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(g_is_client ? wolfDTLSv1_3_client_method()
                                                   : wolfDTLSv1_3_server_method());
    if (ctx == NULL)
        fail(EXIT_FAIL, "wolfSSL_CTX_new failed");
    if (g_is_client) {
        if (o->ca == NULL)
            usage_error("client needs --ca");
        if (wolfSSL_CTX_load_verify_locations(ctx, o->ca, NULL) != WOLFSSL_SUCCESS)
            fail(EXIT_FAIL, "cannot load CA %s", o->ca);
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    }
    else {
        if (o->cert == NULL || o->key == NULL)
            usage_error("server needs --cert and --key");
        if (wolfSSL_CTX_use_certificate_chain_file(ctx, o->cert) != WOLFSSL_SUCCESS)
            fail(EXIT_FAIL, "cannot load certificate %s", o->cert);
        if (wolfSSL_CTX_use_PrivateKey_file(ctx, o->key, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
            fail(EXIT_FAIL, "cannot load key %s", o->key);
    }
    wolfSSL_CTX_SetIORecv(ctx, recv_cb);
    wolfSSL_CTX_SetIOSend(ctx, send_cb);
    return ctx;
}

static void configure_ssl(WOLFSSL *ssl, const struct options *o)
{
    /* wolfSSL's MTU bounds each datagram it writes (record headers included). */
    if (o->mtu > 0 &&
        wolfSSL_dtls_set_mtu(ssl, (unsigned short)(o->mtu - IP_UDP_OVERHEAD)) != WOLFSSL_SUCCESS)
        fail(EXIT_UNSUPPORTED, "unsupported: --mtu %d", o->mtu);
    if (o->groups != NULL)
        apply_groups(ssl, o->groups);
    if (g_is_client) {
        if (o->validate != NULL)
            log_msg("ignoring --validate on the client");
        if (o->key_share != NULL)
            apply_key_share(ssl, o->key_share);
        if (wolfSSL_check_domain_name(ssl, SERVER_NAME) != WOLFSSL_SUCCESS)
            fail(EXIT_FAIL, "wolfSSL_check_domain_name failed");
        return;
    }
    if (o->key_share != NULL)
        log_msg("ignoring --key-share on the server");
    /* A DTLS 1.3 server built with WOLFSSL_SEND_HRR_COOKIE sends the cookie by default. */
    if (o->validate != NULL && strcmp(o->validate, "off") == 0) {
        if (wolfSSL_disable_hrr_cookie(ssl) != WOLFSSL_SUCCESS)
            fail(EXIT_FAIL, "wolfSSL_disable_hrr_cookie failed");
    }
    else if (o->validate != NULL) {
        if (wolfSSL_send_hrr_cookie(ssl, NULL, 0) != WOLFSSL_SUCCESS)
            fail(EXIT_FAIL, "wolfSSL_send_hrr_cookie failed");
    }
}

static void finish_fail(WOLFSSL *ssl, int ret, const char *what)
{
    char err[256], msg[320];
    snprintf(msg, sizeof(msg), "%s: %s", what, error_string(ssl, ret, err, sizeof(err)));
    log_msg("%s", msg);
    emit_result(0, NULL, NULL, msg);
    exit(EXIT_FAIL);
}

static int handshake(WOLFSSL *ssl)
{
    /* wolfSSL_accept() is what applications call; wolfSSL_accept_TLSv13() differs for a
     * fragmented CH1 with the cookie disabled (README.md), so tests can select it. */
    int tls13_accept = getenv("DTLS_INTEROP_WOLFSSL_ACCEPT_TLSV13") != NULL;
    if (!g_is_client && tls13_accept)
        log_msg("server uses wolfSSL_accept_TLSv13()");
    for (;;) {
        int ret = g_is_client      ? wolfSSL_connect(ssl)
                  : tls13_accept ? wolfSSL_accept_TLSv13(ssl)
                                 : wolfSSL_accept(ssl);
        int err;
        if (ret == WOLFSSL_SUCCESS)
            return ret;
        err = wolfSSL_get_error(ssl, ret);
        if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE)
            return ret;
    }
}

int main(int argc, char **argv)
{
    struct options o;
    struct sockaddr_storage addr;
    socklen_t addrlen;
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;
    struct sigaction sa;
    char buf[64];
    int fd, ret;
    const char *expect, *reply;

    setvbuf(stdout, NULL, _IOLBF, 0);
    parse_args(argc, argv, &o);
    g_is_client = strcmp(o.role, "client") == 0;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_deadline;
    sigaction(SIGALRM, &sa, NULL);

    if (getenv("DTLS_INTEROP_WOLFSSL_DEBUG") != NULL)
        wolfSSL_Debugging_ON();
    if (wolfSSL_Init() != WOLFSSL_SUCCESS)
        fail(EXIT_FAIL, "wolfSSL_Init failed");
    log_msg("wolfSSL %s, role %s", LIBWOLFSSL_VERSION_STRING, o.role);

    ctx = make_ctx(&o);
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL)
        fail(EXIT_FAIL, "wolfSSL_new failed");
    configure_ssl(ssl, &o);

    fd = open_socket(&o, &addr, &addrlen);
    if (wolfSSL_set_fd(ssl, fd) != WOLFSSL_SUCCESS)
        fail(EXIT_FAIL, "wolfSSL_set_fd failed");
    if (g_is_client && wolfSSL_dtls_set_peer(ssl, &addr, addrlen) != WOLFSSL_SUCCESS)
        fail(EXIT_FAIL, "wolfSSL_dtls_set_peer failed");

    alarm(DEADLINE_SECONDS);
    if (!g_is_client) {
        puts("{\"event\": \"ready\"}");
        fflush(stdout);
    }

    ret = handshake(ssl);
    if (ret != WOLFSSL_SUCCESS)
        finish_fail(ssl, ret, "handshake");
    log_msg("handshake done: %s, group %s", wolfSSL_get_version(ssl),
            wolfSSL_get_curve_name(ssl) ? wolfSSL_get_curve_name(ssl) : "?");

    expect = g_is_client ? "pong" : "ping";
    reply = g_is_client ? "ping" : "pong";
    if (g_is_client && (ret = wolfSSL_write(ssl, reply, 4)) != 4)
        finish_fail(ssl, ret, "write");
    ret = wolfSSL_read(ssl, buf, sizeof(buf));
    if (ret <= 0)
        finish_fail(ssl, ret, "read");
    if (ret != 4 || memcmp(buf, expect, 4) != 0)
        fail(EXIT_FAIL, "unexpected application data (%d bytes)", ret);
    if (!g_is_client && (ret = wolfSSL_write(ssl, reply, 4)) != 4)
        finish_fail(ssl, ret, "write");

    alarm(0);
    emit_result(1, wolfSSL_get_version(ssl), negotiated_group(ssl), NULL);
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    close(fd);
    return 0;
}
