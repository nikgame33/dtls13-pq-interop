/* wolfSSL adapter for the DTLS 1.3 interop harness (docs/shim-interface.md). */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
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
/* --mtu is the IP path MTU; IPv6 (40) + UDP (8) headers leave the datagram payload. */
#define IP_UDP_OVERHEAD 48
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

static volatile sig_atomic_t g_hrr, g_hrr_cookie, g_hrr_group;
static int g_is_client;

struct options {
    const char *role, *variant, *host, *port, *groups, *mtu, *ca;
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

static void emit_result(int ok, const char *version, const char *group, const char *error)
{
    fputs("{\"event\": \"result\", \"ok\": ", stdout);
    fputs(json_bool(ok), stdout);
    fputs(", \"version\": ", stdout);
    print_json_string(version);
    fputs(", \"group\": ", stdout);
    print_json_string(group);
    printf(", \"hrr\": %s, \"hrr_cookie\": %s, \"hrr_group\": %s, \"error\": ", json_bool(g_hrr),
           json_bool(g_hrr_cookie), json_bool(g_hrr_group));
    print_json_string(error);
    fputs("}\n", stdout);
    fflush(stdout);
}

_Noreturn static void vfail(int code, const char *prefix, const char *fmt, va_list ap)
{
    char msg[256];
    size_t n = (size_t)snprintf(msg, sizeof(msg), "%s", prefix);
    vsnprintf(msg + n, sizeof(msg) - n, fmt, ap);
    log_msg("%s", msg);
    emit_result(0, NULL, NULL, msg);
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

static void on_deadline(int sig)
{
    (void)sig;
    /* Async-signal-safe: write(2) of constant strings only. */
    write_str("{\"event\": \"result\", \"ok\": false, \"version\": null, \"group\": null, \"hrr\": ");
    write_str(json_bool(g_hrr));
    write_str(", \"hrr_cookie\": ");
    write_str(json_bool(g_hrr_cookie));
    write_str(", \"hrr_group\": ");
    write_str(json_bool(g_hrr_group));
    write_str(", \"error\": \"timeout\"}\n");
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
        if (i + 1 > n)
            return 0;
        i += 1 + p[i]; /* legacy_cookie */
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
            if (is_hrr && count_hrr) {
                g_hrr = 1;
                g_hrr_cookie = (seen & SEEN_COOKIE) != 0;
                g_hrr_group = (seen & SEEN_KEY_SHARE) != 0;
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
    enum { O_ROLE = 1, O_VARIANT, O_HOST, O_PORT, O_GROUPS, O_MTU, O_CA,
           O_KEY_SHARE, O_VALIDATE, O_CERT, O_KEY, O_COUNT };
    static const struct option longopts[] = {
        {"role", required_argument, NULL, O_ROLE},
        {"variant", required_argument, NULL, O_VARIANT},
        {"host", required_argument, NULL, O_HOST},
        {"port", required_argument, NULL, O_PORT},
        {"groups", required_argument, NULL, O_GROUPS},
        {"mtu", required_argument, NULL, O_MTU},
        {"ca", required_argument, NULL, O_CA},
        {"key-share", required_argument, NULL, O_KEY_SHARE},
        {"validate", required_argument, NULL, O_VALIDATE},
        {"cert", required_argument, NULL, O_CERT},
        {"key", required_argument, NULL, O_KEY},
        {NULL, 0, NULL, 0},
    };
    const char **slots[O_COUNT];
    size_t i;
    int c, known = 0;

    memset(o, 0, sizeof(*o));
    slots[O_ROLE] = &o->role;
    slots[O_VARIANT] = &o->variant;
    slots[O_HOST] = &o->host;
    slots[O_PORT] = &o->port;
    slots[O_GROUPS] = &o->groups;
    slots[O_MTU] = &o->mtu;
    slots[O_CA] = &o->ca;
    slots[O_KEY_SHARE] = &o->key_share;
    slots[O_VALIDATE] = &o->validate;
    slots[O_CERT] = &o->cert;
    slots[O_KEY] = &o->key;
    opterr = 0;
    while ((c = getopt_long(argc, argv, ":", longopts, NULL)) != -1) {
        if (c <= 0 || c >= O_COUNT)
            usage_error("unknown option or missing value: %s", argv[optind - 1]);
        if (*slots[c] != NULL)
            usage_error("--%s given twice", longopts[c - 1].name);
        *slots[c] = optarg;
    }
    if (optind != argc)
        usage_error("unexpected argument: %s", argv[optind]);

    require(o->role, "role");
    if (strcmp(o->role, "client") != 0 && strcmp(o->role, "server") != 0)
        usage_error("--role=%s is not client|server", o->role);
    g_is_client = strcmp(o->role, "client") == 0;
    require(o->variant, "variant");
    require(o->host, "host");
    require(o->port, "port");
    require(o->groups, "groups");
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
    if (strcmp(o->mtu, "default") != 0)
        o->mtu_bytes = (int)parse_long(o->mtu, "mtu", IP_UDP_OVERHEAD + 1, 65535);
    list_contains(o->groups, ""); /* rejects empty entries */
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
}

/* Returns the socket; for the server also binds it and stores the bound port. */
static int open_socket(const struct options *o, struct sockaddr_storage *addr, socklen_t *addrlen,
                       int *bound_port)
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
        struct sockaddr_storage local;
        socklen_t local_len = sizeof(local);
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (bind(fd, (struct sockaddr *)addr, *addrlen) != 0)
            fail(EXIT_FAIL, "bind %s:%s: %s", o->host, o->port, strerror(errno));
        if (getsockname(fd, (struct sockaddr *)&local, &local_len) != 0)
            fail(EXIT_FAIL, "getsockname: %s", strerror(errno));
        *bound_port = local.ss_family == AF_INET6
                          ? ntohs(((struct sockaddr_in6 *)&local)->sin6_port)
                          : ntohs(((struct sockaddr_in *)&local)->sin_port);
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
    wolfSSL_CTX_SetIORecv(ctx, recv_cb);
    wolfSSL_CTX_SetIOSend(ctx, send_cb);
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
    char err[256], msg[320];
    snprintf(msg, sizeof(msg), "%s: %s", what, error_string(ssl, ret, err, sizeof(err)));
    log_msg("%s", msg);
    emit_result(0, NULL, NULL, msg);
    exit(EXIT_FAIL);
}

static int handshake(WOLFSSL *ssl, int accept_tls13)
{
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

/* Teardown is bounded by poll(), so wolfSSL must not block in recvfrom. */
static void set_nonblocking(WOLFSSL *ssl, int fd)
{
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        log_msg("teardown: fcntl: %s", strerror(errno));
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

int main(int argc, char **argv)
{
    struct options o;
    struct sockaddr_storage addr;
    socklen_t addrlen;
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;
    struct sigaction sa;
    char buf[64];
    int fd, ret, port = 0, accept_tls13;
    const char *version, *group;

    setvbuf(stdout, NULL, _IOLBF, 0);
    parse_args(argc, argv, &o);
    accept_tls13 = strcmp(o.variant, "accept-tls13") == 0;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_deadline;
    sigaction(SIGALRM, &sa, NULL);

    /* Adds wolfSSL's own debug log to stderr; it does not change behaviour. */
    if (getenv("DTLS_INTEROP_WOLFSSL_DEBUG") != NULL)
        wolfSSL_Debugging_ON();
    if (wolfSSL_Init() != WOLFSSL_SUCCESS)
        fail(EXIT_FAIL, "wolfSSL_Init failed");
    log_msg("wolfSSL %s, role %s, variant %s", LIBWOLFSSL_VERSION_STRING, o.role, o.variant);

    ctx = make_ctx(&o);
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL)
        fail(EXIT_FAIL, "wolfSSL_new failed");
    configure_ssl(ssl, &o);

    fd = open_socket(&o, &addr, &addrlen, &port);
    if (wolfSSL_set_fd(ssl, fd) != WOLFSSL_SUCCESS)
        fail(EXIT_FAIL, "wolfSSL_set_fd failed");
    if (g_is_client && wolfSSL_dtls_set_peer(ssl, &addr, addrlen) != WOLFSSL_SUCCESS)
        fail(EXIT_FAIL, "wolfSSL_dtls_set_peer failed");

    alarm(DEADLINE_SECONDS);
    if (!g_is_client)
        printf("{\"event\": \"ready\", \"port\": %d}\n", port);

    ret = handshake(ssl, accept_tls13);
    if (ret != WOLFSSL_SUCCESS)
        finish_fail(ssl, ret, "handshake");
    version = wolfSSL_get_version(ssl);
    group = negotiated_group(ssl);
    log_msg("handshake done: %s, group %s", version, group ? group : "?");

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

    /* The verdict is final here; teardown problems are only logged. */
    if (g_is_client)
        client_teardown(ssl, fd);
    else
        server_teardown(ssl, fd);
    emit_result(1, version, group, NULL);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    close(fd);
    return 0;
}
