/* DTLS 1.3 interop adapter for OpenSSL, implementing docs/shim-interface.md. */
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
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

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

enum { EXIT_OK = 0, EXIT_FAIL = 1, EXIT_UNSUPPORTED = 2, EXIT_USAGE = 64 };

#define SERVER_NAME "localhost"
#define MAX_GROUPS 16
#define TEARDOWN_MS 2000
/* --mtu is the IP path MTU; the contract reserves IPv6 + UDP headers for every address family. */
#define IP_UDP_OVERHEAD 48
#define LISTENER_DEFAULT_MAX_DGRAM 2000

/* Bits stored in the SSL's ex_data once a HelloRetryRequest was sent or received. */
enum { HRR_SEEN = 1, HRR_COOKIE = 2, HRR_GROUP = 4 };

enum { OPT_ROLE, OPT_VARIANT, OPT_HOST, OPT_PORT, OPT_GROUPS, OPT_MTU, OPT_CA, OPT_KEY_SHARE,
    OPT_VALIDATE, OPT_CERT, OPT_KEY, OPT_COUNT };

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
    { NULL, 0, NULL, 0 },
};

static const bool CLIENT_OPT[OPT_COUNT] = {
    [OPT_ROLE] = true, [OPT_VARIANT] = true, [OPT_HOST] = true, [OPT_PORT] = true,
    [OPT_GROUPS] = true, [OPT_MTU] = true, [OPT_CA] = true, [OPT_KEY_SHARE] = true,
};
static const bool SERVER_OPT[OPT_COUNT] = {
    [OPT_ROLE] = true, [OPT_VARIANT] = true, [OPT_HOST] = true, [OPT_PORT] = true,
    [OPT_GROUPS] = true, [OPT_MTU] = true, [OPT_CA] = true, [OPT_VALIDATE] = true,
    [OPT_CERT] = true, [OPT_KEY] = true,
};

struct options {
    const char *val[OPT_COUNT];
    bool server;
    bool accept_variant; /* --variant=accept: SSL_accept on a connected socket, no listener */
    bool cookie;
    long mtu;
    long payload; /* largest UDP payload: mtu - IP_UDP_OVERHEAD, or 0 for --mtu=default */
};

static struct options g_opts;
static int g_hrr_idx = -1;
static unsigned char g_cookie_key[32];
static struct sockaddr_storage g_peer;
static socklen_t g_peer_len;

/* SHA-256("HelloRetryRequest"), RFC 9846 section 4.2.3. */
static const unsigned char HRR_RANDOM[32] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
};

/* OpenSSL reports some groups in lower case ("x25519"); output uses IANA spelling. */
static const char *const IANA_GROUPS[] = {
    "X25519", "X448", "secp256r1", "secp384r1", "secp521r1",
    "X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "MLKEM512X25519",
    "MLKEM512", "MLKEM768", "MLKEM1024",
    "ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144", "ffdhe8192",
};

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

static const char *iana_group_name(const char *name)
{
    if (name == NULL)
        return NULL;
    for (size_t i = 0; i < sizeof(IANA_GROUPS) / sizeof(IANA_GROUPS[0]); i++)
        if (strcasecmp(name, IANA_GROUPS[i]) == 0)
            return IANA_GROUPS[i];
    return name;
}

static void json_bool(bool known, bool value)
{
    fputs(!known ? "null" : value ? "true" : "false", stdout);
}

/* Emits the result line and returns `code` so callers can `return finish(...)`. */
static int finish(int code, SSL *ssl, bool handshake_done, const char *error)
{
    bool known = ssl != NULL && code != EXIT_UNSUPPORTED && code != EXIT_USAGE;
    intptr_t hrr = known ? (intptr_t)SSL_get_ex_data(ssl, g_hrr_idx) : 0;

    printf("{\"event\": \"result\", \"ok\": %s, \"version\": ", code == EXIT_OK ? "true" : "false");
    json_string(handshake_done ? SSL_get_version(ssl) : NULL);
    fputs(", \"group\": ", stdout);
    json_string(handshake_done ? iana_group_name(SSL_get0_group_name(ssl)) : NULL);
    fputs(", \"hrr\": ", stdout);
    json_bool(known, hrr & HRR_SEEN);
    fputs(", \"hrr_cookie\": ", stdout);
    json_bool(known, hrr & HRR_COOKIE);
    fputs(", \"hrr_group\": ", stdout);
    json_bool(known, hrr & HRR_GROUP);
    fputs(", \"error\": ", stdout);
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

/* Library failure: report the last OpenSSL reason string, else the SSL_get_error class. */
static int fail_ssl(SSL *ssl, int ret, const char *what)
{
    char buf[256];
    unsigned long e = ERR_peek_last_error();
    int err = ssl != NULL ? SSL_get_error(ssl, ret) : SSL_ERROR_SSL;
    const char *reason = e != 0 ? ERR_reason_error_string(e) : NULL;

    if (reason != NULL)
        snprintf(buf, sizeof(buf), "%s: %s", what, reason);
    else if (err == SSL_ERROR_SYSCALL && errno != 0)
        snprintf(buf, sizeof(buf), "%s: %s", what, strerror(errno));
    else
        snprintf(buf, sizeof(buf), "%s: SSL_get_error=%d", what, err);
    fprintf(stderr, "error: %s\n", buf);
    ERR_print_errors_fp(stderr);
    return finish(EXIT_FAIL, ssl, false, buf);
}

static const char *hs_name(unsigned char type)
{
    switch (type) {
    case SSL3_MT_CLIENT_HELLO: return "ClientHello";
    case SSL3_MT_SERVER_HELLO: return "ServerHello";
    case SSL3_MT_NEWSESSION_TICKET: return "NewSessionTicket";
    case SSL3_MT_ENCRYPTED_EXTENSIONS: return "EncryptedExtensions";
    case SSL3_MT_CERTIFICATE: return "Certificate";
    case SSL3_MT_CERTIFICATE_VERIFY: return "CertificateVerify";
    case SSL3_MT_FINISHED: return "Finished";
    case SSL3_MT_KEY_UPDATE: return "KeyUpdate";
    default: return "other";
    }
}

static unsigned read_u16(const unsigned char *p)
{
    return (unsigned)p[0] << 8 | p[1];
}

/* Walks the HRR extensions (RFC 9846 section 4.2.3 layout) for cookie and key_share. */
static intptr_t hrr_flags(const unsigned char *p, size_t len)
{
    size_t off = DTLS1_HM_HEADER_LENGTH + 2 + sizeof(HRR_RANDOM), end;
    intptr_t flags = HRR_SEEN;

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

/* DTLS handshake buffers start with the 12-byte header; HRR is a ServerHello with a fixed random. */
static void msg_cb(int write_p, int version, int content_type, const void *buf, size_t len,
    SSL *ssl, void *arg)
{
    const unsigned char *p = buf;
    const char *dir = write_p ? ">>" : "<<";
    bool hrr;

    (void)version;
    (void)arg;
    /* Plaintext (epoch 0) record headers show how ClientHello and ServerHello were fragmented. */
    if (content_type == SSL3_RT_HEADER && len == DTLS1_RT_HEADER_LENGTH
        && p[0] == SSL3_RT_HANDSHAKE) {
        fprintf(stderr, "%s plaintext handshake record (%u bytes)\n", dir, read_u16(p + 11));
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
    if (content_type != SSL3_RT_HANDSHAKE || len < 1)
        return;
    hrr = p[0] == SSL3_MT_SERVER_HELLO && len >= DTLS1_HM_HEADER_LENGTH + 2 + sizeof(HRR_RANDOM)
        && memcmp(p + DTLS1_HM_HEADER_LENGTH + 2, HRR_RANDOM, sizeof(HRR_RANDOM)) == 0;
    if (hrr) {
        intptr_t flags = hrr_flags(p, len);

        SSL_set_ex_data(ssl, g_hrr_idx, (void *)flags);
        fprintf(stderr, "%s HelloRetryRequest (%zu bytes, cookie=%d, selected_group=%d)\n", dir,
            len, (flags & HRR_COOKIE) != 0, (flags & HRR_GROUP) != 0);
        return;
    }
    fprintf(stderr, "%s %s (%zu bytes)\n", dir, hs_name(p[0]), len);
}

/* SSL_set_mtu takes the UDP payload size (DTLS_set_link_mtu would subtract only 28 on IPv4). */
static bool set_mtu(SSL *ssl)
{
    if (g_opts.payload == 0)
        return true;
    SSL_set_options(ssl, SSL_OP_NO_QUERY_MTU);
    return SSL_set_mtu(ssl, g_opts.payload) > 0;
}

/* Listener connections are created internally, so per-connection MTU is set once CH1 arrives. */
static int client_hello_cb(SSL *ssl, int *alert, void *arg)
{
    (void)arg;
    if (!set_mtu(ssl)) {
        *alert = SSL_AD_INTERNAL_ERROR;
        return SSL_CLIENT_HELLO_ERROR;
    }
    return SSL_CLIENT_HELLO_SUCCESS;
}

/* Logs every UDP datagram sent: BIO_write on connected sockets, BIO_sendmmsg from the listener. */
static long datagram_cb(BIO *b, int oper, const char *argp, size_t len, int argi, long argl,
    int ret, size_t *processed)
{
    (void)b, (void)len, (void)argi, (void)argl;
    if (oper == (BIO_CB_WRITE | BIO_CB_RETURN) && ret > 0) {
        fprintf(stderr, ">> datagram (%zu bytes)\n", *processed);
    } else if (oper == (BIO_CB_SENDMMSG | BIO_CB_RETURN) && ret > 0) {
        const BIO_MMSG_CB_ARGS *args = (const BIO_MMSG_CB_ARGS *)argp;

        for (size_t i = 0; i < *args->msgs_processed; i++) {
            const BIO_MSG *m = (const BIO_MSG *)((const char *)args->msg + i * args->stride);
            fprintf(stderr, ">> datagram (%zu bytes)\n", m->data_len);
        }
    }
    return ret;
}

/* accept variant: the HRR cookie binds the peer address, as the listener's cookie does. */
static bool peer_mac(unsigned char *out, size_t *out_len)
{
    return EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, g_cookie_key, sizeof(g_cookie_key),
               (const unsigned char *)&g_peer, g_peer_len, out, 32, out_len)
        != NULL;
}

static int gen_cookie_cb(SSL *ssl, unsigned char *cookie, size_t *cookie_len)
{
    (void)ssl;
    return peer_mac(cookie, cookie_len);
}

static int verify_cookie_cb(SSL *ssl, const unsigned char *cookie, size_t cookie_len)
{
    unsigned char mac[32];
    size_t n;

    (void)ssl;
    return peer_mac(mac, &n) && cookie_len == n && CRYPTO_memcmp(mac, cookie, n) == 0;
}

/* Rejects groups this build lacks (exit 2) and sets the OpenSSL group list.
 * Returns EXIT_OK, or the exit code after emitting a result line. */
static int configure_groups(SSL_CTX *ctx)
{
    char *names[MAX_GROUPS];
    size_t n = 0;
    char list[1024] = "";
    char *copy = strdup(g_opts.val[OPT_GROUPS]);
    const char *share = g_opts.server ? "default" : g_opts.val[OPT_KEY_SHARE];
    STACK_OF(OPENSSL_CSTRING) *impl = sk_OPENSSL_CSTRING_new_null();
    int rc = EXIT_OK;

    if (copy == NULL || impl == NULL || !SSL_CTX_get0_implemented_groups(ctx, 1, impl)) {
        rc = fail_ssl(NULL, 0, "listing implemented groups");
        goto out;
    }
    for (char *tok = strtok(copy, ","); tok != NULL; tok = strtok(NULL, ",")) {
        bool known = false;

        for (int i = 0; i < sk_OPENSSL_CSTRING_num(impl); i++)
            known = known || strcasecmp(tok, sk_OPENSSL_CSTRING_value(impl, i)) == 0;
        if (!known) {
            rc = fail_msg(EXIT_UNSUPPORTED, NULL, "group %s not implemented by %s", tok,
                OpenSSL_version(OPENSSL_VERSION));
            goto out;
        }
        names[n++] = tok;
    }
    /* One tuple: the server takes its best group among the client's shares, else HRR. */
    for (size_t i = 0; i < n; i++) {
        bool star = strcasecmp(names[i], share) == 0;

        if (strlen(list) + strlen(names[i]) + 3 >= sizeof(list)) {
            rc = fail_msg(EXIT_USAGE, NULL, "group list too long");
            goto out;
        }
        strcat(list, i == 0 ? "" : ":");
        strcat(list, star ? "*" : "");
        strcat(list, names[i]);
    }
    fprintf(stderr, "groups list: %s\n", list);
    if (!SSL_CTX_set1_groups_list(ctx, list))
        rc = fail_ssl(NULL, 0, "SSL_CTX_set1_groups_list");
    else if (g_opts.server)
        SSL_CTX_set_options(ctx, SSL_OP_SERVER_PREFERENCE);
out:
    sk_OPENSSL_CSTRING_free(impl);
    free(copy);
    return rc;
}

static long ms_until(const struct timespec *deadline)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return (deadline->tv_sec - now.tv_sec) * 1000 + (deadline->tv_nsec - now.tv_nsec) / 1000000;
}

/* fd < 0 means a listener connection, which only SSL_poll can wait on. */
static bool wait_readable(SSL *ssl, int fd, long ms)
{
    if (ms <= 0)
        return false;
    if (fd >= 0) {
        struct pollfd p = { .fd = fd, .events = POLLIN };

        return poll(&p, 1, (int)ms) > 0;
    } else {
        SSL_POLL_ITEM item = { .desc = SSL_as_poll_descriptor(ssl), .events = SSL_POLL_EVENT_R };
        struct timeval tv = { .tv_sec = ms / 1000, .tv_usec = (ms % 1000) * 1000 };
        size_t ready = 0;

        return SSL_poll(&item, 1, sizeof(item), &tv, 0, &ready) && ready > 0;
    }
}

/* Waits up to TEARDOWN_MS for the peer's close_notify. After our own close_notify DTLS drops
 * other records, so SSL_shutdown is the reader; before it, SSL_read is. Errors only go to stderr. */
static void await_close_notify(SSL *ssl, int fd, bool sent_ours)
{
    struct timespec deadline;
    char buf[64];
    size_t n;
    int ret, err;

    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += TEARDOWN_MS / 1000;
    if (!(fd >= 0 ? BIO_socket_nbio(fd, 1) : SSL_set_blocking_mode(ssl, 0)))
        return;
    for (;;) {
        ret = sent_ours ? SSL_shutdown(ssl) : SSL_read_ex(ssl, buf, sizeof(buf), &n);
        if (sent_ours && ret == 1)
            break;
        err = SSL_get_error(ssl, ret);
        if (!sent_ours && (ret == 1 || err == SSL_ERROR_WANT_WRITE))
            continue;
        if (err == SSL_ERROR_ZERO_RETURN)
            break;
        if (err != SSL_ERROR_WANT_READ) {
            fprintf(stderr, "teardown: SSL_get_error=%d\n", err);
            ERR_print_errors_fp(stderr);
            break;
        }
        if (!wait_readable(ssl, fd, ms_until(&deadline))) {
            fprintf(stderr, "teardown: no close_notify within %d ms\n", TEARDOWN_MS);
            break;
        }
    }
    fprintf(stderr, "teardown done\n");
    ERR_clear_error();
}

static int run_client(SSL_CTX *ctx)
{
    BIO_ADDRINFO *res = NULL;
    const BIO_ADDRINFO *ai;
    int fd = -1, ret, rc;
    BIO *bio;
    SSL *ssl;
    size_t n;
    char buf[64];

    if (!BIO_lookup_ex(g_opts.val[OPT_HOST], g_opts.val[OPT_PORT], BIO_LOOKUP_CLIENT, AF_UNSPEC,
            SOCK_DGRAM, 0, &res))
        return fail_ssl(NULL, 0, "resolving --host");
    for (ai = res; ai != NULL; ai = BIO_ADDRINFO_next(ai)) {
        fd = BIO_socket(BIO_ADDRINFO_family(ai), SOCK_DGRAM, 0, 0);
        if (fd != -1 && BIO_connect(fd, BIO_ADDRINFO_address(ai), 0))
            break;
        if (fd != -1)
            BIO_closesocket(fd);
        fd = -1;
    }
    BIO_ADDRINFO_free(res);
    if (fd == -1)
        return fail_ssl(NULL, 0, "connecting UDP socket");

    /* A connected socket lets the dgram BIO pick up the peer via getpeername. */
    bio = BIO_new_dgram(fd, BIO_CLOSE);
    ssl = SSL_new(ctx);
    if (bio == NULL || ssl == NULL)
        return fail_ssl(NULL, 0, "creating connection");
    BIO_set_callback_ex(bio, datagram_cb);
    SSL_set_bio(ssl, bio, bio);
    if (!set_mtu(ssl))
        return fail_msg(EXIT_UNSUPPORTED, NULL, "--mtu=%ld rejected by SSL_set_mtu(%ld)",
            g_opts.mtu, g_opts.payload);
    if (!SSL_set1_dnsname(ssl, SERVER_NAME) || !SSL_set_tlsext_host_name(ssl, SERVER_NAME))
        return fail_ssl(ssl, 0, "setting server name");

    if ((ret = SSL_connect(ssl)) != 1)
        return fail_ssl(ssl, ret, "handshake");
    fprintf(stderr, "handshake done: %s %s\n", SSL_get_version(ssl), SSL_get0_group_name(ssl));
    if ((ret = SSL_write_ex(ssl, "ping", 4, &n)) != 1)
        return fail_ssl(ssl, ret, "writing ping");
    if ((ret = SSL_read_ex(ssl, buf, sizeof(buf), &n)) != 1)
        return fail_ssl(ssl, ret, "reading pong");
    if (n != 4 || memcmp(buf, "pong", 4) != 0)
        return fail_msg(EXIT_FAIL, ssl, "unexpected echo (%zu bytes)", n);

    /* The verdict is final after pong; teardown problems are only logged. */
    if (SSL_shutdown(ssl) < 0)
        fprintf(stderr, "teardown: sending close_notify failed\n");
    else
        await_close_notify(ssl, fd, true);
    ERR_clear_error();
    rc = finish(EXIT_OK, ssl, true, NULL);
    SSL_free(ssl);
    return rc;
}

static int bind_server_socket(void)
{
    BIO_ADDRINFO *res = NULL;
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);
    int fd;

    if (!BIO_lookup_ex(g_opts.val[OPT_HOST], g_opts.val[OPT_PORT], BIO_LOOKUP_SERVER, AF_UNSPEC,
            SOCK_DGRAM, 0, &res))
        return -1;
    fd = BIO_socket(BIO_ADDRINFO_family(res), SOCK_DGRAM, 0, 0);
    if (fd != -1 && !BIO_bind(fd, BIO_ADDRINFO_address(res), 0)) {
        BIO_closesocket(fd);
        fd = -1;
    }
    BIO_ADDRINFO_free(res);
    if (fd == -1 || getsockname(fd, (struct sockaddr *)&addr, &len) != 0)
        return -1;
    printf("{\"event\": \"ready\", \"port\": %u}\n",
        ntohs(addr.ss_family == AF_INET6 ? ((struct sockaddr_in6 *)&addr)->sin6_port
                                         : ((struct sockaddr_in *)&addr)->sin_port));
    fflush(stdout);
    return fd;
}

/* Default variant: the DTLS listener, which validates new peers itself unless told not to. */
static SSL *accept_with_listener(SSL_CTX *ctx, int fd, SSL **listener)
{
    uint64_t flags = SSL_LISTENER_FLAG_SINGLE_THREAD;
    BIO *bio = BIO_new_dgram(fd, BIO_CLOSE);

    if (!g_opts.cookie)
        flags |= SSL_LISTENER_FLAG_NO_VALIDATE;
    *listener = SSL_new_listener(ctx, flags);
    if (bio == NULL || *listener == NULL)
        return NULL;
    BIO_set_callback_ex(bio, datagram_cb);
    SSL_set_bio(*listener, bio, bio);
    if (g_opts.payload > LISTENER_DEFAULT_MAX_DGRAM
        && !SSL_set_generic_value_uint(*listener, SSL_VALUE_DTLS_LISTENER_MAX_DGRAM_SIZE,
            (uint64_t)g_opts.payload))
        return NULL;
    if (SSL_listen(*listener) != 1)
        return NULL;
    return SSL_accept_connection(*listener, 0);
}

/* accept variant: connect the socket to the first peer and run a plain SSL_accept on it. */
static SSL *accept_connected(SSL_CTX *ctx, int fd)
{
    unsigned char byte;
    BIO *bio;
    SSL *ssl;

    g_peer_len = sizeof(g_peer);
    if (recvfrom(fd, &byte, 1, MSG_PEEK, (struct sockaddr *)&g_peer, &g_peer_len) < 0
        || connect(fd, (struct sockaddr *)&g_peer, g_peer_len) != 0) {
        ERR_raise_data(ERR_LIB_SYS, errno, "waiting for the first datagram");
        return NULL;
    }
    bio = BIO_new_dgram(fd, BIO_CLOSE);
    ssl = SSL_new(ctx);
    if (bio == NULL || ssl == NULL)
        return NULL;
    BIO_set_callback_ex(bio, datagram_cb);
    SSL_set_bio(ssl, bio, bio);
    if (g_opts.cookie)
        SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
    return set_mtu(ssl) ? ssl : NULL;
}

static int run_server(SSL_CTX *ctx)
{
    SSL *probe, *listener = NULL, *conn;
    int fd, ret, rc;
    size_t n;
    char buf[64];

    if (SSL_CTX_use_certificate_chain_file(ctx, g_opts.val[OPT_CERT]) != 1
        || SSL_CTX_use_PrivateKey_file(ctx, g_opts.val[OPT_KEY], SSL_FILETYPE_PEM) != 1
        || SSL_CTX_check_private_key(ctx) != 1)
        return fail_ssl(NULL, 0, "loading --cert/--key");
    /* Reject an MTU the library refuses before announcing readiness. */
    probe = SSL_new(ctx);
    if (probe == NULL || !set_mtu(probe))
        return fail_msg(EXIT_UNSUPPORTED, NULL, "--mtu=%ld rejected by SSL_set_mtu(%ld)",
            g_opts.mtu, g_opts.payload);
    SSL_free(probe);
    SSL_CTX_set_client_hello_cb(ctx, client_hello_cb, NULL);
    if (g_opts.accept_variant) {
        if (RAND_bytes(g_cookie_key, sizeof(g_cookie_key)) != 1)
            return fail_ssl(NULL, 0, "generating cookie key");
        SSL_CTX_set_stateless_cookie_generate_cb(ctx, gen_cookie_cb);
        SSL_CTX_set_stateless_cookie_verify_cb(ctx, verify_cookie_cb);
    }

    if ((fd = bind_server_socket()) == -1)
        return fail_ssl(NULL, 0, "binding UDP socket");
    conn = g_opts.accept_variant ? accept_connected(ctx, fd) : accept_with_listener(ctx, fd, &listener);
    if (conn == NULL)
        return fail_ssl(NULL, 0, "accepting a connection");
    if ((ret = SSL_accept(conn)) != 1)
        return fail_ssl(conn, ret, "handshake");
    fprintf(stderr, "handshake done: %s %s\n", SSL_get_version(conn), SSL_get0_group_name(conn));

    if ((ret = SSL_read_ex(conn, buf, sizeof(buf), &n)) != 1)
        return fail_ssl(conn, ret, "reading ping");
    if (n != 4 || memcmp(buf, "ping", 4) != 0)
        return fail_msg(EXIT_FAIL, conn, "unexpected message (%zu bytes)", n);
    if ((ret = SSL_write_ex(conn, "pong", 4, &n)) != 1)
        return fail_ssl(conn, ret, "writing pong");
    await_close_notify(conn, g_opts.accept_variant ? fd : -1, false);
    if (SSL_shutdown(conn) < 0)
        fprintf(stderr, "teardown: sending close_notify failed\n");
    ERR_clear_error();
    rc = finish(EXIT_OK, conn, true, NULL);
    SSL_free(conn);
    SSL_free(listener);
    return rc;
}

static int usage(const char *fmt, const char *arg)
{
    char msg[256];

    snprintf(msg, sizeof(msg), fmt, arg);
    fprintf(stderr,
        "usage: run --role=client --variant=default --host=HOST --port=PORT\n"
        "           --groups=G1[,G2...] --mtu=N|default --ca=FILE --key-share=GROUP|empty|default\n"
        "       run --role=server --variant=default|accept --host=HOST --port=PORT\n"
        "           --groups=G1[,G2...] --mtu=N|default --ca=FILE --validate=off|cookie\n"
        "           --cert=FILE --key=FILE\n");
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

    v = g_opts.val[OPT_VARIANT];
    /* accept is a server-only variant (variants file); clients only have the default path. */
    if (strcmp(v, "default") != 0 && !(g_opts.server && strcmp(v, "accept") == 0))
        return usage("--variant=%s is not a variant of this role", v);
    g_opts.accept_variant = strcmp(v, "accept") == 0;
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
        if (errno != 0 || *end != '\0' || g_opts.mtu <= IP_UDP_OVERHEAD)
            return usage("--mtu=%s must be default or an integer above 48", g_opts.val[OPT_MTU]);
        g_opts.payload = g_opts.mtu - IP_UDP_OVERHEAD;
    }
    for (int i = OPT_CA; i < OPT_COUNT; i++) {
        if (g_opts.val[i] != NULL && *g_opts.val[i] == '\0')
            return usage("--%s must not be empty", LONGOPTS[i].name);
    }
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

    /* Before parsing: usage errors also print a result line. */
    g_hrr_idx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    if ((rc = parse_options(argc, argv)) != EXIT_OK)
        return rc;
    /* Ignore any system openssl.cnf so runs depend only on the pinned build and these flags. */
    if (!OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG, NULL) || g_hrr_idx < 0)
        return fail_ssl(NULL, 0, "OPENSSL_init_ssl");
    fprintf(stderr, "%s, role=%s variant=%s groups=%s mtu=%s key-share=%s validate=%s\n",
        OpenSSL_version(OPENSSL_VERSION), g_opts.val[OPT_ROLE], g_opts.val[OPT_VARIANT],
        g_opts.val[OPT_GROUPS], g_opts.val[OPT_MTU],
        g_opts.server ? "-" : g_opts.val[OPT_KEY_SHARE],
        g_opts.server ? g_opts.val[OPT_VALIDATE] : "-");

    /* tls_construct_ctos_key_share() fails with NO_SUITABLE_KEY_SHARE when no share is added. */
    if (!g_opts.server && strcmp(g_opts.val[OPT_KEY_SHARE], "empty") == 0)
        return fail_msg(EXIT_UNSUPPORTED, NULL,
            "OpenSSL clients always send at least one key share; empty key_share not possible");

    ctx = SSL_CTX_new(g_opts.server ? DTLS_server_method() : DTLS_client_method());
    if (ctx == NULL || !SSL_CTX_set_min_proto_version(ctx, DTLS1_3_VERSION)
        || !SSL_CTX_set_max_proto_version(ctx, DTLS1_3_VERSION))
        return fail_ssl(NULL, 0, "creating DTLS 1.3 context");
    SSL_CTX_set_msg_callback(ctx, msg_cb);
    if ((rc = configure_groups(ctx)) != EXIT_OK)
        return rc;
    /* Only the client verifies; the server takes --ca because the contract gives it to both. */
    if (!g_opts.server) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        if (!SSL_CTX_load_verify_locations(ctx, g_opts.val[OPT_CA], NULL))
            return fail_ssl(NULL, 0, "loading --ca");
    }

    rc = g_opts.server ? run_server(ctx) : run_client(ctx);
    SSL_CTX_free(ctx);
    return rc;
}
