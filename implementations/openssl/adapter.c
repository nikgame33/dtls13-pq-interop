/* DTLS 1.3 / TLS 1.3 interop adapter for OpenSSL, implementing docs/shim-interface.md. */
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
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

enum { OPT_ROLE, OPT_VARIANT, OPT_HOST, OPT_PORT, OPT_GROUPS, OPT_TRANSPORT, OPT_RESUME, OPT_MTU,
    OPT_CA, OPT_KEY_SHARE, OPT_VALIDATE, OPT_CERT, OPT_KEY, OPT_COUNT };

static const char *const OPT_NAMES[OPT_COUNT] = {
    [OPT_ROLE] = "role", [OPT_VARIANT] = "variant", [OPT_HOST] = "host", [OPT_PORT] = "port",
    [OPT_GROUPS] = "groups", [OPT_TRANSPORT] = "transport", [OPT_RESUME] = "resume",
    [OPT_MTU] = "mtu", [OPT_CA] = "ca", [OPT_KEY_SHARE] = "key-share", [OPT_VALIDATE] = "validate",
    [OPT_CERT] = "cert", [OPT_KEY] = "key",
};

static const bool CLIENT_OPT[OPT_COUNT] = {
    [OPT_ROLE] = true, [OPT_VARIANT] = true, [OPT_HOST] = true, [OPT_PORT] = true,
    [OPT_GROUPS] = true, [OPT_TRANSPORT] = true, [OPT_RESUME] = true, [OPT_MTU] = true,
    [OPT_CA] = true, [OPT_KEY_SHARE] = true,
};
static const bool SERVER_OPT[OPT_COUNT] = {
    [OPT_ROLE] = true, [OPT_VARIANT] = true, [OPT_HOST] = true, [OPT_PORT] = true,
    [OPT_GROUPS] = true, [OPT_TRANSPORT] = true, [OPT_RESUME] = true, [OPT_MTU] = true,
    [OPT_CA] = true, [OPT_VALIDATE] = true, [OPT_CERT] = true, [OPT_KEY] = true,
};

struct options {
    const char *val[OPT_COUNT];
    bool server;
    bool accept_variant; /* --variant=accept: SSL_accept on a connected socket, no listener */
    bool cookie;
    bool tls;    /* --transport=tls: TLS 1.3 over TCP */
    bool resume; /* --resume=ticket: a second connection resumes the first */
    long mtu;
    long payload; /* largest UDP payload: mtu - IP_UDP_OVERHEAD, or 0 for --mtu=default */
};

static struct options g_opts;
static int g_hrr_idx = -1;
static int g_conn; /* connection number for error prefixes; 0 with --resume=off */
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
    char prefixed[320];

    if (error != NULL && g_conn > 0) {
        snprintf(prefixed, sizeof(prefixed), "connection %d: %s", g_conn, error);
        error = prefixed;
    }

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
    fputs(", \"resumed\": ", stdout);
    json_bool(known, known && SSL_session_reused(ssl));
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
    return finish(code, ssl, ssl != NULL && SSL_is_init_finished(ssl), buf);
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
    return finish(EXIT_FAIL, ssl, ssl != NULL && SSL_is_init_finished(ssl), buf);
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
static intptr_t hrr_flags(const unsigned char *p, size_t len, size_t hm_header)
{
    size_t off = hm_header + 2 + sizeof(HRR_RANDOM), end;
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

/* libssl passes each handshake message reassembled (also from TCP segments) with its 12-byte DTLS
 * or 4-byte TLS header; HRR is a ServerHello with a fixed random. */
static void msg_cb(int write_p, int version, int content_type, const void *buf, size_t len,
    SSL *ssl, void *arg)
{
    const unsigned char *p = buf;
    const char *dir = write_p ? ">>" : "<<";
    bool dtls = SSL_is_dtls(ssl);
    size_t hm_header = dtls ? DTLS1_HM_HEADER_LENGTH : SSL3_HM_HEADER_LENGTH;
    bool hrr;

    (void)version;
    (void)arg;
    /* Plaintext (epoch 0) record headers show how ClientHello and ServerHello were fragmented. */
    if (content_type == SSL3_RT_HEADER
        && len == (dtls ? DTLS1_RT_HEADER_LENGTH : SSL3_RT_HEADER_LENGTH)
        && p[0] == SSL3_RT_HANDSHAKE) {
        fprintf(stderr, "%s plaintext handshake record (%u bytes)\n", dir, read_u16(p + len - 2));
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
    hrr = p[0] == SSL3_MT_SERVER_HELLO && len >= hm_header + 2 + sizeof(HRR_RANDOM)
        && memcmp(p + hm_header + 2, HRR_RANDOM, sizeof(HRR_RANDOM)) == 0;
    if (hrr) {
        intptr_t flags = hrr_flags(p, len, hm_header);

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

/* accept variant and TLS: the HRR cookie binds the peer address, as the listener's cookie does. */
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

/* Waits for fd (fd < 0: a listener connection) in the direction err asks for, at most until
 * the DTLS timer expires, then lets the library retransmit; false if waiting failed. */
static bool wait_retry(SSL *ssl, int fd, int err)
{
    bool want_write = err == SSL_ERROR_WANT_WRITE;
    struct timeval tv;
    int infinite = 1;

    if (!SSL_get_event_timeout(ssl, &tv, &infinite))
        return false;
    if (fd >= 0) {
        struct pollfd p = { .fd = fd, .events = want_write ? POLLOUT : POLLIN };
        long ms = tv.tv_sec * 1000 + (tv.tv_usec + 999) / 1000;

        if (poll(&p, 1, infinite ? -1 : (int)ms) < 0 && errno != EINTR)
            return false;
    } else {
        SSL_POLL_ITEM item = { .desc = SSL_as_poll_descriptor(ssl),
            .events = want_write ? SSL_POLL_EVENT_W : SSL_POLL_EVENT_R };
        size_t ready = 0;

        if (!SSL_poll(&item, 1, sizeof(item), infinite ? NULL : &tv, 0, &ready))
            return false;
    }
    return SSL_handle_events(ssl) == 1;
}

enum io_op { IO_CONNECT, IO_ACCEPT, IO_READ, IO_WRITE, IO_SHUTDOWN };

/* A blocking call that retries SSL_ERROR_WANT_READ/WRITE, which OpenSSL 4.1.0 returns even on
 * blocking sockets (README.md); SSL_shutdown retries only WANT_WRITE, its reader is below. */
static int ssl_io(SSL *ssl, int fd, enum io_op op, const void *buf, size_t len, size_t *n)
{
    for (;;) {
        int ret, err;

        switch (op) {
        case IO_CONNECT:
            ret = SSL_connect(ssl);
            break;
        case IO_ACCEPT:
            ret = SSL_accept(ssl);
            break;
        case IO_READ:
            ret = SSL_read_ex(ssl, (void *)buf, len, n);
            break;
        case IO_WRITE:
            ret = SSL_write_ex(ssl, buf, len, n);
            break;
        default:
            ret = SSL_shutdown(ssl);
            if (ret == 0)
                return ret;
        }
        if (ret > 0)
            return ret;
        err = SSL_get_error(ssl, ret);
        if (!(err == SSL_ERROR_WANT_WRITE || (err == SSL_ERROR_WANT_READ && op != IO_SHUTDOWN)))
            return ret;
        fprintf(stderr, "retry after SSL_get_error=%d\n", err);
        if (!wait_retry(ssl, fd, err))
            return ret;
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

/* Connects a new socket to --host/--port, so every call gets its own source port. */
static int client_socket(void)
{
    int type = g_opts.tls ? SOCK_STREAM : SOCK_DGRAM;
    BIO_ADDRINFO *res = NULL;
    const BIO_ADDRINFO *ai;
    int fd = -1;

    if (!BIO_lookup_ex(g_opts.val[OPT_HOST], g_opts.val[OPT_PORT], BIO_LOOKUP_CLIENT, AF_UNSPEC,
            type, 0, &res))
        return -1;
    for (ai = res; ai != NULL; ai = BIO_ADDRINFO_next(ai)) {
        fd = BIO_socket(BIO_ADDRINFO_family(ai), type, 0, 0);
        if (fd != -1 && BIO_connect(fd, BIO_ADDRINFO_address(ai), 0))
            break;
        if (fd != -1)
            BIO_closesocket(fd);
        fd = -1;
    }
    BIO_ADDRINFO_free(res);
    if (fd != -1) {
        struct sockaddr_storage local;
        socklen_t len = sizeof(local);

        if (getsockname(fd, (struct sockaddr *)&local, &len) == 0)
            fprintf(stderr, "socket: local port %u\n",
                ntohs(local.ss_family == AF_INET6 ? ((struct sockaddr_in6 *)&local)->sin6_port
                                                  : ((struct sockaddr_in *)&local)->sin_port));
    }
    return fd;
}

/* One client lifecycle on fd, which *out then owns. offer is the session to resume; ticket, if
 * not NULL, receives a resumable session that arrived before pong (else NULL). */
static int client_connection(SSL_CTX *ctx, int fd, SSL_SESSION *offer, SSL_SESSION **ticket,
    SSL **out)
{
    /* A connected socket lets the dgram BIO pick up the peer via getpeername. */
    BIO *bio = g_opts.tls ? BIO_new_socket(fd, BIO_CLOSE) : BIO_new_dgram(fd, BIO_CLOSE);
    SSL *ssl = SSL_new(ctx);
    size_t n;
    char buf[64];
    int ret;

    *out = ssl;
    if (bio == NULL || ssl == NULL)
        return fail_ssl(NULL, 0, "creating connection");
    if (!g_opts.tls)
        BIO_set_callback_ex(bio, datagram_cb);
    SSL_set_bio(ssl, bio, bio);
    if (!set_mtu(ssl))
        return fail_msg(EXIT_UNSUPPORTED, NULL, "--mtu=%ld rejected by SSL_set_mtu(%ld)",
            g_opts.mtu, g_opts.payload);
    if (!SSL_set1_dnsname(ssl, SERVER_NAME) || !SSL_set_tlsext_host_name(ssl, SERVER_NAME))
        return fail_ssl(ssl, 0, "setting server name");
    if (offer != NULL && !SSL_set_session(ssl, offer))
        return fail_ssl(ssl, 0, "SSL_set_session");

    if ((ret = ssl_io(ssl, fd, IO_CONNECT, NULL, 0, NULL)) != 1)
        return fail_ssl(ssl, ret, "handshake");
    fprintf(stderr, "handshake done: %s %s resumed=%d\n", SSL_get_version(ssl),
        SSL_get0_group_name(ssl), SSL_session_reused(ssl));
    if ((ret = ssl_io(ssl, fd, IO_WRITE, "ping", 4, &n)) != 1)
        return fail_ssl(ssl, ret, "writing ping");
    if ((ret = ssl_io(ssl, fd, IO_READ, buf, sizeof(buf), &n)) != 1)
        return fail_ssl(ssl, ret, "reading pong");
    if (n != 4 || memcmp(buf, "pong", 4) != 0)
        return fail_msg(EXIT_FAIL, ssl, "unexpected echo (%zu bytes)", n);
    /* TLS 1.3 clients replace their session with each NewSessionTicket (statem_clnt.c). */
    if (ticket != NULL) {
        *ticket = SSL_get1_session(ssl);
        if (*ticket != NULL && !SSL_SESSION_is_resumable(*ticket)) {
            SSL_SESSION_free(*ticket);
            *ticket = NULL;
        }
        fprintf(stderr, "session ticket before pong: %s\n", *ticket != NULL ? "yes" : "no");
    }

    /* The verdict is final after pong; teardown problems are only logged. */
    if (ssl_io(ssl, fd, IO_SHUTDOWN, NULL, 0, NULL) < 0)
        fprintf(stderr, "teardown: sending close_notify failed\n");
    else
        await_close_notify(ssl, fd, true);
    ERR_clear_error();
    return EXIT_OK;
}

static int run_client(SSL_CTX *ctx)
{
    SSL_SESSION *ticket = NULL;
    SSL *ssl;
    int fd, rc;
    const char *what = g_opts.tls ? "connecting TCP socket" : "connecting UDP socket";

    if ((fd = client_socket()) == -1)
        return fail_ssl(NULL, 0, what);
    if ((rc = client_connection(ctx, fd, NULL, g_opts.resume ? &ticket : NULL, &ssl)) != EXIT_OK)
        return rc;
    if (g_opts.resume) {
        if (ticket == NULL) {
            fprintf(stderr, "error: no session ticket received\n");
            return finish(EXIT_FAIL, ssl, true, "no session ticket received");
        }
        /* Opened while the first socket is still open, so its port cannot be reused. */
        fd = client_socket();
        SSL_free(ssl);
        g_conn = 2;
        if (fd == -1)
            return fail_ssl(NULL, 0, what);
        if ((rc = client_connection(ctx, fd, ticket, NULL, &ssl)) != EXIT_OK)
            return rc;
        SSL_SESSION_free(ticket);
    }
    rc = finish(EXIT_OK, ssl, true, NULL);
    SSL_free(ssl);
    return rc;
}

struct server {
    int fd;                      /* the bound UDP socket or the listening TCP socket */
    int second_fd;               /* accept variant: UDP socket for connection 2 */
    struct sockaddr_storage addr; /* bound address, captured before any connect() */
    socklen_t addr_len;
    SSL *listener;               /* default DTLS variant */
};

/* Binds (UDP) or listens (TCP), then prints the ready line with the bound port. */
static bool bind_server_socket(struct server *srv)
{
    int type = g_opts.tls ? SOCK_STREAM : SOCK_DGRAM;
    /* The accept variant binds a second UDP socket to the same port for connection 2. */
    int opts = g_opts.tls || (g_opts.accept_variant && g_opts.resume) ? BIO_SOCK_REUSEADDR : 0;
    BIO_ADDRINFO *res = NULL;
    int fd;

    if (!BIO_lookup_ex(g_opts.val[OPT_HOST], g_opts.val[OPT_PORT], BIO_LOOKUP_SERVER, AF_UNSPEC,
            type, 0, &res))
        return false;
    fd = BIO_socket(BIO_ADDRINFO_family(res), type, 0, 0);
    if (fd != -1
        && !(g_opts.tls ? BIO_listen(fd, BIO_ADDRINFO_address(res), opts)
                        : BIO_bind(fd, BIO_ADDRINFO_address(res), opts))) {
        BIO_closesocket(fd);
        fd = -1;
    }
    BIO_ADDRINFO_free(res);
    srv->addr_len = sizeof(srv->addr);
    if (fd == -1 || getsockname(fd, (struct sockaddr *)&srv->addr, &srv->addr_len) != 0)
        return false;
    srv->fd = fd;
    printf("{\"event\": \"ready\", \"port\": %u}\n",
        ntohs(srv->addr.ss_family == AF_INET6 ? ((struct sockaddr_in6 *)&srv->addr)->sin6_port
                                              : ((struct sockaddr_in *)&srv->addr)->sin_port));
    fflush(stdout);
    return true;
}

/* Default variant: the DTLS listener, which validates new peers itself unless told not to. */
static SSL *new_listener(SSL_CTX *ctx, int fd)
{
    uint64_t flags = SSL_LISTENER_FLAG_SINGLE_THREAD;
    BIO *bio = BIO_new_dgram(fd, BIO_CLOSE);
    SSL *listener;

    if (!g_opts.cookie)
        flags |= SSL_LISTENER_FLAG_NO_VALIDATE;
    listener = SSL_new_listener(ctx, flags);
    if (bio == NULL || listener == NULL)
        return NULL;
    BIO_set_callback_ex(bio, datagram_cb);
    SSL_set_bio(listener, bio, bio);
    if (g_opts.payload > LISTENER_DEFAULT_MAX_DGRAM
        && !SSL_set_generic_value_uint(listener, SSL_VALUE_DTLS_LISTENER_MAX_DGRAM_SIZE,
            (uint64_t)g_opts.payload))
        return NULL;
    return SSL_listen(listener) == 1 ? listener : NULL;
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
    /* The socket stays open until exit, so the old peer's late datagrams never reach a new one. */
    bio = BIO_new_dgram(fd, BIO_NOCLOSE);
    ssl = SSL_new(ctx);
    if (bio == NULL || ssl == NULL)
        return NULL;
    BIO_set_callback_ex(bio, datagram_cb);
    SSL_set_bio(ssl, bio, bio);
    if (g_opts.cookie)
        SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
    return set_mtu(ssl) ? ssl : NULL;
}

/* Bound while the first socket is connected to peer 1: Linux prefers the connected socket for
 * peer 1's datagrams and delivers those of any other peer to this one. */
static int second_socket(const struct server *srv)
{
    int one = 1;
    int fd = socket(srv->addr.ss_family, SOCK_DGRAM, 0);

    if (fd != -1
        && (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0
            || bind(fd, (const struct sockaddr *)&srv->addr, srv->addr_len) != 0)) {
        ERR_raise_data(ERR_LIB_SYS, errno, "binding the second UDP socket");
        close(fd);
        fd = -1;
    }
    return fd;
}

static SSL *accept_tcp(SSL_CTX *ctx, int listen_fd, int *fd)
{
    BIO *bio;
    SSL *ssl;

    g_peer_len = sizeof(g_peer);
    if ((*fd = accept(listen_fd, (struct sockaddr *)&g_peer, &g_peer_len)) < 0) {
        ERR_raise_data(ERR_LIB_SYS, errno, "accepting a TCP connection");
        return NULL;
    }
    bio = BIO_new_socket(*fd, BIO_CLOSE);
    ssl = SSL_new(ctx);
    if (bio == NULL || ssl == NULL)
        return NULL;
    SSL_set_bio(ssl, bio, bio);
    return ssl;
}

/* SSL_stateless() gives 0 after sending the cookie HRR, -1 with an empty error queue for a
 * middlebox-compatibility CCS (tls_get_message_header), 1 once CH2 echoed a valid cookie. */
static int tls_stateless(SSL *conn)
{
    int ret = -1, hrrs = 0;

    for (int i = 0; i < 4; i++) {
        ret = SSL_stateless(conn);
        fprintf(stderr, "SSL_stateless: %d\n", ret);
        if (ret == 1 || (ret == 0 && ++hrrs > 1) || (ret < 0 && ERR_peek_error() != 0))
            break;
    }
    return ret;
}

/* One server lifecycle; *out receives the connection for the result line. */
static int server_connection(SSL_CTX *ctx, struct server *srv, SSL **out)
{
    SSL *conn;
    int fd = -1, ret;
    size_t n;
    char buf[64];

    if (g_opts.tls) {
        conn = accept_tcp(ctx, srv->fd, &fd);
    } else if (g_opts.accept_variant) {
        fd = g_conn == 2 ? srv->second_fd : srv->fd;
        conn = accept_connected(ctx, fd);
        if (conn != NULL && g_conn == 1 && (srv->second_fd = second_socket(srv)) == -1)
            conn = NULL;
    } else {
        conn = SSL_accept_connection(srv->listener, 0);
    }
    *out = conn;
    if (conn == NULL)
        return fail_ssl(NULL, 0, "accepting a connection");
    if (g_opts.tls && g_opts.cookie && (ret = tls_stateless(conn)) != 1)
        return fail_ssl(conn, ret, ret == 0 ? "stateless HRR: cookie not echoed" : "stateless HRR");
    if ((ret = ssl_io(conn, fd, IO_ACCEPT, NULL, 0, NULL)) != 1)
        return fail_ssl(conn, ret, "handshake");
    fprintf(stderr, "handshake done: %s %s resumed=%d\n", SSL_get_version(conn),
        SSL_get0_group_name(conn), SSL_session_reused(conn));

    if ((ret = ssl_io(conn, fd, IO_READ, buf, sizeof(buf), &n)) != 1)
        return fail_ssl(conn, ret, "reading ping");
    if (n != 4 || memcmp(buf, "ping", 4) != 0)
        return fail_msg(EXIT_FAIL, conn, "unexpected message (%zu bytes)", n);
    if ((ret = ssl_io(conn, fd, IO_WRITE, "pong", 4, &n)) != 1)
        return fail_ssl(conn, ret, "writing pong");
    await_close_notify(conn, fd, false);
    if (ssl_io(conn, fd, IO_SHUTDOWN, NULL, 0, NULL) < 0)
        fprintf(stderr, "teardown: sending close_notify failed\n");
    ERR_clear_error();
    return EXIT_OK;
}

static int run_server(SSL_CTX *ctx)
{
    struct server srv = { .fd = -1, .second_fd = -1 };
    int last = g_opts.resume ? 2 : 1, rc = EXIT_OK;
    SSL *probe, *conn;

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
    if (g_opts.accept_variant || (g_opts.tls && g_opts.cookie)) {
        if (RAND_bytes(g_cookie_key, sizeof(g_cookie_key)) != 1)
            return fail_ssl(NULL, 0, "generating cookie key");
        SSL_CTX_set_stateless_cookie_generate_cb(ctx, gen_cookie_cb);
        SSL_CTX_set_stateless_cookie_verify_cb(ctx, verify_cookie_cb);
    }

    if (!bind_server_socket(&srv))
        return fail_ssl(NULL, 0, g_opts.tls ? "listening on TCP socket" : "binding UDP socket");
    if (!g_opts.tls && !g_opts.accept_variant && (srv.listener = new_listener(ctx, srv.fd)) == NULL)
        return fail_ssl(NULL, 0, "starting the DTLS listener");
    /* Both connections come from the same SSL_CTX, whose ticket key decrypts the ticket. */
    for (int i = 1; i <= last; i++) {
        g_conn = g_opts.resume ? i : 0;
        if ((rc = server_connection(ctx, &srv, &conn)) != EXIT_OK)
            return rc;
        if (i == last)
            rc = finish(EXIT_OK, conn, true, NULL);
        SSL_free(conn);
    }
    SSL_free(srv.listener);
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
        "       run --role=server --variant=default|accept --host=HOST --port=PORT\n"
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

    /* Exact names only: getopt_long would also accept abbreviations such as --group. */
    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i], *eq = strchr(arg, '=');
        size_t len;

        if (strncmp(arg, "--", 2) != 0)
            return usage("unexpected argument %s", arg);
        len = (eq != NULL ? (size_t)(eq - arg) : strlen(arg)) - 2;
        for (c = 0; c < OPT_COUNT; c++)
            if (strlen(OPT_NAMES[c]) == len && strncmp(arg + 2, OPT_NAMES[c], len) == 0)
                break;
        if (c == OPT_COUNT)
            return usage("unknown option %s", arg);
        if (eq == NULL && i + 1 == argc)
            return usage("missing value for %s", arg);
        if (g_opts.val[c] != NULL)
            return usage("--%s given twice", OPT_NAMES[c]);
        g_opts.val[c] = eq != NULL ? eq + 1 : argv[++i];
    }
    if ((v = g_opts.val[OPT_ROLE]) == NULL || (strcmp(v, "client") != 0 && strcmp(v, "server") != 0))
        return usage("--role must be client or server", NULL);
    g_opts.server = strcmp(v, "server") == 0;
    allowed = g_opts.server ? SERVER_OPT : CLIENT_OPT;
    for (int i = 0; i < OPT_COUNT; i++) {
        if (allowed[i] && g_opts.val[i] == NULL)
            return usage("--%s is required", OPT_NAMES[i]);
        if (!allowed[i] && g_opts.val[i] != NULL)
            return usage("--%s is not an option of this role", OPT_NAMES[i]);
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
    v = g_opts.val[OPT_TRANSPORT];
    if (strcmp(v, "dtls") != 0 && strcmp(v, "tls") != 0)
        return usage("--transport must be dtls or tls", NULL);
    g_opts.tls = strcmp(v, "tls") == 0;
    v = g_opts.val[OPT_RESUME];
    if (strcmp(v, "off") != 0 && strcmp(v, "ticket") != 0)
        return usage("--resume must be off or ticket", NULL);
    g_opts.resume = strcmp(v, "ticket") == 0;
    /* A byte stream has no datagram size to configure. */
    if (g_opts.tls && strcmp(g_opts.val[OPT_MTU], "default") != 0)
        return usage("--mtu=%s: only default is valid with --transport=tls", g_opts.val[OPT_MTU]);
    if (strcmp(g_opts.val[OPT_MTU], "default") != 0) {
        errno = 0;
        g_opts.mtu = strtol(g_opts.val[OPT_MTU], &end, 10);
        if (errno != 0 || *end != '\0' || g_opts.mtu <= IP_UDP_OVERHEAD)
            return usage("--mtu=%s must be default or an integer above 48", g_opts.val[OPT_MTU]);
        g_opts.payload = g_opts.mtu - IP_UDP_OVERHEAD;
    }
    for (int i = OPT_CA; i < OPT_COUNT; i++) {
        if (g_opts.val[i] != NULL && *g_opts.val[i] == '\0')
            return usage("--%s must not be empty", OPT_NAMES[i]);
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
    int rc, version;

    /* Before parsing: usage errors also print a result line. */
    g_hrr_idx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    if ((rc = parse_options(argc, argv)) != EXIT_OK)
        return rc;
    /* Ignore any system openssl.cnf so runs depend only on the pinned build and these flags. */
    if (!OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG, NULL) || g_hrr_idx < 0)
        return fail_ssl(NULL, 0, "OPENSSL_init_ssl");
    g_conn = g_opts.resume ? 1 : 0;
    fprintf(stderr,
        "%s, role=%s variant=%s transport=%s resume=%s groups=%s mtu=%s key-share=%s validate=%s\n",
        OpenSSL_version(OPENSSL_VERSION), g_opts.val[OPT_ROLE], g_opts.val[OPT_VARIANT],
        g_opts.val[OPT_TRANSPORT], g_opts.val[OPT_RESUME], g_opts.val[OPT_GROUPS],
        g_opts.val[OPT_MTU],
        g_opts.server ? "-" : g_opts.val[OPT_KEY_SHARE],
        g_opts.server ? g_opts.val[OPT_VALIDATE] : "-");

    /* tls_construct_ctos_key_share() fails with NO_SUITABLE_KEY_SHARE when no share is added. */
    if (!g_opts.server && strcmp(g_opts.val[OPT_KEY_SHARE], "empty") == 0)
        return fail_msg(EXIT_UNSUPPORTED, NULL,
            "OpenSSL clients always send at least one key share; empty key_share not possible");

    if (g_opts.tls && g_opts.accept_variant)
        return fail_msg(EXIT_UNSUPPORTED, NULL,
            "--variant=accept is a connected-UDP-socket code path; DTLS only, not --transport=tls");

    if (g_opts.tls)
        ctx = SSL_CTX_new(g_opts.server ? TLS_server_method() : TLS_client_method());
    else
        ctx = SSL_CTX_new(g_opts.server ? DTLS_server_method() : DTLS_client_method());
    version = g_opts.tls ? TLS1_3_VERSION : DTLS1_3_VERSION;
    if (ctx == NULL || !SSL_CTX_set_min_proto_version(ctx, version)
        || !SSL_CTX_set_max_proto_version(ctx, version))
        return fail_ssl(NULL, 0, g_opts.tls ? "creating TLS 1.3 context" : "creating DTLS 1.3 context");
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
