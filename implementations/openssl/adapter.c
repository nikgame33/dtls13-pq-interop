/* DTLS 1.3 interop adapter for OpenSSL, implementing docs/shim-interface.md. */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

enum { EXIT_OK = 0, EXIT_FAIL = 1, EXIT_UNSUPPORTED = 2 };

#define SERVER_NAME "localhost"
#define TICKET_KEYS_LEN 80
#define MAX_GROUPS 16
#define LINGER_SECONDS 2

struct options {
    const char *role;
    const char *host;
    const char *port;
    const char *groups;
    const char *key_share;
    const char *validate;
    const char *cert;
    const char *key;
    const char *ca;
    const char *psk_in;
    const char *psk_out;
    long mtu;
};

static const struct options *g_opts;
static int g_hrr_idx = -1;
static bool g_session_saved;

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

static bool hrr_seen(SSL *ssl)
{
    return ssl != NULL && SSL_get_ex_data(ssl, g_hrr_idx) != NULL;
}

/* Emits the result line and returns `code` so callers can `return finish(...)`. */
static int finish(int code, SSL *ssl, bool handshake_done, const char *error)
{
    printf("{\"event\": \"result\", \"ok\": %s, \"version\": ", code == EXIT_OK ? "true" : "false");
    json_string(handshake_done ? SSL_get_version(ssl) : NULL);
    fputs(", \"group\": ", stdout);
    json_string(handshake_done ? iana_group_name(SSL_get0_group_name(ssl)) : NULL);
    fputs(", \"hrr\": ", stdout);
    fputs(code == EXIT_UNSUPPORTED || ssl == NULL ? "null" : hrr_seen(ssl) ? "true" : "false", stdout);
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

/* DTLS handshake buffers start with the 12-byte header; HRR is a ServerHello with a fixed random. */
static void msg_cb(int write_p, int version, int content_type, const void *buf, size_t len,
    SSL *ssl, void *arg)
{
    const unsigned char *p = buf;
    bool hrr;

    (void)version;
    (void)arg;
    /* Plaintext (epoch 0) record headers show how ClientHello and ServerHello were fragmented. */
    if (content_type == SSL3_RT_HEADER && len == DTLS1_RT_HEADER_LENGTH
        && p[0] == SSL3_RT_HANDSHAKE) {
        fprintf(stderr, "%s plaintext handshake record (%d bytes)\n", write_p ? ">>" : "<<",
            (p[11] << 8) | p[12]);
        return;
    }
    if (content_type == SSL3_RT_ACK) {
        fprintf(stderr, "%s ACK (%zu bytes)\n", write_p ? ">>" : "<<", len);
        return;
    }
    if (content_type == SSL3_RT_ALERT && len == 2) {
        fprintf(stderr, "%s alert %s\n", write_p ? ">>" : "<<",
            SSL_alert_desc_string_long(p[1]));
        return;
    }
    if (content_type != SSL3_RT_HANDSHAKE || len < 1)
        return;
    hrr = p[0] == SSL3_MT_SERVER_HELLO && len >= DTLS1_HM_HEADER_LENGTH + 2 + sizeof(HRR_RANDOM)
        && memcmp(p + DTLS1_HM_HEADER_LENGTH + 2, HRR_RANDOM, sizeof(HRR_RANDOM)) == 0;
    if (hrr)
        SSL_set_ex_data(ssl, g_hrr_idx, (void *)1);
    fprintf(stderr, "%s %s (%zu bytes)\n", write_p ? ">>" : "<<",
        hrr ? "HelloRetryRequest" : hs_name(p[0]), len);
}

/* Listener connections are created internally, so per-connection MTU is set once CH1 arrives. */
static int client_hello_cb(SSL *ssl, int *alert, void *arg)
{
    (void)arg;
    if (g_opts->mtu > 0) {
        SSL_set_options(ssl, SSL_OP_NO_QUERY_MTU);
        if (!SSL_set_mtu(ssl, g_opts->mtu)) {
            *alert = SSL_AD_INTERNAL_ERROR;
            return SSL_CLIENT_HELLO_ERROR;
        }
    }
    return SSL_CLIENT_HELLO_SUCCESS;
}

static int new_session_cb(SSL *ssl, SSL_SESSION *sess)
{
    FILE *f = fopen(g_opts->psk_out, "w");

    (void)ssl;
    if (f == NULL || !PEM_write_SSL_SESSION(f, sess)) {
        fprintf(stderr, "error: cannot write session to %s\n", g_opts->psk_out);
    } else {
        g_session_saved = true;
        fprintf(stderr, "session ticket saved to %s\n", g_opts->psk_out);
    }
    if (f != NULL)
        fclose(f);
    return 0;
}

/* Rejects groups this build lacks (exit 2) and sets the OpenSSL group list.
 * Returns EXIT_OK, or the exit code after emitting a result line. */
static int configure_groups(SSL_CTX *ctx, bool server)
{
    char *names[MAX_GROUPS];
    size_t n = 0;
    char list[1024] = "";
    char *copy = strdup(g_opts->groups);
    STACK_OF(OPENSSL_CSTRING) *impl = sk_OPENSSL_CSTRING_new_null();
    bool share_found = false;
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
        if (n == MAX_GROUPS) {
            rc = fail_msg(EXIT_FAIL, NULL, "too many groups");
            goto out;
        }
        names[n++] = tok;
    }
    for (size_t i = 0; i < n; i++) {
        /* Server: one tuple per group, so the first mutually supported group wins (via HRR). */
        const char *sep = i == 0 ? "" : server ? "/" : ":";
        bool share = !server && g_opts->key_share != NULL
            && strcasecmp(names[i], g_opts->key_share) == 0;

        share_found = share_found || share;
        if (strlen(list) + strlen(sep) + strlen(names[i]) + 2 >= sizeof(list)) {
            rc = fail_msg(EXIT_FAIL, NULL, "group list too long");
            goto out;
        }
        strcat(list, sep);
        strcat(list, share ? "*" : "");
        strcat(list, names[i]);
    }
    if (!server && g_opts->key_share != NULL && !share_found) {
        rc = fail_msg(EXIT_FAIL, NULL, "--key-share %s is not in --groups", g_opts->key_share);
        goto out;
    }
    fprintf(stderr, "groups list: %s\n", list);
    if (!SSL_CTX_set1_groups_list(ctx, list))
        rc = fail_ssl(NULL, 0, "SSL_CTX_set1_groups_list");
    else if (server)
        SSL_CTX_set_options(ctx, SSL_OP_SERVER_PREFERENCE);
out:
    sk_OPENSSL_CSTRING_free(impl);
    free(copy);
    return rc;
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

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if (!SSL_CTX_load_verify_locations(ctx, g_opts->ca, NULL))
        return fail_ssl(NULL, 0, "loading --ca");
    if (g_opts->psk_out != NULL) {
        SSL_CTX_set_session_cache_mode(ctx,
            SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
        SSL_CTX_sess_set_new_cb(ctx, new_session_cb);
    }

    if (!BIO_lookup_ex(g_opts->host, g_opts->port, BIO_LOOKUP_CLIENT, AF_UNSPEC, SOCK_DGRAM, 0,
            &res))
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
    SSL_set_bio(ssl, bio, bio);
    if (g_opts->mtu > 0) {
        SSL_set_options(ssl, SSL_OP_NO_QUERY_MTU);
        if (!SSL_set_mtu(ssl, g_opts->mtu))
            return fail_msg(EXIT_UNSUPPORTED, NULL, "--mtu %ld rejected by SSL_set_mtu", g_opts->mtu);
    }
    if (!SSL_set1_dnsname(ssl, SERVER_NAME) || !SSL_set_tlsext_host_name(ssl, SERVER_NAME))
        return fail_ssl(ssl, 0, "setting server name");
    if (g_opts->psk_in != NULL) {
        FILE *f = fopen(g_opts->psk_in, "r");
        SSL_SESSION *sess = f != NULL ? PEM_read_SSL_SESSION(f, NULL, NULL, NULL) : NULL;

        if (f != NULL)
            fclose(f);
        if (sess == NULL || !SSL_set_session(ssl, sess))
            return fail_msg(EXIT_FAIL, ssl, "cannot load session from %s", g_opts->psk_in);
        SSL_SESSION_free(sess);
    }

    if ((ret = SSL_connect(ssl)) != 1)
        return fail_ssl(ssl, ret, "handshake");
    fprintf(stderr, "handshake done: %s %s resumed=%d\n", SSL_get_version(ssl),
        SSL_get0_group_name(ssl), SSL_session_reused(ssl));

    if ((ret = SSL_write_ex(ssl, "ping", 4, &n)) != 1)
        return fail_ssl(ssl, ret, "writing ping");
    if ((ret = SSL_read_ex(ssl, buf, sizeof(buf), &n)) != 1)
        return fail_ssl(ssl, ret, "reading pong");
    if (n != 4 || memcmp(buf, "pong", 4) != 0)
        return fail_msg(EXIT_FAIL, ssl, "unexpected echo (%zu bytes)", n);
    if (g_opts->psk_out != NULL && !g_session_saved)
        return fail_msg(EXIT_FAIL, ssl, "no session ticket received for --psk-out");
    /* The server may already be gone; close_notify is best effort. */
    SSL_shutdown(ssl);
    ERR_clear_error();
    rc = finish(EXIT_OK, ssl, true, NULL);
    SSL_free(ssl);
    return rc;
}

static int ticket_keys(SSL_CTX *ctx)
{
    unsigned char keys[TICKET_KEYS_LEN];
    FILE *f;

    if (g_opts->psk_in != NULL) {
        f = fopen(g_opts->psk_in, "rb");
        if (f == NULL || fread(keys, 1, sizeof(keys), f) != sizeof(keys)
            || !SSL_CTX_set_tlsext_ticket_keys(ctx, keys, sizeof(keys))) {
            if (f != NULL)
                fclose(f);
            return fail_msg(EXIT_FAIL, NULL, "cannot load ticket keys from %s", g_opts->psk_in);
        }
        fclose(f);
    }
    if (g_opts->psk_out != NULL) {
        f = fopen(g_opts->psk_out, "wb");
        if (f == NULL || !SSL_CTX_get_tlsext_ticket_keys(ctx, keys, sizeof(keys))
            || fwrite(keys, 1, sizeof(keys), f) != sizeof(keys)) {
            if (f != NULL)
                fclose(f);
            return fail_msg(EXIT_FAIL, NULL, "cannot write ticket keys to %s", g_opts->psk_out);
        }
        fclose(f);
    }
    return EXIT_OK;
}

/* Exiting early makes the client's ticket ACKs hit a closed port; Linux reports that ICMP error
 * before queued data, losing the pong. Before our close_notify: DTLS drops records after it. */
static void linger_for_close_notify(SSL *conn)
{
    SSL_POLL_ITEM item = { .desc = SSL_as_poll_descriptor(conn), .events = SSL_POLL_EVENT_R };
    struct timeval timeout = { .tv_sec = LINGER_SECONDS };
    char buf[64];
    size_t n, ready;
    int ret, err;

    if (!SSL_set_blocking_mode(conn, 0))
        return;
    for (;;) {
        ret = SSL_read_ex(conn, buf, sizeof(buf), &n);
        err = SSL_get_error(conn, ret);
        if (ret == 1 || err == SSL_ERROR_WANT_WRITE)
            continue;
        if (err == SSL_ERROR_ZERO_RETURN)
            break;
        if (err != SSL_ERROR_WANT_READ) {
            fprintf(stderr, "waiting for close_notify: SSL_get_error=%d\n", err);
            ERR_print_errors_fp(stderr);
            break;
        }
        if (!SSL_poll(&item, 1, sizeof(item), &timeout, 0, &ready) || ready == 0) {
            fprintf(stderr, "no close_notify from client within %ds\n", LINGER_SECONDS);
            break;
        }
    }
    ERR_clear_error();
}

static int run_server(SSL_CTX *ctx)
{
    BIO_ADDRINFO *res = NULL;
    uint64_t flags = SSL_LISTENER_FLAG_SINGLE_THREAD;
    SSL *probe, *listener, *conn;
    int fd, ret, rc;
    BIO *bio;
    size_t n;
    char buf[64];

    if (SSL_CTX_use_certificate_chain_file(ctx, g_opts->cert) != 1
        || SSL_CTX_use_PrivateKey_file(ctx, g_opts->key, SSL_FILETYPE_PEM) != 1
        || SSL_CTX_check_private_key(ctx) != 1)
        return fail_ssl(NULL, 0, "loading --cert/--key");
    if ((rc = ticket_keys(ctx)) != EXIT_OK)
        return rc;
    /* Reject an MTU the library refuses before announcing readiness. */
    probe = SSL_new(ctx);
    if (probe == NULL || (g_opts->mtu > 0 && !SSL_set_mtu(probe, g_opts->mtu)))
        return fail_msg(EXIT_UNSUPPORTED, NULL, "--mtu %ld rejected by SSL_set_mtu", g_opts->mtu);
    SSL_free(probe);
    SSL_CTX_set_client_hello_cb(ctx, client_hello_cb, NULL);

    if (strcmp(g_opts->validate, "off") == 0)
        flags |= SSL_LISTENER_FLAG_NO_VALIDATE;
    if (!BIO_lookup_ex(g_opts->host, g_opts->port, BIO_LOOKUP_SERVER, AF_UNSPEC, SOCK_DGRAM, 0,
            &res))
        return fail_ssl(NULL, 0, "resolving --host");
    fd = BIO_socket(BIO_ADDRINFO_family(res), SOCK_DGRAM, 0, 0);
    if (fd == -1 || !BIO_bind(fd, BIO_ADDRINFO_address(res), 0)) {
        BIO_ADDRINFO_free(res);
        return fail_ssl(NULL, 0, "binding UDP socket");
    }
    BIO_ADDRINFO_free(res);

    bio = BIO_new_dgram(fd, BIO_CLOSE);
    listener = SSL_new_listener(ctx, flags);
    if (bio == NULL || listener == NULL)
        return fail_ssl(NULL, 0, "creating DTLS listener");
    SSL_set_bio(listener, bio, bio);
    if (g_opts->mtu > 2000
        && !SSL_set_generic_value_uint(listener, SSL_VALUE_DTLS_LISTENER_MAX_DGRAM_SIZE,
            (uint64_t)g_opts->mtu))
        return fail_ssl(NULL, 0, "raising listener datagram size");
    if (SSL_listen(listener) != 1)
        return fail_ssl(NULL, 0, "SSL_listen");
    puts("{\"event\": \"ready\"}");
    fflush(stdout);

    conn = SSL_accept_connection(listener, 0);
    if (conn == NULL)
        return fail_ssl(NULL, 0, "SSL_accept_connection");
    if ((ret = SSL_accept(conn)) != 1)
        return fail_ssl(conn, ret, "handshake");
    fprintf(stderr, "handshake done: %s %s resumed=%d\n", SSL_get_version(conn),
        SSL_get0_group_name(conn), SSL_session_reused(conn));

    if ((ret = SSL_read_ex(conn, buf, sizeof(buf), &n)) != 1)
        return fail_ssl(conn, ret, "reading ping");
    if (n != 4 || memcmp(buf, "ping", 4) != 0)
        return fail_msg(EXIT_FAIL, conn, "unexpected message (%zu bytes)", n);
    if ((ret = SSL_write_ex(conn, "pong", 4, &n)) != 1)
        return fail_ssl(conn, ret, "writing pong");
    linger_for_close_notify(conn);
    SSL_shutdown(conn);
    ERR_clear_error();
    rc = finish(EXIT_OK, conn, true, NULL);
    SSL_free(conn);
    SSL_free(listener);
    return rc;
}

static int usage(const char *msg)
{
    fprintf(stderr,
        "usage: run --role client|server --host HOST --port PORT --groups G1[,G2...]\n"
        "           [--key-share GROUP|empty] [--mtu N] [--validate off|cookie]\n"
        "           [--cert FILE] [--key FILE] [--ca FILE] [--psk-in FILE] [--psk-out FILE]\n");
    return fail_msg(EXIT_FAIL, NULL, "usage: %s", msg);
}

int main(int argc, char **argv)
{
    static const struct option longopts[] = {
        { "role", required_argument, NULL, 'r' },
        { "host", required_argument, NULL, 'h' },
        { "port", required_argument, NULL, 'p' },
        { "groups", required_argument, NULL, 'g' },
        { "key-share", required_argument, NULL, 's' },
        { "mtu", required_argument, NULL, 'm' },
        { "validate", required_argument, NULL, 'v' },
        { "cert", required_argument, NULL, 'c' },
        { "key", required_argument, NULL, 'k' },
        { "ca", required_argument, NULL, 'a' },
        { "psk-in", required_argument, NULL, 'i' },
        { "psk-out", required_argument, NULL, 'o' },
        { NULL, 0, NULL, 0 },
    };
    struct options o = { .validate = "off" };
    bool server;
    SSL_CTX *ctx;
    char *end;
    int c, rc;

    g_opts = &o;
    while ((c = getopt_long(argc, argv, "", longopts, NULL)) != -1) {
        switch (c) {
        case 'r': o.role = optarg; break;
        case 'h': o.host = optarg; break;
        case 'p': o.port = optarg; break;
        case 'g': o.groups = optarg; break;
        case 's': o.key_share = optarg; break;
        case 'v': o.validate = optarg; break;
        case 'c': o.cert = optarg; break;
        case 'k': o.key = optarg; break;
        case 'a': o.ca = optarg; break;
        case 'i': o.psk_in = optarg; break;
        case 'o': o.psk_out = optarg; break;
        case 'm':
            o.mtu = strtol(optarg, &end, 10);
            if (*end != '\0' || o.mtu <= 0)
                return usage("--mtu must be a positive integer");
            break;
        default: return usage("unknown option");
        }
    }
    if (optind != argc || o.role == NULL || o.host == NULL || o.port == NULL || o.groups == NULL)
        return usage("--role, --host, --port and --groups are required");
    if (strcmp(o.role, "client") != 0 && strcmp(o.role, "server") != 0)
        return usage("--role must be client or server");
    server = strcmp(o.role, "server") == 0;
    if (strcmp(o.validate, "off") != 0 && strcmp(o.validate, "cookie") != 0)
        return usage("--validate must be off or cookie");
    if (server ? o.cert == NULL || o.key == NULL : o.ca == NULL)
        return usage(server ? "server needs --cert and --key" : "client needs --ca");

    /* Ignore any system openssl.cnf so runs depend only on the pinned build and these flags. */
    if (!OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG, NULL))
        return fail_ssl(NULL, 0, "OPENSSL_init_ssl");
    fprintf(stderr, "%s, role=%s groups=%s key-share=%s mtu=%ld validate=%s\n",
        OpenSSL_version(OPENSSL_VERSION), o.role, o.groups, o.key_share ? o.key_share : "(default)",
        o.mtu, o.validate);

    /* tls_construct_ctos_key_share() fails with NO_SUITABLE_KEY_SHARE when no share is added. */
    if (!server && o.key_share != NULL && strcmp(o.key_share, "empty") == 0)
        return fail_msg(EXIT_UNSUPPORTED, NULL,
            "OpenSSL clients always send at least one key share; empty key_share not possible");

    g_hrr_idx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    ctx = SSL_CTX_new(server ? DTLS_server_method() : DTLS_client_method());
    if (ctx == NULL || g_hrr_idx < 0 || !SSL_CTX_set_min_proto_version(ctx, DTLS1_3_VERSION)
        || !SSL_CTX_set_max_proto_version(ctx, DTLS1_3_VERSION))
        return fail_ssl(NULL, 0, "creating DTLS 1.3 context");
    SSL_CTX_set_msg_callback(ctx, msg_cb);
    if ((rc = configure_groups(ctx, server)) != EXIT_OK)
        return rc;

    rc = server ? run_server(ctx) : run_client(ctx);
    SSL_CTX_free(ctx);
    return rc;
}
