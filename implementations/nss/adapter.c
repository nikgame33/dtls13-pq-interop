/* DTLS 1.3 (and TLS 1.3) interop adapter for NSS, implementing docs/shim-interface.md. */
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
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

#include <base64.h>
#include <cert.h>
#include <nss.h>
#include <pk11pub.h>
#include <prerror.h>
#include <prinit.h>
#include <prio.h>
#include <private/pprio.h>
#include <secerr.h>
#include <ssl.h>
#include <sslerr.h>
#include <sslexp.h>
#include <sslproto.h>

enum { EXIT_OK = 0, EXIT_FAIL = 1, EXIT_UNSUPPORTED = 2, EXIT_USAGE = 64 };

#define SERVER_NAME "localhost"
#define MAX_GROUPS 16
#define TEARDOWN_MS 2000
#define HANDSHAKE_MS 60000
/* --mtu is the IP path MTU; the contract reserves IPv6 + UDP headers for every address family. */
#define IP_UDP_OVERHEAD 48
/* NSS has no MTU API. Its estimate starts at 1472 (dtlscon.c COMMON_MTU_VALUES) and a datagram
 * holds at most estimate - DTLS_MAX_EXPANSION (77) - 12 + 34 bytes of ciphertext record. */
#define NSS_MTU_PLATEAU 1472
#define NSS_MAX_DATAGRAM (NSS_MTU_PLATEAU - 55)
#define MAX_MESSAGES 8

enum { HRR_SEEN = 1, HRR_COOKIE = 2, HRR_GROUP = 4 };

enum { OPT_ROLE, OPT_VARIANT, OPT_HOST, OPT_PORT, OPT_GROUPS, OPT_TRANSPORT, OPT_RESUME, OPT_MTU,
    OPT_CA, OPT_KEY_SHARE, OPT_VALIDATE, OPT_CERT, OPT_KEY, OPT_COUNT };

static const struct option LONGOPTS[] = {
    { "role", required_argument, NULL, OPT_ROLE },
    { "variant", required_argument, NULL, OPT_VARIANT },
    { "host", required_argument, NULL, OPT_HOST },
    { "port", required_argument, NULL, OPT_PORT },
    { "groups", required_argument, NULL, OPT_GROUPS },
    { "transport", required_argument, NULL, OPT_TRANSPORT },
    { "resume", required_argument, NULL, OPT_RESUME },
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
    [OPT_GROUPS] = true, [OPT_TRANSPORT] = true, [OPT_RESUME] = true, [OPT_MTU] = true, [OPT_CA] = true, [OPT_KEY_SHARE] = true,
};
static const bool SERVER_OPT[OPT_COUNT] = {
    [OPT_ROLE] = true, [OPT_VARIANT] = true, [OPT_HOST] = true, [OPT_PORT] = true,
    [OPT_GROUPS] = true, [OPT_TRANSPORT] = true, [OPT_RESUME] = true, [OPT_MTU] = true, [OPT_CA] = true, [OPT_VALIDATE] = true,
    [OPT_CERT] = true, [OPT_KEY] = true,
};

/* IANA names of the groups NSS 3.134 implements (lib/ssl/sslt.h, sslsock.c ssl_named_groups). */
static const struct {
    const char *name;
    SSLNamedGroup id;
} GROUPS[] = {
    { "X25519", ssl_grp_ec_curve25519 },
    { "secp256r1", ssl_grp_ec_secp256r1 },
    { "secp384r1", ssl_grp_ec_secp384r1 },
    { "secp521r1", ssl_grp_ec_secp521r1 },
    { "X25519MLKEM768", ssl_grp_kem_mlkem768x25519 },
    { "SecP256r1MLKEM768", ssl_grp_kem_secp256r1mlkem768 },
    { "SecP384r1MLKEM1024", ssl_grp_kem_secp384r1mlkem1024 },
    { "MLKEM1024", ssl_grp_kem_mlkem1024 },
    { "ffdhe2048", ssl_grp_ffdhe_2048 },
    { "ffdhe3072", ssl_grp_ffdhe_3072 },
    { "ffdhe4096", ssl_grp_ffdhe_4096 },
    { "ffdhe6144", ssl_grp_ffdhe_6144 },
    { "ffdhe8192", ssl_grp_ffdhe_8192 },
};

struct options {
    const char *val[OPT_COUNT];
    bool server;
    bool tls; /* --transport=tls: TLS 1.3 over TCP */
    bool resume; /* --resume=ticket: a second connection resumes the first */
    bool cookie;
    long mtu;
    long payload; /* largest UDP payload: mtu - IP_UDP_OVERHEAD, or 0 for --mtu=default */
    SSLNamedGroup groups[MAX_GROUPS];
    unsigned ngroups;
};

/* A handshake message being reassembled from the plaintext records the IO layer sees. */
struct message {
    bool used, done, sent;
    unsigned type, seq;
    size_t len, got;
    unsigned char *buf, *have;
};

static struct options g_opts;
static PRFileDesc *g_ssl;
static bool g_started;
static int g_hrr;
static long g_oversize;
static PRErrorCode g_cert_error;
static struct message g_msgs[MAX_MESSAGES];
static CERTCertList *g_anchors;
static struct sockaddr_storage g_peer;
static socklen_t g_peer_len;
static int g_conn; /* connection number for error prefixes; 0 with --resume=off */
static PRUint8 *g_token; /* client: the latest resumption token (NewSessionTicket) */
static unsigned g_token_len;

/* TLS: unparsed record bytes and handshake bytes per direction (0 received, 1 sent). */
static struct stream {
    unsigned char *rec, *hs;
    size_t rlen, hlen;
} g_streams[2];

/* SHA-256("HelloRetryRequest"), RFC 9846 section 4.2.3. */
static const unsigned char HRR_RANDOM[32] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
};

static const char *group_name(unsigned id)
{
    for (size_t i = 0; i < sizeof(GROUPS) / sizeof(GROUPS[0]); i++)
        if (GROUPS[i].id == id)
            return GROUPS[i].name;
    return NULL;
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
static int finish(int code, bool handshake_done, const char *error)
{
    SSLChannelInfo info;
    char unknown[16], prefixed[320];
    const char *version = NULL, *group = NULL;
    bool known = g_started && code != EXIT_UNSUPPORTED && code != EXIT_USAGE, resumed = false;

    if (error != NULL && g_conn > 0) {
        snprintf(prefixed, sizeof(prefixed), "connection %d: %s", g_conn, error);
        error = prefixed;
    }
    if (handshake_done && SSL_GetChannelInfo(g_ssl, &info, sizeof(info)) == SECSuccess) {
        if (info.protocolVersion == SSL_LIBRARY_VERSION_TLS_1_3)
            version = g_opts.tls ? "TLSv1.3" : "DTLSv1.3";
        else
            version = g_opts.tls ? "TLS<1.3" : "DTLS<1.3";
        resumed = info.resumed;
        snprintf(unknown, sizeof(unknown), "0x%04x", (unsigned)info.keaGroup);
        group = group_name(info.keaGroup) != NULL ? group_name(info.keaGroup) : unknown;
    }
    printf("{\"event\": \"result\", \"ok\": %s, \"version\": ", code == EXIT_OK ? "true" : "false");
    json_string(version);
    fputs(", \"group\": ", stdout);
    json_string(group);
    fputs(", \"hrr\": ", stdout);
    json_bool(known, g_hrr & HRR_SEEN);
    fputs(", \"hrr_cookie\": ", stdout);
    json_bool(known, g_hrr & HRR_COOKIE);
    fputs(", \"hrr_group\": ", stdout);
    json_bool(known, g_hrr & HRR_GROUP);
    fputs(", \"resumed\": ", stdout);
    json_bool(known, resumed);
    fputs(", \"error\": ", stdout);
    json_string(error);
    puts("}");
    fflush(stdout);
    return code;
}

static int fail_msg(int code, const char *fmt, ...)
{
    char buf[256];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    fprintf(stderr, "error: %s\n", buf);
    return finish(code, false, buf);
}

/* Library failure: the NSPR/NSS error name and text, or the oversize/certificate cause. */
static int fail_nss(const char *what)
{
    PRErrorCode err = PR_GetError();
    const char *name = PR_ErrorToName(err), *text = PR_ErrorToString(err, PR_LANGUAGE_I_DEFAULT);

    if (g_oversize > 0)
        return fail_msg(EXIT_FAIL, "%s: NSS sent a %ld-byte datagram, above the %ld bytes --mtu=%ld allows",
            what, g_oversize, g_opts.payload, g_opts.mtu);
    if (g_cert_error != 0)
        return fail_msg(EXIT_FAIL, "%s: certificate verify failed: %s", what,
            PR_ErrorToName(g_cert_error) != NULL ? PR_ErrorToName(g_cert_error) : "unknown");
    if (name == NULL)
        return fail_msg(EXIT_FAIL, "%s: NSS error %d", what, (int)err);
    return fail_msg(EXIT_FAIL, "%s: %s: %s", what, name, text != NULL ? text : "");
}

static unsigned read_u16(const unsigned char *p)
{
    return (unsigned)p[0] << 8 | p[1];
}

static size_t read_u24(const unsigned char *p)
{
    return (size_t)p[0] << 16 | (size_t)p[1] << 8 | p[2];
}

static const char *hs_name(unsigned type)
{
    switch (type) {
    case 1: return "ClientHello";
    case 2: return "ServerHello";
    case 4: return "NewSessionTicket";
    case 8: return "EncryptedExtensions";
    case 11: return "Certificate";
    case 15: return "CertificateVerify";
    case 20: return "Finished";
    default: return "other";
    }
}

/* Calls fn for each extension of a hello body whose extensions start at off. */
static void each_extension(const unsigned char *p, size_t len, size_t off,
    void (*fn)(unsigned type, const unsigned char *data, size_t n, void *arg), void *arg)
{
    size_t end;

    if (off + 2 > len)
        return;
    end = off + 2 + read_u16(p + off);
    end = end < len ? end : len;
    for (off += 2; off + 4 <= end && off + 4 + read_u16(p + off + 2) <= end;
         off += 4 + read_u16(p + off + 2))
        fn(read_u16(p + off), p + off + 4, read_u16(p + off + 2), arg);
}

static void hrr_extension(unsigned type, const unsigned char *data, size_t n, void *arg)
{
    (void)arg;
    if (type == 44) {
        g_hrr |= HRR_COOKIE;
    } else if (type == 51 && n == 2) {
        g_hrr |= HRR_GROUP;
        fprintf(stderr, "   HelloRetryRequest selected_group %s (0x%04x)\n",
            group_name(read_u16(data)) != NULL ? group_name(read_u16(data)) : "unknown",
            read_u16(data));
    }
}

struct shares {
    SSLNamedGroup groups[MAX_GROUPS * 2];
    unsigned n;
};

static void ch_extension(unsigned type, const unsigned char *data, size_t n, void *arg)
{
    struct shares *s = arg;

    if (type != 51 || n < 2)
        return;
    for (size_t off = 2; off + 4 <= n && s->n < sizeof(s->groups) / sizeof(s->groups[0]);
         off += 4 + read_u16(data + off + 2))
        s->groups[s->n++] = (SSLNamedGroup)read_u16(data + off);
}

static void psk_extension(unsigned type, const unsigned char *data, size_t n, void *arg)
{
    (void)data, (void)n;
    *(bool *)arg |= type == 41;
}

static bool has_share(const struct shares *s, SSLNamedGroup g)
{
    for (unsigned i = 0; i < s->n; i++)
        if (s->groups[i] == g)
            return true;
    return false;
}

/* Contract group rule: NSS takes its first mutual group, so groups the client sent a share for
 * go first (in --groups order); without such a share NSS sends an HRR for its first group. */
/* Offset of a ClientHello's extensions block, or len if it is malformed. */
static size_t ch_extensions(const unsigned char *ch, size_t len)
{
    size_t off = 2 + 32; /* legacy_version, random */

    if (off + 1 > len)
        return len;
    off += 1 + ch[off]; /* legacy_session_id */
    if (off + 1 > len)
        return len;
    if (!g_opts.tls)
        off += 1 + ch[off]; /* DTLS legacy_cookie */
    if (off + 2 > len)
        return len;
    off += 2 + read_u16(ch + off); /* cipher_suites */
    if (off + 1 > len)
        return len;
    return off + 1 + ch[off]; /* legacy_compression_methods */
}

static void order_server_groups(const unsigned char *ch, size_t len)
{
    struct shares shares = { .n = 0 };
    SSLNamedGroup order[MAX_GROUPS];
    unsigned n = 0;
    char list[512] = "";

    each_extension(ch, len, ch_extensions(ch, len), ch_extension, &shares);
    for (int pass = 0; pass < 2; pass++)
        for (unsigned i = 0; i < g_opts.ngroups; i++)
            if (has_share(&shares, g_opts.groups[i]) == (pass == 0))
                order[n++] = g_opts.groups[i];
    for (unsigned i = 0; i < n; i++) {
        strcat(list, i == 0 ? "" : ",");
        strcat(list, group_name(order[i]));
    }
    fprintf(stderr, "   ClientHello has %u key share(s); NSS group order: %s\n", shares.n, list);
    if (SSL_NamedGroupConfig(g_ssl, order, n) != SECSuccess)
        fprintf(stderr, "error: SSL_NamedGroupConfig failed: %s\n", PR_ErrorToName(PR_GetError()));
}

static void on_message(bool sent, unsigned type, const unsigned char *body, size_t len)
{
    const char *dir = sent ? ">>" : "<<";
    bool hrr = type == 2 && len >= 2 + sizeof(HRR_RANDOM)
        && memcmp(body + 2, HRR_RANDOM, sizeof(HRR_RANDOM)) == 0;

    if (hrr) {
        size_t off = 2 + sizeof(HRR_RANDOM);

        g_hrr = HRR_SEEN;
        if (off < len)
            each_extension(body, len, off + 1 + body[off] + 2 + 1, hrr_extension, NULL);
        fprintf(stderr, "%s HelloRetryRequest (%zu bytes, cookie=%d, selected_group=%d)\n", dir,
            len, (g_hrr & HRR_COOKIE) != 0, (g_hrr & HRR_GROUP) != 0);
        return;
    }
    fprintf(stderr, "%s %s (%zu bytes)\n", dir, hs_name(type), len);
    if (type == 1) {
        bool psk = false;

        each_extension(body, len, ch_extensions(body, len), psk_extension, &psk);
        if (psk)
            fprintf(stderr, "   ClientHello offers a PSK (pre_shared_key)\n");
    }
    if (type == 1 && !sent && g_opts.server)
        order_server_groups(body, len);
}

/* Adds one plaintext handshake fragment; a complete message is passed to on_message once. */
static void reassemble(bool sent, unsigned type, unsigned seq, size_t len, size_t foff,
    const unsigned char *frag, size_t flen)
{
    struct message *m = NULL;

    if (foff + flen > len || len > 65536)
        return;
    for (int i = 0; i < MAX_MESSAGES && m == NULL; i++)
        if (g_msgs[i].used && g_msgs[i].sent == sent && g_msgs[i].type == type && g_msgs[i].seq == seq)
            m = &g_msgs[i];
    for (int i = 0; i < MAX_MESSAGES && m == NULL; i++)
        if (!g_msgs[i].used) {
            m = &g_msgs[i];
            *m = (struct message){ .used = true, .sent = sent, .type = type, .seq = seq, .len = len };
            m->buf = calloc(len + 1, 1);
            m->have = calloc(len + 1, 1);
        }
    if (m == NULL || m->done || m->len != len || m->buf == NULL || m->have == NULL)
        return;
    for (size_t i = 0; i < flen; i++)
        if (!m->have[foff + i]) {
            m->have[foff + i] = 1;
            m->buf[foff + i] = frag[i];
            m->got++;
        }
    if (m->got == m->len) {
        m->done = true;
        on_message(sent, type, m->buf, m->len);
        free(m->buf);
        free(m->have);
        m->buf = m->have = NULL;
    }
}

/* Logs the records of one datagram; plaintext handshake fragments go to reassemble(). */
static void inspect(bool sent, const unsigned char *p, size_t n)
{
    const char *dir = sent ? ">>" : "<<";
    size_t off = 0;

    while (off < n) {
        unsigned char t = p[off];
        size_t len, hl;

        if ((t & 0xe0) == 0x20) {
            /* RFC 9147 unified header: C (no CIDs here), S and L bits. */
            if (t & 0x10)
                return;
            hl = 1 + ((t & 0x08) ? 2 : 1) + ((t & 0x04) ? 2 : 0);
            if (off + hl > n)
                return;
            len = (t & 0x04) ? read_u16(p + off + hl - 2) : n - off - hl;
            fprintf(stderr, "%s ciphertext record (%zu bytes)\n", dir, len);
            off += hl + len;
            continue;
        }
        if (off + 13 > n || off + 13 + read_u16(p + off + 11) > n)
            return;
        len = read_u16(p + off + 11);
        if (t == 22) {
            const unsigned char *r = p + off + 13;

            fprintf(stderr, "%s plaintext handshake record (%zu bytes)\n", dir, len);
            for (size_t h = 0; h + 12 <= len && h + 12 + read_u24(r + h + 9) <= len;
                 h += 12 + read_u24(r + h + 9))
                reassemble(sent, r[h], read_u16(r + h + 4), read_u24(r + h + 1),
                    read_u24(r + h + 6), r + h + 12, read_u24(r + h + 9));
        } else {
            fprintf(stderr, "%s plaintext record type %u (%zu bytes)\n", dir, t, len);
        }
        off += 13 + len;
    }
}

/* TLS: logs the records of a byte stream chunk; plaintext handshake messages go to on_message(). */
static void inspect_stream(bool sent, const unsigned char *p, size_t n)
{
    struct stream *s = &g_streams[sent];
    const char *dir = sent ? ">>" : "<<";
    unsigned char *rec = realloc(s->rec, s->rlen + n);
    size_t off = 0;

    if (rec == NULL)
        return;
    s->rec = rec;
    memcpy(s->rec + s->rlen, p, n);
    s->rlen += n;
    while (off + 5 <= s->rlen && off + 5 + read_u16(s->rec + off + 3) <= s->rlen) {
        unsigned char t = s->rec[off];
        size_t len = read_u16(s->rec + off + 3), h = 0;

        if (t == 22) {
            unsigned char *hs = realloc(s->hs, s->hlen + len);

            fprintf(stderr, "%s plaintext handshake record (%zu bytes)\n", dir, len);
            if (hs == NULL)
                return;
            s->hs = hs;
            memcpy(s->hs + s->hlen, s->rec + off + 5, len);
            s->hlen += len;
            for (; h + 4 <= s->hlen && h + 4 + read_u24(s->hs + h + 1) <= s->hlen; h += 4 + read_u24(s->hs + h + 1))
                on_message(sent, s->hs[h], s->hs + h + 4, read_u24(s->hs + h + 1));
            memmove(s->hs, s->hs + h, s->hlen - h);
            s->hlen -= h;
        } else if (t == 23) {
            fprintf(stderr, "%s ciphertext record (%zu bytes)\n", dir, len);
        } else {
            fprintf(stderr, "%s plaintext record type %u (%zu bytes)\n", dir, t, len);
        }
        off += 5 + len;
    }
    memmove(s->rec, s->rec + off, s->rlen - off);
    s->rlen -= off;
}

/* NSPR layer between libssl and the socket: logs, checks --mtu, feeds inspect(). */
static PRInt32 PR_CALLBACK layer_send(PRFileDesc *fd, const void *buf, PRInt32 amount,
    PRIntn flags, PRIntervalTime timeout)
{
    PRInt32 n;

    if (g_opts.payload > 0 && amount > g_opts.payload) {
        fprintf(stderr, ">> refused %d-byte datagram above --mtu=%ld\n", amount, g_opts.mtu);
        g_oversize = amount;
        PR_SetError(PR_BUFFER_OVERFLOW_ERROR, EMSGSIZE);
        return -1;
    }
    n = fd->lower->methods->send(fd->lower, buf, amount, flags, timeout);
    if (n > 0 && g_opts.tls) {
        fprintf(stderr, ">> TCP (%d bytes)\n", n);
        inspect_stream(true, buf, (size_t)n);
    } else if (n > 0) {
        fprintf(stderr, ">> datagram (%d bytes)\n", n);
        inspect(true, buf, (size_t)n);
    }
    return n;
}

static PRInt32 PR_CALLBACK layer_write(PRFileDesc *fd, const void *buf, PRInt32 amount)
{
    return layer_send(fd, buf, amount, 0, PR_INTERVAL_NO_TIMEOUT);
}

static PRInt32 PR_CALLBACK layer_recv(PRFileDesc *fd, void *buf, PRInt32 amount, PRIntn flags,
    PRIntervalTime timeout)
{
    PRInt32 n = fd->lower->methods->recv(fd->lower, buf, amount, flags, timeout);

    if (n > 0 && g_opts.tls) {
        fprintf(stderr, "<< TCP (%d bytes)\n", n);
        inspect_stream(false, buf, (size_t)n);
    } else if (n > 0) {
        fprintf(stderr, "<< datagram (%d bytes)\n", n);
        inspect(false, buf, (size_t)n);
    }
    return n;
}

static PRInt32 PR_CALLBACK layer_read(PRFileDesc *fd, void *buf, PRInt32 amount)
{
    return layer_recv(fd, buf, amount, 0, PR_INTERVAL_NO_TIMEOUT);
}

/* close_notify is sent by libssl; shutdown(2) would only break late ACKs; TCP closes on PR_Close. */
static PRStatus PR_CALLBACK layer_shutdown(PRFileDesc *fd, PRIntn how)
{
    (void)fd, (void)how;
    return PR_SUCCESS;
}

static void PR_CALLBACK alert_cb(const PRFileDesc *fd, void *arg, const SSLAlert *alert)
{
    (void)fd;
    if (alert->description == 0)
        fprintf(stderr, "%s alert close notify\n", arg != NULL ? ">>" : "<<");
    else
        fprintf(stderr, "%s alert %s %u\n", arg != NULL ? ">>" : "<<",
            alert->level == 2 ? "fatal" : "warning", alert->description);
}

/* Client: libssl's own check (chain to a trusted cert, name from SSL_SetURL); only --ca is trusted. */
static SECStatus PR_CALLBACK auth_cert_cb(void *arg, PRFileDesc *fd, PRBool checksig,
    PRBool is_server)
{
    SECStatus rv = SSL_AuthCertificate(arg, fd, checksig, is_server);

    if (rv != SECSuccess) {
        g_cert_error = PR_GetError();
        fprintf(stderr, "certificate verification failed: %s\n", PR_ErrorToName(g_cert_error));
    }
    return rv;
}

/* --validate=cookie: an HRR for every first ClientHello; NSS encrypts and authenticates the
 * token inside its cookie, so the token is just the peer address the cookie must come from. */
static SSLHelloRetryRequestAction PR_CALLBACK hrr_cb(PRBool first, const PRUint8 *token,
    unsigned token_len, PRUint8 *retry, unsigned *retry_len, unsigned retry_max, void *arg)
{
    (void)arg;
    if (first) {
        if (g_peer_len > retry_max)
            return ssl_hello_retry_fail;
        memcpy(retry, &g_peer, g_peer_len);
        *retry_len = g_peer_len;
        return ssl_hello_retry_request;
    }
    if (token_len == g_peer_len && memcmp(token, &g_peer, g_peer_len) == 0)
        return ssl_hello_retry_accept;
    fprintf(stderr, "error: second ClientHello without our cookie token\n");
    return ssl_hello_retry_fail;
}

/* Reads every PEM block labelled label from path into items; returns the count, -1 on error. */
static int read_pem(const char *path, const char *label, SECItem *items, int max)
{
    char begin[64], end[64], *text, *p, *q;
    FILE *f = fopen(path, "rb");
    long size;
    int n = 0;

    if (f == NULL)
        return -1;
    if (fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0
        || (text = calloc((size_t)size + 1, 1)) == NULL) {
        fclose(f);
        return -1;
    }
    if (fread(text, 1, (size_t)size, f) != (size_t)size) {
        fclose(f);
        free(text);
        return -1;
    }
    fclose(f);
    snprintf(begin, sizeof(begin), "-----BEGIN %s-----", label);
    snprintf(end, sizeof(end), "-----END %s-----", label);
    for (p = strstr(text, begin); p != NULL && n < max; p = strstr(q, begin)) {
        p += strlen(begin);
        if ((q = strstr(p, end)) == NULL)
            break;
        *q = '\0';
        items[n] = (SECItem){ siBuffer, NULL, 0 };
        if (ATOB_ConvertAsciiToItem(&items[n], p) != SECSuccess)
            break;
        n++;
        q += strlen(end);
        *(q - strlen(end)) = '-';
    }
    free(text);
    return n;
}

static int load_server_credentials(CERTCertificate **cert, SECKEYPrivateKey **key)
{
    SECItem certs[8], der;
    int n = read_pem(g_opts.val[OPT_CERT], "CERTIFICATE", certs, 8);
    PK11SlotInfo *slot;
    SECStatus rv;

    if (n < 1)
        return fail_msg(EXIT_FAIL, "loading --cert: no PEM certificate in %s", g_opts.val[OPT_CERT]);
    /* Extra certificates become temporary certs, from which NSS builds the sent chain. */
    for (int i = n - 1; i >= 0; i--) {
        CERTCertificate *c = CERT_NewTempCertificate(CERT_GetDefaultCertDB(), &certs[i], NULL,
            PR_FALSE, PR_TRUE);

        SECITEM_FreeItem(&certs[i], PR_FALSE);
        if (c == NULL)
            return fail_nss("loading --cert");
        if (i == 0)
            *cert = c;
    }
    if (read_pem(g_opts.val[OPT_KEY], "PRIVATE KEY", &der, 1) != 1)
        return fail_msg(EXIT_FAIL, "loading --key: no PKCS#8 PEM key in %s", g_opts.val[OPT_KEY]);
    slot = PK11_GetInternalSlot();
    rv = PK11_ImportDERPrivateKeyInfoAndReturnKey(slot, &der, NULL, NULL, PR_FALSE, PR_TRUE,
        KU_ALL, key, NULL);
    PK11_FreeSlot(slot);
    SECITEM_FreeItem(&der, PR_FALSE);
    if (rv != SECSuccess)
        return fail_nss("loading --key");
    return EXIT_OK;
}

static int load_ca(void)
{
    SECItem certs[8];
    int n = read_pem(g_opts.val[OPT_CA], "CERTIFICATE", certs, 8);

    if (n < 1)
        return fail_msg(EXIT_FAIL, "loading --ca: no PEM certificate in %s", g_opts.val[OPT_CA]);
    g_anchors = CERT_NewCertList();
    for (int i = 0; i < n; i++) {
        CERTCertificate *c = CERT_NewTempCertificate(CERT_GetDefaultCertDB(), &certs[i], NULL,
            PR_FALSE, PR_TRUE);

        SECITEM_FreeItem(&certs[i], PR_FALSE);
        CERTCertTrust trust;

        if (c == NULL || CERT_AddCertToListTail(g_anchors, c) != SECSuccess
            || CERT_DecodeTrustString(&trust, "C,,") != SECSuccess
            || CERT_ChangeCertTrust(CERT_GetDefaultCertDB(), c, &trust) != SECSuccess)
            return fail_nss("loading --ca");
    }
    return EXIT_OK;
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

/* Waits for a datagram or NSS's next DTLS timer (retransmission, ACK); false at the deadline. */
static bool wait_io(const struct timespec *deadline)
{
    PRPollDesc pd = { .fd = g_ssl, .in_flags = PR_POLL_READ };
    PRIntervalTime timer;
    long ms = ms_until(deadline);

    if (ms <= 0)
        return false;
    if (DTLS_GetHandshakeTimeout(g_ssl, &timer) == SECSuccess && timer != PR_INTERVAL_NO_TIMEOUT
        && (long)PR_IntervalToMilliseconds(timer) < ms)
        ms = (long)PR_IntervalToMilliseconds(timer);
    PR_Poll(&pd, 1, PR_MillisecondsToInterval((PRUint32)ms));
    return true;
}

/* Returns bytes read, 0 on close_notify, -1 on error, -2 at the deadline. */
static int read_record(char *buf, int size, long ms)
{
    struct timespec deadline = deadline_in(ms);

    for (;;) {
        PRInt32 n = PR_Recv(g_ssl, buf, size, 0, PR_INTERVAL_NO_WAIT);

        if (n >= 0)
            return n;
        if (PR_GetError() != PR_WOULD_BLOCK_ERROR)
            return -1;
        if (!wait_io(&deadline))
            return -2;
    }
}

static int handshake(void)
{
    struct timespec deadline = deadline_in(HANDSHAKE_MS);
    SSLChannelInfo info;

    g_started = true;
    while (SSL_ForceHandshake(g_ssl) != SECSuccess) {
        if (PR_GetError() != PR_WOULD_BLOCK_ERROR)
            return fail_nss("handshake");
        if (!wait_io(&deadline))
            return fail_msg(EXIT_FAIL, "handshake: no result within %d ms", HANDSHAKE_MS);
    }
    if (SSL_GetChannelInfo(g_ssl, &info, sizeof(info)) == SECSuccess)
        fprintf(stderr, "handshake done: version 0x%04x, group %s\n", info.protocolVersion,
            group_name(info.keaGroup) != NULL ? group_name(info.keaGroup) : "unknown");
    return EXIT_OK;
}

/* Waits up to TEARDOWN_MS for the peer's close_notify; problems only go to stderr. */
static void await_close_notify(void)
{
    char buf[64];
    int n;

    while ((n = read_record(buf, sizeof(buf), TEARDOWN_MS)) > 0)
        fprintf(stderr, "teardown: ignoring %d bytes of data\n", n);
    if (n == -2)
        fprintf(stderr, "teardown: no close_notify within %d ms\n", TEARDOWN_MS);
    else if (n == -1)
        fprintf(stderr, "teardown: %s\n", PR_ErrorToName(PR_GetError()));
    fprintf(stderr, "teardown done\n");
}

static void send_close_notify(void)
{
    if (PR_Shutdown(g_ssl, PR_SHUTDOWN_SEND) != PR_SUCCESS)
        fprintf(stderr, "teardown: sending close_notify failed: %s\n", PR_ErrorToName(PR_GetError()));
}

/* Client: keeps the latest resumption token; NSS delivers one per NewSessionTicket. */
static SECStatus PR_CALLBACK token_cb(PRFileDesc *fd, const PRUint8 *token, unsigned len, void *arg)
{
    PRUint8 *copy = malloc(len);

    (void)fd, (void)arg;
    if (copy == NULL)
        return SECFailure;
    memcpy(copy, token, len);
    free(g_token);
    g_token = copy;
    g_token_len = len;
    fprintf(stderr, "   resumption token (%u bytes)\n", len);
    return SECSuccess;
}

/* Per-connection state, so the result line describes the last connection only. */
static void reset_connection(int conn)
{
    g_conn = g_opts.resume ? conn : 0;
    g_hrr = 0;
    g_oversize = 0;
    g_cert_error = 0;
    for (int i = 0; i < MAX_MESSAGES; i++) {
        free(g_msgs[i].buf);
        free(g_msgs[i].have);
    }
    memset(g_msgs, 0, sizeof(g_msgs));
    for (int i = 0; i < 2; i++) {
        free(g_streams[i].rec);
        free(g_streams[i].hs);
    }
    memset(g_streams, 0, sizeof(g_streams));
    if (g_ssl != NULL)
        PR_Close(g_ssl);
    g_ssl = NULL;
    if (g_opts.resume)
        fprintf(stderr, "connection %d\n", conn);
}

/* Wraps a connected socket in the logging layer and libssl, configured for this role. */
static int import_socket(int fd)
{
    static PRIOMethods methods;
    PRSocketOptionData nonblocking = { .option = PR_SockOpt_Nonblocking, .value.non_blocking = PR_TRUE };
    SSLVersionRange range = { SSL_LIBRARY_VERSION_TLS_1_3, SSL_LIBRARY_VERSION_TLS_1_3 };
    PRFileDesc *sock = g_opts.tls ? PR_ImportTCPSocket(fd) : PR_ImportUDPSocket(fd), *layer;

    methods = *PR_GetDefaultIOMethods();
    methods.send = layer_send;
    methods.write = layer_write;
    methods.recv = layer_recv;
    methods.read = layer_read;
    methods.shutdown = layer_shutdown;
    if (sock == NULL || PR_SetSocketOption(sock, &nonblocking) != PR_SUCCESS)
        return fail_nss("importing the socket");
    layer = PR_CreateIOLayerStub(PR_GetUniqueIdentity("dtls-adapter"), &methods);
    if (layer == NULL || PR_PushIOLayer(sock, PR_TOP_IO_LAYER, layer) != PR_SUCCESS)
        return fail_nss("pushing the IO layer");
    if ((g_ssl = g_opts.tls ? SSL_ImportFD(NULL, sock) : DTLS_ImportFD(NULL, sock)) == NULL)
        return fail_nss(g_opts.tls ? "SSL_ImportFD" : "DTLS_ImportFD");
    /* NSS servers send no NewSessionTicket unless enabled (sslsock.c ssl_defaults). */
    if (SSL_VersionRangeSet(g_ssl, &range) != SECSuccess
        || SSL_NamedGroupConfig(g_ssl, g_opts.groups, g_opts.ngroups) != SECSuccess
        || (g_opts.server && SSL_OptionSet(g_ssl, SSL_ENABLE_SESSION_TICKETS, PR_TRUE) != SECSuccess)
        || SSL_AlertReceivedCallback(g_ssl, alert_cb, NULL) != SECSuccess
        || SSL_AlertSentCallback(g_ssl, alert_cb, (void *)1) != SECSuccess
        || SSL_ResetHandshake(g_ssl, g_opts.server) != SECSuccess)
        return fail_nss("configuring the socket");
    return EXIT_OK;
}

static int connect_socket(void)
{
    int type = g_opts.tls ? SOCK_STREAM : SOCK_DGRAM;
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = type }, *res, *ai;
    struct sockaddr_storage local;
    socklen_t len = sizeof(local);
    int fd = -1;

    if (getaddrinfo(g_opts.val[OPT_HOST], g_opts.val[OPT_PORT], &hints, &res) != 0)
        return fail_msg(EXIT_FAIL, "resolving --host %s", g_opts.val[OPT_HOST]);
    for (ai = res; ai != NULL && fd < 0; ai = ai->ai_next) {
        fd = socket(ai->ai_family, type, 0);
        if (fd >= 0 && connect(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
            close(fd);
            fd = -1;
        }
    }
    freeaddrinfo(res);
    if (fd < 0)
        return fail_msg(EXIT_FAIL, "connecting %s socket: %s", g_opts.tls ? "TCP" : "UDP", strerror(errno));
    if (getsockname(fd, (struct sockaddr *)&local, &len) == 0)
        fprintf(stderr, "socket: local port %u\n",
            ntohs(local.ss_family == AF_INET6 ? ((struct sockaddr_in6 *)&local)->sin6_port
                                              : ((struct sockaddr_in *)&local)->sin_port));
    return import_socket(fd);
}

/* One client lifecycle; connection 2 offers the token from connection 1. */
static int client_connection(int conn)
{
    const char *share = g_opts.val[OPT_KEY_SHARE];
    int rc, n;
    char buf[64];

    reset_connection(conn);
    if ((rc = connect_socket()) != EXIT_OK)
        return rc;
    /* NSS puts one share for its first group into CH1, plus one per SSL_SendAdditionalKeyShares. */
    if (strcmp(share, "default") != 0 && SSL_SendAdditionalKeyShares(g_ssl, 0) != SECSuccess)
        return fail_nss("SSL_SendAdditionalKeyShares");
    if (SSL_SetURL(g_ssl, SERVER_NAME) != SECSuccess
        || SSL_AuthCertificateHook(g_ssl, auth_cert_cb, CERT_GetDefaultCertDB()) != SECSuccess)
        return fail_nss("configuring server authentication");
    if (g_opts.resume && SSL_SetResumptionTokenCallback(g_ssl, token_cb, NULL) != SECSuccess)
        return fail_nss("SSL_SetResumptionTokenCallback");
    if (conn == 2 && SSL_SetResumptionToken(g_ssl, g_token, g_token_len) != SECSuccess)
        return fail_nss("SSL_SetResumptionToken");

    if ((rc = handshake()) != EXIT_OK)
        return rc;
    if (PR_Write(g_ssl, "ping", 4) != 4)
        return fail_nss("writing ping");
    n = read_record(buf, sizeof(buf), HANDSHAKE_MS);
    if (n < 0)
        return n == -2 ? fail_msg(EXIT_FAIL, "reading pong: timeout") : fail_nss("reading pong");
    if (n != 4 || memcmp(buf, "pong", 4) != 0)
        return fail_msg(EXIT_FAIL, "unexpected echo (%d bytes)", n);
    if (conn == 1 && g_opts.resume && g_token == NULL) {
        fprintf(stderr, "error: no session ticket received\n");
        return finish(EXIT_FAIL, true, "no session ticket received");
    }

    /* The verdict is final after pong; teardown problems are only logged. */
    send_close_notify();
    await_close_notify();
    return EXIT_OK;
}

static int run_client(void)
{
    int rc;

    if ((rc = load_ca()) != EXIT_OK)
        return rc;
    for (int conn = 1; conn <= (g_opts.resume ? 2 : 1); conn++)
        if ((rc = client_connection(conn)) != EXIT_OK)
            return rc;
    return finish(EXIT_OK, true, NULL);
}

/* A UDP or listening TCP socket on --host/--port (or on *addr, the port of the first one). */
static int server_socket(struct sockaddr_storage *addr, socklen_t *len)
{
    int type = g_opts.tls ? SOCK_STREAM : SOCK_DGRAM, one = 1, fd;
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = type, .ai_flags = AI_PASSIVE };
    struct addrinfo *res;

    if (*len == 0) {
        if (getaddrinfo(g_opts.val[OPT_HOST], g_opts.val[OPT_PORT], &hints, &res) != 0)
            return -1;
        memcpy(addr, res->ai_addr, res->ai_addrlen);
        *len = res->ai_addrlen;
        freeaddrinfo(res);
    }
    fd = socket(addr->ss_family, type, 0);
    if (fd >= 0 && (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0
                       || bind(fd, (struct sockaddr *)addr, *len) != 0
                       || (g_opts.tls && listen(fd, 4) != 0)
                       || getsockname(fd, (struct sockaddr *)addr, len) != 0)) {
        close(fd);
        fd = -1;
    }
    return fd;
}

/* DTLS: libssl serves one peer per socket, so the socket is connected to the first datagram's
 * sender; datagrams that connection 1's peer still sends are dropped. */
static int accept_datagram_peer(int fd, const struct sockaddr_storage *prev, socklen_t prev_len)
{
    unsigned char byte;

    for (;;) {
        g_peer_len = sizeof(g_peer);
        if (recvfrom(fd, &byte, 1, MSG_PEEK, (struct sockaddr *)&g_peer, &g_peer_len) < 0)
            return fail_msg(EXIT_FAIL, "waiting for the first datagram: %s", strerror(errno));
        if (prev_len == 0 || g_peer_len != prev_len || memcmp(&g_peer, prev, prev_len) != 0)
            break;
        fprintf(stderr, "<< dropping a late datagram from connection 1's peer\n");
        recv(fd, &byte, 1, 0);
    }
    if (connect(fd, (struct sockaddr *)&g_peer, g_peer_len) != 0)
        return fail_msg(EXIT_FAIL, "connecting to the peer: %s", strerror(errno));
    return EXIT_OK;
}

/* One server lifecycle on fd (DTLS: the bound socket; TLS: the listening socket). */
static int server_connection(int conn, int fd, CERTCertificate *cert, SECKEYPrivateKey *key)
{
    int rc, n;
    char buf[64];

    reset_connection(conn);
    if (g_opts.tls) {
        g_peer_len = sizeof(g_peer);
        if ((fd = accept(fd, (struct sockaddr *)&g_peer, &g_peer_len)) < 0)
            return fail_msg(EXIT_FAIL, "accepting a TCP connection: %s", strerror(errno));
    }
    if ((rc = import_socket(fd)) != EXIT_OK)
        return rc;
    if (SSL_ConfigServerCert(g_ssl, cert, key, NULL, 0) != SECSuccess)
        return fail_nss("SSL_ConfigServerCert");
    if (g_opts.cookie && SSL_HelloRetryRequestCallback(g_ssl, hrr_cb, NULL) != SECSuccess)
        return fail_nss("SSL_HelloRetryRequestCallback");

    if ((rc = handshake()) != EXIT_OK)
        return rc;
    n = read_record(buf, sizeof(buf), HANDSHAKE_MS);
    if (n < 0)
        return n == -2 ? fail_msg(EXIT_FAIL, "reading ping: timeout") : fail_nss("reading ping");
    if (n != 4 || memcmp(buf, "ping", 4) != 0)
        return fail_msg(EXIT_FAIL, "unexpected message (%d bytes)", n);
    if (PR_Write(g_ssl, "pong", 4) != 4)
        return fail_nss("writing pong");
    await_close_notify();
    send_close_notify();
    return EXIT_OK;
}

static int run_server(void)
{
    CERTCertificate *cert = NULL;
    SECKEYPrivateKey *key = NULL;
    struct sockaddr_storage addr, prev;
    socklen_t len = 0, prev_len = 0;
    int fd, next = -1, rc;

    if ((rc = load_server_credentials(&cert, &key)) != EXIT_OK)
        return rc;
    /* Server-side session state lives in this process; tickets are encrypted with its keys. */
    if (SSL_ConfigServerSessionIDCache(0, 0, 0, NULL) != SECSuccess)
        return fail_nss("SSL_ConfigServerSessionIDCache");
    if ((fd = server_socket(&addr, &len)) < 0)
        return fail_msg(EXIT_FAIL, "binding the server socket: %s", strerror(errno));
    printf("{\"event\": \"ready\", \"port\": %u}\n",
        ntohs(addr.ss_family == AF_INET6 ? ((struct sockaddr_in6 *)&addr)->sin6_port
                                         : ((struct sockaddr_in *)&addr)->sin_port));
    fflush(stdout);
    for (int conn = 1; conn <= (g_opts.resume ? 2 : 1); conn++) {
        if (!g_opts.tls) {
            if ((rc = accept_datagram_peer(fd, &prev, prev_len)) != EXIT_OK)
                return rc;
            /* Connection 2 comes from a new port: a second unconnected socket on the same port
             * gets it, while connection 1's peer stays with the connected one. */
            if (conn == 1 && g_opts.resume && (next = server_socket(&addr, &len)) < 0)
                return fail_msg(EXIT_FAIL, "binding the second UDP socket: %s", strerror(errno));
            prev = g_peer;
            prev_len = g_peer_len;
        }
        if ((rc = server_connection(conn, fd, cert, key)) != EXIT_OK)
            return rc;
        if (!g_opts.tls)
            fd = next;
    }
    return finish(EXIT_OK, true, NULL);
}

static int usage(const char *fmt, const char *arg)
{
    char msg[256];

    snprintf(msg, sizeof(msg), fmt, arg);
    fprintf(stderr,
        "usage: run --role=client --variant=default --host=HOST --port=PORT --groups=G1[,G2...]\n"
        "           --transport=dtls|tls --resume=off|ticket --mtu=N|default --ca=FILE\n"
        "           --key-share=GROUP|empty|default\n"
        "       run --role=server --variant=default --host=HOST --port=PORT --groups=G1[,G2...]\n"
        "           --transport=dtls|tls --resume=off|ticket --mtu=N|default --ca=FILE\n"
        "           --validate=off|cookie --cert=FILE --key=FILE\n");
    return fail_msg(EXIT_USAGE, "usage: %s", msg);
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

    /* getopt_long also takes unique prefixes (--group); the contract wants exact names only. */
    for (int i = 1; i < argc; i++) {
        size_t len = strcspn(argv[i] + 2, "=");
        int k = 0;

        if (strncmp(argv[i], "--", 2) != 0)
            continue;
        while (LONGOPTS[k].name != NULL
            && (strlen(LONGOPTS[k].name) != len || strncmp(LONGOPTS[k].name, argv[i] + 2, len) != 0))
            k++;
        if (LONGOPTS[k].name == NULL)
            return usage("unknown option: %s", argv[i]);
        i += argv[i][2 + len] == '\0'; /* "--opt value": skip the value */
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
    /* libssl has one DTLS code path per role, so there are no variants. */
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
    v = g_opts.val[OPT_TRANSPORT];
    if (strcmp(v, "dtls") != 0 && strcmp(v, "tls") != 0)
        return usage("--transport must be dtls or tls", NULL);
    g_opts.tls = strcmp(v, "tls") == 0;
    v = g_opts.val[OPT_RESUME];
    if (strcmp(v, "off") != 0 && strcmp(v, "ticket") != 0)
        return usage("--resume must be off or ticket", NULL);
    g_opts.resume = strcmp(v, "ticket") == 0;
    if (g_opts.tls && strcmp(g_opts.val[OPT_MTU], "default") != 0)
        return usage("--mtu=%s: TLS over TCP takes only --mtu=default", g_opts.val[OPT_MTU]);
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

/* Maps --groups to NSS group ids; groups NSS lacks and unexpressible requests exit 2. */
static int check_supported(void)
{
    char *copy = strdup(g_opts.val[OPT_GROUPS]);
    const char *share = g_opts.val[OPT_KEY_SHARE];

    if (copy == NULL)
        return fail_msg(EXIT_FAIL, "out of memory");
    for (char *tok = strtok(copy, ","); tok != NULL; tok = strtok(NULL, ",")) {
        size_t i = 0;

        while (i < sizeof(GROUPS) / sizeof(GROUPS[0]) && strcasecmp(tok, GROUPS[i].name) != 0)
            i++;
        if (i == sizeof(GROUPS) / sizeof(GROUPS[0])) {
            int rc = fail_msg(EXIT_UNSUPPORTED, "group %s not implemented by NSS %s", tok,
                NSS_GetVersion());
            free(copy);
            return rc;
        }
        g_opts.groups[g_opts.ngroups++] = GROUPS[i].id;
    }
    free(copy);
    if (g_opts.payload > 0 && g_opts.payload < NSS_MAX_DATAGRAM)
        return fail_msg(EXIT_UNSUPPORTED,
            "--mtu=%ld: NSS has no DTLS MTU setting and sends datagrams of up to %d bytes",
            g_opts.mtu, NSS_MAX_DATAGRAM);
    if (g_opts.server)
        return EXIT_OK;
    if (strcmp(share, "empty") == 0)
        return fail_msg(EXIT_UNSUPPORTED,
            "NSS clients always send a key share for their first group; empty key_share not possible");
    if (strcmp(share, "default") != 0 && strcasecmp(share, group_name(g_opts.groups[0])) != 0)
        return fail_msg(EXIT_UNSUPPORTED,
            "NSS sends its key share for the first --groups entry (%s), not for %s",
            group_name(g_opts.groups[0]), share);
    return EXIT_OK;
}

int main(int argc, char **argv)
{
    int rc;

    if ((rc = parse_options(argc, argv)) != EXIT_OK)
        return rc;
    /* No database: nothing outside the pinned build and these flags affects the run. */
    if (NSS_NoDB_Init(NULL) != SECSuccess)
        return fail_nss("NSS_NoDB_Init");
    g_conn = g_opts.resume ? 1 : 0;
    fprintf(stderr, "NSS %s, NSPR %s, role=%s variant=%s transport=%s resume=%s groups=%s mtu=%s "
        "key-share=%s validate=%s\n",
        NSS_GetVersion(), PR_GetVersion(), g_opts.val[OPT_ROLE], g_opts.val[OPT_VARIANT],
        g_opts.val[OPT_TRANSPORT], g_opts.val[OPT_RESUME], g_opts.val[OPT_GROUPS], g_opts.val[OPT_MTU],
        g_opts.server ? "-" : g_opts.val[OPT_KEY_SHARE],
        g_opts.server ? g_opts.val[OPT_VALIDATE] : "-");
    if ((rc = check_supported()) != EXIT_OK)
        return rc;
    rc = g_opts.server ? run_server() : run_client();
    if (g_ssl != NULL)
        PR_Close(g_ssl);
    return rc;
}
