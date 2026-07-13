#include "hello.h"
#include "reader.h"
#include "util.h"

#include <sodium.h>
#include <string.h>

/* Extension type codes (RFC 8446 section 4.2). */
#define EXT_SERVER_NAME 0
#define EXT_SUPPORTED_GROUPS 10
#define EXT_SIGNATURE_ALGORITHMS 13
#define EXT_SUPPORTED_VERSIONS 43
#define EXT_KEY_SHARE 51

/* HelloRetryRequest is a ServerHello whose random equals this fixed value
 * (SHA-256 of "HelloRetryRequest"), RFC 8446 section 4.1.3. */
static const uint8_t HRR_RANDOM[32] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C};

/* Signature schemes we advertise. We only advertise algorithms plan 05 can
 * actually verify (ECDSA P-256, RSA-PSS-RSAE at SHA-256/384/512), so the
 * server's CertificateVerify uses one we can check. */
static const uint16_t SIG_ALGS[] = {
    0x0403, /* ecdsa_secp256r1_sha256 */
    0x0804, /* rsa_pss_rsae_sha256 */
    0x0805, /* rsa_pss_rsae_sha384 */
    0x0806, /* rsa_pss_rsae_sha512 */
};

void hello_gen_keys(tls_conn_t *c) {
    if (sodium_init() < 0)
        die("libsodium init failed");
    randombytes_buf(c->client_priv, X25519_LEN);
    crypto_scalarmult_base(c->client_pub, c->client_priv);
    randombytes_buf(c->client_random, TLS_RANDOM_LEN);
    /* legacy_session_id: 32 random bytes for middlebox compatibility. */
    c->session_id_len = 32;
    randombytes_buf(c->session_id, 32);
}

static void put_server_name_ext(buf_t *b, const char *host) {
    buf_u16(b, EXT_SERVER_NAME);
    size_t ext = buf_begin_u16(b);
    size_t list = buf_begin_u16(b);  /* ServerNameList length */
    buf_u8(b, 0);                    /* name_type = host_name */
    size_t name = buf_begin_u16(b);  /* HostName length */
    buf_append(b, host, strlen(host));
    buf_end_u16(b, name);
    buf_end_u16(b, list);
    buf_end_u16(b, ext);
}

static void put_supported_groups_ext(buf_t *b) {
    buf_u16(b, EXT_SUPPORTED_GROUPS);
    size_t ext = buf_begin_u16(b);
    size_t list = buf_begin_u16(b);
    buf_u16(b, TLS_GROUP_X25519);
    buf_end_u16(b, list);
    buf_end_u16(b, ext);
}

static void put_signature_algorithms_ext(buf_t *b) {
    buf_u16(b, EXT_SIGNATURE_ALGORITHMS);
    size_t ext = buf_begin_u16(b);
    size_t list = buf_begin_u16(b);
    for (size_t i = 0; i < sizeof SIG_ALGS / sizeof SIG_ALGS[0]; i++)
        buf_u16(b, SIG_ALGS[i]);
    buf_end_u16(b, list);
    buf_end_u16(b, ext);
}

static void put_supported_versions_ext(buf_t *b) {
    buf_u16(b, EXT_SUPPORTED_VERSIONS);
    size_t ext = buf_begin_u16(b);
    size_t list = buf_begin_u8(b);   /* ClientHello uses a 1-byte list length */
    buf_u16(b, TLS13_VERSION);
    buf_end_u8(b, list);
    buf_end_u16(b, ext);
}

static void put_key_share_ext(buf_t *b, const uint8_t *pub) {
    buf_u16(b, EXT_KEY_SHARE);
    size_t ext = buf_begin_u16(b);
    size_t list = buf_begin_u16(b);  /* client_shares length */
    buf_u16(b, TLS_GROUP_X25519);
    size_t key = buf_begin_u16(b);   /* key_exchange length */
    buf_append(b, pub, X25519_LEN);
    buf_end_u16(b, key);
    buf_end_u16(b, list);
    buf_end_u16(b, ext);
}

void hello_build_clienthello(tls_conn_t *c, buf_t *out) {
    buf_u8(out, HS_CLIENT_HELLO);
    size_t hs = buf_begin_u24(out);           /* handshake length */

    buf_u16(out, 0x0303);                      /* legacy_version = TLS 1.2 */
    buf_append(out, c->client_random, TLS_RANDOM_LEN);

    buf_u8(out, c->session_id_len);            /* legacy_session_id */
    buf_append(out, c->session_id, c->session_id_len);

    size_t cs = buf_begin_u16(out);            /* cipher_suites */
    buf_u16(out, TLS_AES_128_GCM_SHA256);
    buf_end_u16(out, cs);

    buf_u8(out, 1);                            /* legacy_compression_methods */
    buf_u8(out, 0);                            /* null compression */

    size_t exts = buf_begin_u16(out);          /* extensions block */
    put_server_name_ext(out, c->host);
    put_supported_groups_ext(out);
    put_signature_algorithms_ext(out);
    put_supported_versions_ext(out);
    put_key_share_ext(out, c->client_pub);
    buf_end_u16(out, exts);

    buf_end_u24(out, hs);

    /* Keep a copy in the transcript (message with header, no record header). */
    buf_append(&c->transcript, out->data, out->len);
}

/* Walk ServerHello extensions, pulling selected_version and the server
 * key_share. */
static int parse_sh_extensions(tls_conn_t *c, rd_t *r, int *saw_version) {
    uint16_t total = rd_u16(r);
    rd_t ex;
    const uint8_t *blk = rd_bytes(r, total);
    if (!rd_ok(r))
        return -1;
    rd_init(&ex, blk, total);

    while (rd_remaining(&ex) > 0) {
        uint16_t type = rd_u16(&ex);
        uint16_t len = rd_u16(&ex);
        const uint8_t *data = rd_bytes(&ex, len);
        if (!rd_ok(&ex))
            return -1;

        rd_t in;
        rd_init(&in, data, len);
        if (type == EXT_SUPPORTED_VERSIONS) {
            uint16_t v = rd_u16(&in);
            if (!rd_ok(&in))
                return -1;
            if (v != TLS13_VERSION) {
                warn("server selected version 0x%04x, not TLS 1.3", v);
                return -1;
            }
            *saw_version = 1;
        } else if (type == EXT_KEY_SHARE) {
            uint16_t group = rd_u16(&in);
            uint16_t klen = rd_u16(&in);
            const uint8_t *key = rd_bytes(&in, klen);
            if (!rd_ok(&in))
                return -1;
            if (group != TLS_GROUP_X25519) {
                warn("server key_share group 0x%04x is not x25519", group);
                return -1;
            }
            if (klen != X25519_LEN) {
                warn("server key_share length %u != 32", klen);
                return -1;
            }
            memcpy(c->server_pub, key, X25519_LEN);
            c->have_server_pub = 1;
        }
    }
    return 0;
}

int hello_parse_serverhello(tls_conn_t *c, const uint8_t *body, size_t len) {
    rd_t r;
    rd_init(&r, body, len);

    uint16_t legacy_version = rd_u16(&r);
    (void)legacy_version; /* real version is in supported_versions extension */

    const uint8_t *random = rd_bytes(&r, TLS_RANDOM_LEN);
    if (!rd_ok(&r))
        return -1;
    if (memcmp(random, HRR_RANDOM, TLS_RANDOM_LEN) == 0) {
        warn("HelloRetryRequest received - not supported");
        return -2;
    }
    memcpy(c->server_random, random, TLS_RANDOM_LEN);

    uint8_t sid_len = rd_u8(&r);
    rd_bytes(&r, sid_len); /* legacy_session_id_echo, ignored */

    uint16_t suite = rd_u16(&r);
    if (!rd_ok(&r))
        return -1;
    if (suite != TLS_AES_128_GCM_SHA256) {
        warn("server chose cipher suite 0x%04x, which we did not offer", suite);
        return -1;
    }
    c->cipher_suite = suite;

    uint8_t compression = rd_u8(&r);
    if (compression != 0) {
        warn("server selected non-null compression");
        return -1;
    }

    int saw_version = 0;
    if (parse_sh_extensions(c, &r, &saw_version) != 0)
        return -1;
    if (!rd_ok(&r))
        return -1;

    if (!saw_version) {
        warn("ServerHello lacks supported_versions - not TLS 1.3");
        return -1;
    }
    if (!c->have_server_pub) {
        warn("ServerHello lacks an x25519 key_share");
        return -1;
    }
    return 0;
}
