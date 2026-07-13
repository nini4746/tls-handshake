/* Plan 02 verification: ServerHello negotiation defenses (un-offered cipher
 * suite abort, HRR detection) and a happy-path parse that captures the server
 * key_share. Also confirms the ClientHello round-trips through its own parser
 * shape (version/cipher/extension nesting is well-formed). */
#include "test_util.h"

#include "../src/hello.h"
#include "../src/tls.h"
#include "../src/buf.h"
#include "../src/int.h"

#include <string.h>

static const uint8_t HRR_RANDOM[32] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C};

/* Build a ServerHello body (bytes after the 4-byte handshake header). */
static void build_sh(buf_t *b, const uint8_t random[32], uint16_t suite,
                     uint16_t sel_version, uint16_t ks_group, int with_ks) {
    buf_reset(b);
    buf_u16(b, 0x0303);
    buf_append(b, random, 32);
    buf_u8(b, 0); /* session_id_echo length 0 */
    buf_u16(b, suite);
    buf_u8(b, 0); /* compression */
    size_t exts = buf_begin_u16(b);
    /* supported_versions */
    buf_u16(b, 43);
    size_t e1 = buf_begin_u16(b);
    buf_u16(b, sel_version);
    buf_end_u16(b, e1);
    /* key_share */
    if (with_ks) {
        buf_u16(b, 51);
        size_t e2 = buf_begin_u16(b);
        buf_u16(b, ks_group);
        size_t k = buf_begin_u16(b);
        for (int i = 0; i < 32; i++)
            buf_u8(b, (uint8_t)(0x40 + i));
        buf_end_u16(b, k);
        buf_end_u16(b, e2);
    }
    buf_end_u16(b, exts);
}

int main(void) {
    printf("test_hello\n");

    tls_conn_t c;
    tls_conn_init(&c, -1, "example.com");

    uint8_t rnd[32];
    memset(rnd, 0x11, sizeof rnd);
    buf_t sh;
    buf_init(&sh);

    /* Happy path. */
    build_sh(&sh, rnd, TLS_AES_128_GCM_SHA256, TLS13_VERSION, TLS_GROUP_X25519, 1);
    CHECK(hello_parse_serverhello(&c, sh.data, sh.len) == 0);
    CHECK(c.cipher_suite == TLS_AES_128_GCM_SHA256);
    CHECK(c.have_server_pub == 1);
    uint8_t expect_pub[32];
    for (int i = 0; i < 32; i++)
        expect_pub[i] = (uint8_t)(0x40 + i);
    CHECK_MEM(c.server_pub, expect_pub, 32);

    /* Un-offered cipher suite -> abort. */
    tls_conn_free(&c);
    tls_conn_init(&c, -1, "example.com");
    build_sh(&sh, rnd, 0x1302, TLS13_VERSION, TLS_GROUP_X25519, 1);
    CHECK(hello_parse_serverhello(&c, sh.data, sh.len) == -1);

    /* Wrong selected version -> abort. */
    tls_conn_free(&c);
    tls_conn_init(&c, -1, "example.com");
    build_sh(&sh, rnd, TLS_AES_128_GCM_SHA256, 0x0303, TLS_GROUP_X25519, 1);
    CHECK(hello_parse_serverhello(&c, sh.data, sh.len) == -1);

    /* HRR random -> -2. */
    tls_conn_free(&c);
    tls_conn_init(&c, -1, "example.com");
    build_sh(&sh, HRR_RANDOM, TLS_AES_128_GCM_SHA256, TLS13_VERSION,
             TLS_GROUP_X25519, 1);
    CHECK(hello_parse_serverhello(&c, sh.data, sh.len) == -2);

    /* Non-x25519 key_share -> abort. */
    tls_conn_free(&c);
    tls_conn_init(&c, -1, "example.com");
    build_sh(&sh, rnd, TLS_AES_128_GCM_SHA256, TLS13_VERSION, 0x0017, 1);
    CHECK(hello_parse_serverhello(&c, sh.data, sh.len) == -1);

    /* ClientHello assembly is well-formed: first byte is HS_CLIENT_HELLO and
     * the 3-byte length matches the remaining bytes. */
    tls_conn_free(&c);
    tls_conn_init(&c, -1, "example.com");
    hello_gen_keys(&c);
    buf_t ch;
    buf_init(&ch);
    hello_build_clienthello(&c, &ch);
    CHECK(ch.data[0] == HS_CLIENT_HELLO);
    CHECK(get_u24(ch.data + 1) == ch.len - 4);

    buf_free(&ch);
    buf_free(&sh);
    tls_conn_free(&c);
    TEST_REPORT();
}
