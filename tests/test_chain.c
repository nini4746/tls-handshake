/* Issue #1 regression (memory-only):
 *  - A Certificate message with more than MAX_CHAIN (10) entries must be
 *    rejected by verify_server_certificate without writing past its stack
 *    arrays. Run under `make SAN=1 test` to catch the overflow.
 * The fixture is the RFC 8448 server certificate, repeated 11 times. */
#include "test_util.h"
#include "vec_aead.h"

#include "../src/buf.h"
#include "../src/handshake.h"
#include "../src/tls.h"
#include "../src/verify.h"

#include <stdint.h>
#include <string.h>

static size_t msg_len(const uint8_t *m) {
    return 4 + (((size_t)m[1] << 16) | ((size_t)m[2] << 8) | m[3]);
}

static void put_u24(buf_t *b, size_t v) {
    uint8_t x[3] = {(uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
    buf_append(b, x, 3);
}

/* Build a Certificate body (empty context) holding ncert copies of der. */
static void build_cert_msg(buf_t *b, const uint8_t *der, size_t dlen,
                           int ncert) {
    static const uint8_t zero[2] = {0, 0};
    buf_append(b, zero, 1); /* certificate_request_context length */
    put_u24(b, (3 + dlen + 2) * (size_t)ncert);
    for (int i = 0; i < ncert; i++) {
        put_u24(b, dlen);
        buf_append(b, der, dlen);
        buf_append(b, zero, 2); /* no per-certificate extensions */
    }
}

static void test_chain_too_long(void) {
    const uint8_t *p = RFC8448_SERVER_HS_PAYLOAD;
    const uint8_t *cert = p + msg_len(p); /* skip EncryptedExtensions */
    const uint8_t *der[8];
    size_t dlen[8];
    CHECK(certificate_list_parse(cert + 4, msg_len(cert) - 4, der, dlen, 8) ==
          1);

    tls_conn_t c;
    tls_conn_init(&c, -1, "server");
    build_cert_msg(&c.cert_msg, der[0], dlen[0], 11);
    CHECK(verify_server_certificate(&c) == -1);
    tls_conn_free(&c);
}

int main(void) {
    printf("test_chain\n");
    test_chain_too_long();
    TEST_REPORT();
}
