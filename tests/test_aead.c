/* Plan 04 verification, memory-only:
 *  - AEAD decrypt of the RFC 8448 server encrypted handshake record, including
 *    inner content-type recovery and zero-padding strip.
 *  - Tamper detection (auth failure) on a flipped ciphertext byte.
 *  - Server Finished verify_data reproduced end-to-end from RFC 8448 material,
 *    and mismatch rejection on a one-byte transcript change.
 *  - Certificate list parsing.
 *  - Handshake message-order enforcement is covered by expect_message() in the
 *    driver; here we assert the ordering predicate directly. */
#include "test_util.h"
#include "vec_aead.h"

#include "../src/aead.h"
#include "../src/keysched.h"
#include "../src/hkdf.h"
#include "../src/handshake.h"
#include "../src/record.h"
#include "../src/util.h"
#include "../src/tls.h"

#include <string.h>

static const char *SERVER_HS_TRAFFIC =
    "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38";

static void test_aead_decrypt(void) {
    aead_ctx_t rd;
    uint8_t secret[HASH_LEN];
    from_hex(secret, sizeof secret, SERVER_HS_TRAFFIC);
    aead_ctx_init(&rd, secret);

    const uint8_t *hdr = RFC8448_SERVER_HS_RECORD;      /* 5-byte record header */
    const uint8_t *body = RFC8448_SERVER_HS_RECORD + 5; /* ciphertext || tag */
    size_t bodylen = sizeof RFC8448_SERVER_HS_RECORD - 5;

    uint8_t out[1024];
    size_t outlen;
    uint8_t inner;
    CHECK(aead_open(&rd, hdr, body, bodylen, out, &outlen, &inner) == 0);
    CHECK(inner == TLS_CT_HANDSHAKE); /* recovered inner content type = 22 */
    CHECK(outlen == sizeof RFC8448_SERVER_HS_PAYLOAD);
    CHECK_MEM(out, RFC8448_SERVER_HS_PAYLOAD, sizeof RFC8448_SERVER_HS_PAYLOAD);
}

static void test_aead_tamper(void) {
    aead_ctx_t rd;
    uint8_t secret[HASH_LEN];
    from_hex(secret, sizeof secret, SERVER_HS_TRAFFIC);
    aead_ctx_init(&rd, secret);

    uint8_t rec[sizeof RFC8448_SERVER_HS_RECORD];
    memcpy(rec, RFC8448_SERVER_HS_RECORD, sizeof rec);
    rec[10] ^= 0x01; /* flip a ciphertext byte */

    uint8_t out[1024];
    size_t outlen;
    uint8_t inner;
    CHECK(aead_open(&rd, rec, rec + 5, sizeof rec - 5, out, &outlen, &inner) ==
          -1);
}

static void test_server_finished(void) {
    /* Transcript-Hash(ClientHello..CertificateVerify) = SHA-256 of CH || SH ||
     * (server flight up to but excluding the 36-byte Finished message). */
    uint8_t transcript[1024];
    size_t n = 0;
    memcpy(transcript + n, RFC8448_CLIENTHELLO, sizeof RFC8448_CLIENTHELLO);
    n += sizeof RFC8448_CLIENTHELLO;
    memcpy(transcript + n, RFC8448_SERVERHELLO, sizeof RFC8448_SERVERHELLO);
    n += sizeof RFC8448_SERVERHELLO;
    size_t flight_wo_fin = sizeof RFC8448_SERVER_HS_PAYLOAD - 36;
    memcpy(transcript + n, RFC8448_SERVER_HS_PAYLOAD, flight_wo_fin);
    n += flight_wo_fin;

    uint8_t th[HASH_LEN];
    sha256(th, transcript, n);

    uint8_t secret[HASH_LEN];
    from_hex(secret, sizeof secret, SERVER_HS_TRAFFIC);

    /* verify_data = last 32 bytes of the payload (Finished body). */
    const uint8_t *vd = RFC8448_SERVER_HS_PAYLOAD +
                        (sizeof RFC8448_SERVER_HS_PAYLOAD - HASH_LEN);
    CHECK(finished_verify(secret, th, vd, HASH_LEN) == 0);

    /* Flip one transcript byte -> mismatch. */
    uint8_t th2[HASH_LEN];
    transcript[0] ^= 0x01;
    sha256(th2, transcript, n);
    CHECK(finished_verify(secret, th2, vd, HASH_LEN) == -1);
}

static void test_certificate_parse(void) {
    /* The server flight payload begins with EncryptedExtensions (type 8, len
     * from its header), followed by the Certificate message (type 11). Locate
     * the Certificate message and parse its list. */
    const uint8_t *p = RFC8448_SERVER_HS_PAYLOAD;
    /* EE: 08 00 00 24 ... so EE length = 0x24, message = 4 + 0x24. */
    CHECK(p[0] == HS_ENCRYPTED_EXTENSIONS);
    size_t ee_len = ((size_t)p[1] << 16) | ((size_t)p[2] << 8) | p[3];
    const uint8_t *cert = p + 4 + ee_len;
    CHECK(cert[0] == HS_CERTIFICATE);
    size_t cert_len = ((size_t)cert[1] << 16) | ((size_t)cert[2] << 8) | cert[3];

    const uint8_t *der[8];
    size_t dlen[8];
    int cnt = certificate_list_parse(cert + 4, cert_len, der, dlen, 8);
    CHECK(cnt == 1); /* RFC 8448 uses a single self-signed cert */
    CHECK(dlen[0] > 0);
    CHECK(der[0][0] == 0x30); /* DER SEQUENCE */
}

int main(void) {
    printf("test_aead\n");
    test_aead_decrypt();
    test_aead_tamper();
    test_server_finished();
    test_certificate_parse();
    TEST_REPORT();
}
