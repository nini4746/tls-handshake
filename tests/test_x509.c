/* Plan 05 verification (memory-only):
 *  - DER/X.509 parsing of the RFC 8448 server certificate.
 *  - RSA (sha256WithRSAEncryption) self-signature verification over the exact
 *    tbsCertificate bytes, and tamper rejection.
 *  - Validity field parsing.
 *  - SAN hostname matching: exact, single-label wildcard, multi-label reject,
 *    case-insensitive.
 *  - CertificateVerify (RSA-PSS-SHA256) verified end-to-end from RFC 8448
 *    material, with transcript-tamper rejection.
 * Full ECDSA chain-to-root and incomplete-chain rejection are exercised live. */
#include "test_util.h"
#include "vec_aead.h"

#include "../src/x509.h"
#include "../src/der.h"
#include "../src/verify.h"
#include "../src/handshake.h"
#include "../src/hkdf.h"
#include "../src/tls.h"

#include <string.h>
#include <time.h>

/* Locate the Certificate and CertificateVerify messages inside the RFC 8448
 * server flight payload (EncryptedExtensions, Certificate, CertificateVerify,
 * Finished, concatenated). */
static size_t msg_len(const uint8_t *m) {
    return 4 + (((size_t)m[1] << 16) | ((size_t)m[2] << 8) | m[3]);
}

static x509_cert_t g_leaf;
static const uint8_t *g_cert_der;
static size_t g_cert_dlen;
static const uint8_t *g_cv;     /* CertificateVerify body (after 4-byte header) */
static size_t g_cv_len;
static size_t g_cert_msg_off;   /* offset of Certificate message in payload */

static void locate(void) {
    const uint8_t *p = RFC8448_SERVER_HS_PAYLOAD;
    size_t ee = msg_len(p);
    const uint8_t *cert = p + ee;
    g_cert_msg_off = ee;
    const uint8_t *cv = cert + msg_len(cert);

    const uint8_t *der[8];
    size_t dlen[8];
    int n = certificate_list_parse(cert + 4, msg_len(cert) - 4, der, dlen, 8);
    CHECK(n == 1);
    g_cert_der = der[0];
    g_cert_dlen = dlen[0];
    CHECK(x509_parse(g_cert_der, g_cert_dlen, &g_leaf) == 0);

    g_cv = cv + 4;
    g_cv_len = msg_len(cv) - 4;
}

static void test_parse(void) {
    /* Self-signed toy cert: issuer == subject. */
    CHECK(x509_name_equal(g_leaf.issuer, g_leaf.issuer_len, g_leaf.subject,
                          g_leaf.subject_len));
    CHECK(g_leaf.tbs != NULL && g_leaf.tbs_len > 0);
    CHECK(g_leaf.spki != NULL && g_leaf.spki_len > 0);
    CHECK(g_leaf.sig_value_len > 0);

    /* Validity 160730012359Z .. 260730012359Z. */
    struct tm tm;
    memset(&tm, 0, sizeof tm);
    tm.tm_year = 2026 - 1900;
    tm.tm_mon = 6; /* July */
    tm.tm_mday = 30;
    tm.tm_hour = 1;
    tm.tm_min = 23;
    tm.tm_sec = 59;
    time_t expect_after = timegm(&tm);
    CHECK(g_leaf.not_after == expect_after);
    CHECK(g_leaf.not_before < g_leaf.not_after);
}

static void test_self_signature(void) {
    /* Self-signed: verify leaf signature with the leaf's own SPKI. */
    CHECK(verify_cert_signature(&g_leaf, g_leaf.spki, g_leaf.spki_len) == 0);

    /* Tamper: flip the last DER byte (inside signatureValue) -> must fail. */
    uint8_t *copy = malloc(g_cert_dlen);
    memcpy(copy, g_cert_der, g_cert_dlen);
    copy[g_cert_dlen - 1] ^= 0x01;
    x509_cert_t bad;
    CHECK(x509_parse(copy, g_cert_dlen, &bad) == 0);
    CHECK(verify_cert_signature(&bad, bad.spki, bad.spki_len) == -1);
    free(copy);
}

static void test_hostname(void) {
    CHECK(hostname_match("example.com", 11, "example.com") == 1);
    CHECK(hostname_match("Example.COM", 11, "example.com") == 1); /* case */
    CHECK(hostname_match("example.com", 11, "www.example.com") == 0);
    CHECK(hostname_match("*.example.com", 13, "a.example.com") == 1);
    CHECK(hostname_match("*.example.com", 13, "A.example.com") == 1);
    CHECK(hostname_match("*.example.com", 13, "a.b.example.com") == 0); /* multi */
    CHECK(hostname_match("*.example.com", 13, "example.com") == 0);
    CHECK(hostname_match("*.example.com", 13, "a.example.org") == 0);
}

static void test_certificate_verify(void) {
    /* Transcript-Hash(ClientHello..Certificate). */
    uint8_t buf[2048];
    size_t n = 0;
    memcpy(buf + n, RFC8448_CLIENTHELLO, sizeof RFC8448_CLIENTHELLO);
    n += sizeof RFC8448_CLIENTHELLO;
    memcpy(buf + n, RFC8448_SERVERHELLO, sizeof RFC8448_SERVERHELLO);
    n += sizeof RFC8448_SERVERHELLO;
    /* EncryptedExtensions + Certificate = payload up to CertificateVerify. */
    const uint8_t *p = RFC8448_SERVER_HS_PAYLOAD;
    size_t upto = g_cert_msg_off + msg_len(p + g_cert_msg_off);
    memcpy(buf + n, p, upto);
    n += upto;
    uint8_t th[HASH_LEN];
    sha256(th, buf, n);

    /* CertificateVerify body: scheme(2) || sig_len(2) || sig. */
    uint16_t scheme = ((uint16_t)g_cv[0] << 8) | g_cv[1];
    uint16_t siglen = ((uint16_t)g_cv[2] << 8) | g_cv[3];
    CHECK(scheme == 0x0804); /* rsa_pss_rsae_sha256 */
    const uint8_t *sig = g_cv + 4;

    CHECK(verify_certificate_verify(g_leaf.spki, g_leaf.spki_len, scheme, sig,
                                    siglen, th) == 0);

    /* One-byte transcript change -> signature must fail. */
    th[0] ^= 0x01;
    CHECK(verify_certificate_verify(g_leaf.spki, g_leaf.spki_len, scheme, sig,
                                    siglen, th) == -1);
}

int main(void) {
    printf("test_x509\n");
    locate();
    test_parse();
    test_self_signature();
    test_hostname();
    test_certificate_verify();
    TEST_REPORT();
}
