/* Minimal X.509 certificate field extraction (RFC 5280).
 * Only the fields chain verification needs; everything is a raw byte slice into
 * the original DER so signatures verify against the exact encoding. */
#ifndef TLS_X509_H
#define TLS_X509_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

#define X509_MAX_SAN 64

typedef struct {
    /* tbsCertificate: raw bytes (tag+len+value), the signed content. */
    const uint8_t *tbs;
    size_t tbs_len;

    /* issuer / subject Name: raw DER (tag+len+value) for byte-exact matching. */
    const uint8_t *issuer;
    size_t issuer_len;
    const uint8_t *subject;
    size_t subject_len;

    /* subjectPublicKeyInfo: raw DER (tag+len+value). */
    const uint8_t *spki;
    size_t spki_len;

    /* signatureAlgorithm OID value bytes (content only). */
    const uint8_t *sig_alg_oid;
    size_t sig_alg_oid_len;

    /* signatureValue: raw signature (BIT STRING content minus unused-bits byte). */
    const uint8_t *sig_value;
    size_t sig_value_len;

    time_t not_before;
    time_t not_after;

    /* subjectAltName dNSName entries (pointers into the DER, not terminated). */
    const char *dns[X509_MAX_SAN];
    size_t dns_len[X509_MAX_SAN];
    int dns_count;

    int has_basic_constraints;
    int is_ca; /* basicConstraints cA */
} x509_cert_t;

/* Parse a DER certificate into out. Returns 0 on success, -1 on malformed. */
int x509_parse(const uint8_t *der, size_t len, x509_cert_t *out);

/* Byte-exact comparison of two DER Name blobs. */
int x509_name_equal(const uint8_t *a, size_t alen, const uint8_t *b,
                    size_t blen);

#endif /* TLS_X509_H */
