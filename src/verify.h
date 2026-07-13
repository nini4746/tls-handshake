/* Certificate chain and CertificateVerify verification.
 *
 * Chain building, name matching, validity, transcript construction and DER
 * parsing are all hand-written; OpenSSL libcrypto provides only the raw
 * signature-verify primitive and the public-key object (built from
 * hand-parsed key material), per SPEC C3/N4. */
#ifndef TLS_VERIFY_H
#define TLS_VERIFY_H

#include <stdint.h>
#include <stddef.h>

#include "tls.h"
#include "x509.h"

/* Match a SAN dNSName pattern (not NUL-terminated) against a hostname,
 * case-insensitively, with left-most single-label wildcard support.
 * Returns 1 on match, 0 otherwise. */
int hostname_match(const char *pattern, size_t plen, const char *host);

/* Any leaf SAN dNSName matches host? Returns 0 on match, -1 otherwise. */
int verify_hostname(const x509_cert_t *leaf, const char *host);

/* Verify cert->signatureValue over cert->tbs using issuer_spki (a
 * SubjectPublicKeyInfo). Signature scheme comes from the cert's
 * signatureAlgorithm OID. Returns 0 on success, -1 on failure. */
int verify_cert_signature(const x509_cert_t *cert, const uint8_t *issuer_spki,
                          size_t issuer_spki_len);

/* Verify a TLS 1.3 CertificateVerify (RFC 8446 4.4.3): reconstruct the signed
 * content (64 spaces || context || 0x00 || transcript_hash) and check sig with
 * the leaf public key. scheme is the TLS SignatureScheme code. Returns 0/-1. */
int verify_certificate_verify(const uint8_t *leaf_spki, size_t leaf_spki_len,
                              uint16_t scheme, const uint8_t *sig, size_t siglen,
                              const uint8_t *transcript_hash);

/* Full server certificate check driven from connection state: extract the
 * chain from c->cert_msg, verify hostname, validity, chain signatures up to a
 * trust anchor in c->cafile, and the CertificateVerify in c->cert_verify.
 * Prints the failing step on error. Returns 0 on success, -1 on failure. */
int verify_server_certificate(tls_conn_t *c);

#endif /* TLS_VERIFY_H */
