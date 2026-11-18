#include "verify.h"
#include "der.h"
#include "handshake.h"
#include "hkdf.h"
#include "int.h"
#include "pem.h"
#include "util.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_CHAIN 10

typedef enum {
    SIG_UNKNOWN,
    SIG_RSA_PKCS1_SHA256,
    SIG_RSA_PKCS1_SHA384,
    SIG_RSA_PKCS1_SHA512,
    SIG_RSA_PSS_SHA256,
    SIG_RSA_PSS_SHA384,
    SIG_RSA_PSS_SHA512,
    SIG_ECDSA_SHA256,
    SIG_ECDSA_SHA384,
} sig_scheme_t;

/* --- OID / scheme mapping --------------------------------------------- */

static const uint8_t OID_RSA_ENC[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                      0x0d, 0x01, 0x01, 0x01};
static const uint8_t OID_RSASSA_PSS[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                         0x0d, 0x01, 0x01, 0x0a};
static const uint8_t OID_SHA256_RSA[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                         0x0d, 0x01, 0x01, 0x0b};
static const uint8_t OID_SHA384_RSA[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                         0x0d, 0x01, 0x01, 0x0c};
static const uint8_t OID_SHA512_RSA[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                         0x0d, 0x01, 0x01, 0x0d};
static const uint8_t OID_EC_PUBKEY[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01};
static const uint8_t OID_ECDSA_SHA256[] = {0x2a, 0x86, 0x48, 0xce,
                                           0x3d, 0x04, 0x03, 0x02};
static const uint8_t OID_ECDSA_SHA384[] = {0x2a, 0x86, 0x48, 0xce,
                                           0x3d, 0x04, 0x03, 0x03};
static const uint8_t OID_P256[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
static const uint8_t OID_P384[] = {0x2b, 0x81, 0x04, 0x00, 0x22};

static int oid_match(const uint8_t *a, size_t alen, const uint8_t *b,
                     size_t blen) {
    return alen == blen && memcmp(a, b, alen) == 0;
}

static sig_scheme_t scheme_from_oid(const uint8_t *oid, size_t len) {
    if (oid_match(oid, len, OID_SHA256_RSA, sizeof OID_SHA256_RSA))
        return SIG_RSA_PKCS1_SHA256;
    if (oid_match(oid, len, OID_SHA384_RSA, sizeof OID_SHA384_RSA))
        return SIG_RSA_PKCS1_SHA384;
    if (oid_match(oid, len, OID_SHA512_RSA, sizeof OID_SHA512_RSA))
        return SIG_RSA_PKCS1_SHA512;
    if (oid_match(oid, len, OID_RSASSA_PSS, sizeof OID_RSASSA_PSS))
        return SIG_RSA_PSS_SHA256; /* params assumed SHA-256 (common case) */
    if (oid_match(oid, len, OID_ECDSA_SHA256, sizeof OID_ECDSA_SHA256))
        return SIG_ECDSA_SHA256;
    if (oid_match(oid, len, OID_ECDSA_SHA384, sizeof OID_ECDSA_SHA384))
        return SIG_ECDSA_SHA384;
    return SIG_UNKNOWN;
}

static sig_scheme_t scheme_from_tls_code(uint16_t code) {
    switch (code) {
    case 0x0401: return SIG_RSA_PKCS1_SHA256;
    case 0x0501: return SIG_RSA_PKCS1_SHA384;
    case 0x0601: return SIG_RSA_PKCS1_SHA512;
    case 0x0804: return SIG_RSA_PSS_SHA256;
    case 0x0805: return SIG_RSA_PSS_SHA384;
    case 0x0806: return SIG_RSA_PSS_SHA512;
    case 0x0403: return SIG_ECDSA_SHA256;
    case 0x0503: return SIG_ECDSA_SHA384;
    default: return SIG_UNKNOWN;
    }
}

static const EVP_MD *scheme_md(sig_scheme_t s) {
    switch (s) {
    case SIG_RSA_PKCS1_SHA256:
    case SIG_RSA_PSS_SHA256:
    case SIG_ECDSA_SHA256:
        return EVP_sha256();
    case SIG_RSA_PKCS1_SHA384:
    case SIG_RSA_PSS_SHA384:
    case SIG_ECDSA_SHA384:
        return EVP_sha384();
    case SIG_RSA_PKCS1_SHA512:
    case SIG_RSA_PSS_SHA512:
        return EVP_sha512();
    default:
        return NULL;
    }
}

static int scheme_is_pss(sig_scheme_t s) {
    return s == SIG_RSA_PSS_SHA256 || s == SIG_RSA_PSS_SHA384 ||
           s == SIG_RSA_PSS_SHA512;
}

/* --- public key from hand-parsed SubjectPublicKeyInfo ------------------ */

static EVP_PKEY *rsa_pubkey(const uint8_t *bitstr, size_t len) {
    /* bitstr is the BIT STRING content; first byte is unused-bits count (0). */
    if (len < 1)
        return NULL;
    der_tlv_t seq;
    if (der_parse(bitstr + 1, len - 1, &seq) != 0 || seq.tag != DER_SEQUENCE)
        return NULL;
    der_cur_t c;
    der_cur_init(&c, seq.content, seq.content_len);
    der_tlv_t n, e;
    if (der_next(&c, &n) != 1 || der_next(&c, &e) != 1)
        return NULL;

    BIGNUM *bn = BN_bin2bn(n.content, (int)n.content_len, NULL);
    BIGNUM *be = BN_bin2bn(e.content, (int)e.content_len, NULL);
    EVP_PKEY *pk = NULL;
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    if (bn && be && bld && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn) &&
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, be)) {
        OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
        if (params && ctx && EVP_PKEY_fromdata_init(ctx) == 1)
            EVP_PKEY_fromdata(ctx, &pk, EVP_PKEY_PUBLIC_KEY, params);
        EVP_PKEY_CTX_free(ctx);
        OSSL_PARAM_free(params);
    }
    OSSL_PARAM_BLD_free(bld);
    BN_free(bn);
    BN_free(be);
    return pk;
}

static EVP_PKEY *ec_pubkey(const der_tlv_t *curve_oid, const uint8_t *bitstr,
                           size_t len) {
    if (len < 1)
        return NULL;
    const char *group;
    if (oid_match(curve_oid->content, curve_oid->content_len, OID_P256,
                  sizeof OID_P256))
        group = "prime256v1";
    else if (oid_match(curve_oid->content, curve_oid->content_len, OID_P384,
                       sizeof OID_P384))
        group = "secp384r1";
    else
        return NULL;

    const uint8_t *point = bitstr + 1; /* skip unused-bits byte */
    size_t point_len = len - 1;

    EVP_PKEY *pk = NULL;
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    if (bld &&
        OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                        group, 0) &&
        OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, point,
                                         point_len)) {
        OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
        if (params && ctx && EVP_PKEY_fromdata_init(ctx) == 1)
            EVP_PKEY_fromdata(ctx, &pk, EVP_PKEY_PUBLIC_KEY, params);
        EVP_PKEY_CTX_free(ctx);
        OSSL_PARAM_free(params);
    }
    OSSL_PARAM_BLD_free(bld);
    return pk;
}

/* Build an EVP_PKEY from a SubjectPublicKeyInfo (hand-parsed). */
static EVP_PKEY *pubkey_from_spki(const uint8_t *spki, size_t spki_len) {
    der_tlv_t seq;
    if (der_parse(spki, spki_len, &seq) != 0 || seq.tag != DER_SEQUENCE)
        return NULL;
    der_cur_t c;
    der_cur_init(&c, seq.content, seq.content_len);
    der_tlv_t algid, bits;
    if (der_next(&c, &algid) != 1 || algid.tag != DER_SEQUENCE)
        return NULL;
    if (der_next(&c, &bits) != 1 || bits.tag != DER_BIT_STRING)
        return NULL;

    der_cur_t ac;
    der_cur_init(&ac, algid.content, algid.content_len);
    der_tlv_t oid;
    if (der_next(&ac, &oid) != 1 || oid.tag != DER_OID)
        return NULL;

    if (oid_match(oid.content, oid.content_len, OID_RSA_ENC, sizeof OID_RSA_ENC))
        return rsa_pubkey(bits.content, bits.content_len);
    if (oid_match(oid.content, oid.content_len, OID_EC_PUBKEY,
                  sizeof OID_EC_PUBKEY)) {
        der_tlv_t curve;
        if (der_next(&ac, &curve) != 1 || curve.tag != DER_OID)
            return NULL;
        return ec_pubkey(&curve, bits.content, bits.content_len);
    }
    return NULL;
}

/* --- raw signature verify --------------------------------------------- */

static int verify_signature(EVP_PKEY *pk, sig_scheme_t s, const uint8_t *msg,
                            size_t msglen, const uint8_t *sig, size_t siglen) {
    const EVP_MD *md = scheme_md(s);
    if (!md)
        return -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        return -1;
    EVP_PKEY_CTX *pctx = NULL;
    int ok = 0;
    if (EVP_DigestVerifyInit(ctx, &pctx, md, NULL, pk) == 1) {
        int ready = 1;
        if (scheme_is_pss(s)) {
            if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
                EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <=
                    0 ||
                EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) <= 0)
                ready = 0;
        }
        if (ready && EVP_DigestVerify(ctx, sig, siglen, msg, msglen) == 1)
            ok = 1;
    }
    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}

int verify_cert_signature(const x509_cert_t *cert, const uint8_t *issuer_spki,
                          size_t issuer_spki_len) {
    sig_scheme_t s = scheme_from_oid(cert->sig_alg_oid, cert->sig_alg_oid_len);
    if (s == SIG_UNKNOWN)
        return -1;
    EVP_PKEY *pk = pubkey_from_spki(issuer_spki, issuer_spki_len);
    if (!pk)
        return -1;
    int r = verify_signature(pk, s, cert->tbs, cert->tbs_len, cert->sig_value,
                             cert->sig_value_len);
    EVP_PKEY_free(pk);
    return r;
}

/* --- hostname matching ------------------------------------------------- */

int hostname_match(const char *pattern, size_t plen, const char *host) {
    size_t hlen = strlen(host);
    if (plen >= 2 && pattern[0] == '*' && pattern[1] == '.') {
        /* Wildcard matches exactly one left-most label. */
        const char *prest = pattern + 2;
        size_t prlen = plen - 2;
        const char *dot = memchr(host, '.', hlen);
        if (!dot)
            return 0;
        const char *hrest = dot + 1;
        size_t hrlen = hlen - (size_t)(hrest - host);
        return hrlen == prlen && strncasecmp(hrest, prest, prlen) == 0;
    }
    return plen == hlen && strncasecmp(pattern, host, hlen) == 0;
}

int verify_hostname(const x509_cert_t *leaf, const char *host) {
    for (int i = 0; i < leaf->dns_count; i++)
        if (hostname_match(leaf->dns[i], leaf->dns_len[i], host))
            return 0;
    return -1;
}

/* --- CertificateVerify ------------------------------------------------- */

int verify_certificate_verify(const uint8_t *leaf_spki, size_t leaf_spki_len,
                              uint16_t scheme, const uint8_t *sig, size_t siglen,
                              const uint8_t *transcript_hash) {
    static const char *CTX = "TLS 1.3, server CertificateVerify";
    uint8_t content[64 + 64 + 1 + HASH_LEN];
    size_t n = 0;
    memset(content, 0x20, 64);
    n = 64;
    memcpy(content + n, CTX, strlen(CTX));
    n += strlen(CTX);
    content[n++] = 0x00;
    memcpy(content + n, transcript_hash, HASH_LEN);
    n += HASH_LEN;

    sig_scheme_t s = scheme_from_tls_code(scheme);
    if (s == SIG_UNKNOWN) {
        warn("verify: unsupported CertificateVerify scheme 0x%04x", scheme);
        return -1;
    }
    EVP_PKEY *pk = pubkey_from_spki(leaf_spki, leaf_spki_len);
    if (!pk)
        return -1;
    int r = verify_signature(pk, s, content, n, sig, siglen);
    EVP_PKEY_free(pk);
    return r;
}

/* --- full chain verification ------------------------------------------ */

/* Find a trust anchor whose subject matches subj (issuer lookup). */
static const x509_cert_t *ca_find(const ca_store_t *store, const uint8_t *subj,
                                  size_t subj_len) {
    for (int i = 0; i < store->count; i++) {
        const x509_cert_t *ca = &store->entries[i].cert;
        if (x509_name_equal(ca->subject, ca->subject_len, subj, subj_len))
            return ca;
    }
    return NULL;
}

/* Is this presented certificate itself a trust anchor? A root can be sent in
 * the chain (e.g. cross-signed GTS Root R1); match on subject AND public key so
 * we trust it directly rather than requiring its cross-signer. */
static int ca_is_anchor(const ca_store_t *store, const x509_cert_t *cur) {
    for (int i = 0; i < store->count; i++) {
        const x509_cert_t *ca = &store->entries[i].cert;
        if (x509_name_equal(ca->subject, ca->subject_len, cur->subject,
                            cur->subject_len) &&
            ca->spki_len == cur->spki_len &&
            memcmp(ca->spki, cur->spki, cur->spki_len) == 0)
            return 1;
    }
    return 0;
}

int verify_server_certificate(tls_conn_t *c) {
    const uint8_t *der[MAX_CHAIN];
    size_t dlen[MAX_CHAIN];
    int n = certificate_list_parse(c->cert_msg.data, c->cert_msg.len, der, dlen,
                                   MAX_CHAIN);
    if (n <= 0) {
        warn("verify: Certificate message has no certificates");
        return -1;
    }
    if (n > MAX_CHAIN) {
        warn("verify: certificate chain too long (%d > %d)", n, MAX_CHAIN);
        return -1;
    }

    x509_cert_t chain[MAX_CHAIN];
    for (int i = 0; i < n; i++) {
        if (x509_parse(der[i], dlen[i], &chain[i]) != 0) {
            warn("verify: failed to parse certificate %d", i);
            return -1;
        }
    }

    /* Hostname (leaf SAN). */
    if (verify_hostname(&chain[0], c->host) != 0) {
        warn("verify: hostname '%s' does not match any leaf SAN dNSName",
             c->host);
        return -1;
    }

    /* Validity of every presented certificate. */
    time_t now = time(NULL);
    for (int i = 0; i < n; i++) {
        if (now < chain[i].not_before) {
            warn("verify: certificate %d not yet valid", i);
            return -1;
        }
        if (now > chain[i].not_after) {
            warn("verify: certificate %d has expired", i);
            return -1;
        }
    }

    /* Load trust anchors. */
    ca_store_t cas;
    if (pem_load_ca(c->cafile, &cas) != 0) {
        warn("verify: could not load CA bundle '%s'", c->cafile);
        return -1;
    }

    /* Build and verify the chain from leaf up to a trust anchor. */
    int trusted = 0;
    for (int i = 0; i < n && !trusted; i++) {
        x509_cert_t *cur = &chain[i];

        /* If this certificate is itself a trust anchor (root sent in-band), the
         * path is complete: the previous cert was already verified against its
         * key. */
        if (ca_is_anchor(&cas, cur)) {
            trusted = 1;
            break;
        }

        /* Prefer the next presented certificate if it is the issuer. */
        if (i + 1 < n &&
            x509_name_equal(chain[i + 1].subject, chain[i + 1].subject_len,
                            cur->issuer, cur->issuer_len)) {
            x509_cert_t *issuer = &chain[i + 1];
            if (!issuer->is_ca) {
                warn("verify: intermediate %d lacks basicConstraints cA", i + 1);
                ca_store_free(&cas);
                return -1;
            }
            if (verify_cert_signature(cur, issuer->spki, issuer->spki_len) != 0) {
                warn("verify: signature of certificate %d by presented issuer "
                     "failed",
                     i);
                ca_store_free(&cas);
                return -1;
            }
            continue; /* ascend to the issuer */
        }

        /* Otherwise the issuer must be a trust anchor. */
        const x509_cert_t *ca = ca_find(&cas, cur->issuer, cur->issuer_len);
        if (!ca) {
            warn("verify: incomplete chain - issuer of certificate %d not "
                 "found among trust anchors (AIA not followed)",
                 i);
            ca_store_free(&cas);
            return -1;
        }
        if (verify_cert_signature(cur, ca->spki, ca->spki_len) != 0) {
            warn("verify: signature of certificate %d by trust anchor failed", i);
            ca_store_free(&cas);
            return -1;
        }
        trusted = 1;
    }
    ca_store_free(&cas);
    if (!trusted) {
        warn("verify: chain did not terminate at a trust anchor");
        return -1;
    }

    /* CertificateVerify signature over the transcript with the leaf key. */
    if (c->cert_verify.len < 4 || !c->have_th_cert) {
        warn("verify: missing CertificateVerify material");
        return -1;
    }
    uint16_t scheme = get_u16(c->cert_verify.data);
    uint16_t siglen = get_u16(c->cert_verify.data + 2);
    if ((size_t)4 + siglen > c->cert_verify.len) {
        warn("verify: malformed CertificateVerify");
        return -1;
    }
    const uint8_t *sig = c->cert_verify.data + 4;
    if (verify_certificate_verify(chain[0].spki, chain[0].spki_len, scheme, sig,
                                  siglen, c->th_cert) != 0) {
        warn("verify: CertificateVerify signature check failed");
        return -1;
    }

    fprintf(stderr,
            "certificate verified: chain to trust anchor OK, hostname '%s' "
            "matched, CertificateVerify OK\n",
            c->host);
    return 0;
}
