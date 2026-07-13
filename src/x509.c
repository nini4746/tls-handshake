#include "x509.h"
#include "der.h"

#include <string.h>

/* OID value bytes (after the 06 <len> prefix). */
static const uint8_t OID_SAN[] = {0x55, 0x1d, 0x11};              /* 2.5.29.17 */
static const uint8_t OID_BASIC_CONSTRAINTS[] = {0x55, 0x1d, 0x13};/* 2.5.29.19 */

static int oid_eq(const der_tlv_t *t, const uint8_t *oid, size_t n) {
    return t->tag == DER_OID && t->content_len == n &&
           memcmp(t->content, oid, n) == 0;
}

/* Parse a 2-digit field. */
static int two(const char *p) {
    if (p[0] < '0' || p[0] > '9' || p[1] < '0' || p[1] > '9')
        return -1;
    return (p[0] - '0') * 10 + (p[1] - '0');
}

/* Convert UTCTime / GeneralizedTime (…YYMMDDHHMMSSZ) to time_t. */
static int parse_time(const der_tlv_t *t, time_t *out) {
    const char *s = (const char *)t->content;
    size_t n = t->content_len;
    struct tm tm;
    memset(&tm, 0, sizeof tm);
    int year;
    size_t i;

    if (t->tag == DER_UTCTIME && n >= 13) {
        int yy = two(s);
        if (yy < 0)
            return -1;
        year = (yy >= 50 ? 1900 : 2000) + yy;
        i = 2;
    } else if (t->tag == DER_GENERALIZEDTIME && n >= 15) {
        int hi = two(s), lo = two(s + 2);
        if (hi < 0 || lo < 0)
            return -1;
        year = hi * 100 + lo;
        i = 4;
    } else {
        return -1;
    }

    int mon = two(s + i), day = two(s + i + 2), hh = two(s + i + 4),
        mm = two(s + i + 6), ss = two(s + i + 8);
    if (mon < 1 || day < 0 || hh < 0 || mm < 0 || ss < 0)
        return -1;
    if (s[i + 10] != 'Z') /* only UTC 'Z' form supported */
        return -1;

    tm.tm_year = year - 1900;
    tm.tm_mon = mon - 1;
    tm.tm_mday = day;
    tm.tm_hour = hh;
    tm.tm_min = mm;
    tm.tm_sec = ss;
    *out = timegm(&tm);
    return 0;
}

static int parse_validity(const der_tlv_t *validity, x509_cert_t *out) {
    der_cur_t c;
    der_cur_init(&c, validity->content, validity->content_len);
    der_tlv_t nb, na;
    if (der_next(&c, &nb) != 1 || der_next(&c, &na) != 1)
        return -1;
    if (parse_time(&nb, &out->not_before) != 0)
        return -1;
    if (parse_time(&na, &out->not_after) != 0)
        return -1;
    return 0;
}

/* SAN extnValue content is a SEQUENCE of GeneralName; dNSName is [2] (0x82). */
static void parse_san(const uint8_t *val, size_t len, x509_cert_t *out) {
    der_tlv_t seq;
    if (der_parse(val, len, &seq) != 0 || seq.tag != DER_SEQUENCE)
        return;
    der_cur_t c;
    der_cur_init(&c, seq.content, seq.content_len);
    der_tlv_t gn;
    while (der_next(&c, &gn) == 1) {
        if (gn.tag == 0x82 && out->dns_count < X509_MAX_SAN) { /* dNSName */
            out->dns[out->dns_count] = (const char *)gn.content;
            out->dns_len[out->dns_count] = gn.content_len;
            out->dns_count++;
        }
    }
}

/* basicConstraints extnValue content is SEQUENCE { cA BOOLEAN DEFAULT FALSE,
 * pathLenConstraint INTEGER OPTIONAL }. */
static void parse_basic_constraints(const uint8_t *val, size_t len,
                                    x509_cert_t *out) {
    der_tlv_t seq;
    if (der_parse(val, len, &seq) != 0 || seq.tag != DER_SEQUENCE)
        return;
    out->has_basic_constraints = 1;
    der_cur_t c;
    der_cur_init(&c, seq.content, seq.content_len);
    der_tlv_t t;
    if (der_next(&c, &t) == 1 && t.tag == DER_BOOLEAN && t.content_len == 1)
        out->is_ca = t.content[0] != 0;
}

static void parse_extensions(const der_tlv_t *ext_ctx, x509_cert_t *out) {
    /* ext_ctx is [3] EXPLICIT; its content is a single SEQUENCE OF Extension. */
    der_tlv_t seq;
    if (der_parse(ext_ctx->content, ext_ctx->content_len, &seq) != 0 ||
        seq.tag != DER_SEQUENCE)
        return;
    der_cur_t c;
    der_cur_init(&c, seq.content, seq.content_len);
    der_tlv_t ext;
    while (der_next(&c, &ext) == 1) {
        if (ext.tag != DER_SEQUENCE)
            continue;
        der_cur_t ec;
        der_cur_init(&ec, ext.content, ext.content_len);
        der_tlv_t oid, t;
        if (der_next(&ec, &oid) != 1)
            continue;
        /* optional critical BOOLEAN, then extnValue OCTET STRING */
        if (der_next(&ec, &t) != 1)
            continue;
        if (t.tag == DER_BOOLEAN && der_next(&ec, &t) != 1)
            continue;
        if (t.tag != DER_OCTET_STRING)
            continue;
        if (oid_eq(&oid, OID_SAN, sizeof OID_SAN))
            parse_san(t.content, t.content_len, out);
        else if (oid_eq(&oid, OID_BASIC_CONSTRAINTS, sizeof OID_BASIC_CONSTRAINTS))
            parse_basic_constraints(t.content, t.content_len, out);
    }
}

int x509_parse(const uint8_t *der, size_t len, x509_cert_t *out) {
    memset(out, 0, sizeof *out);

    der_tlv_t cert;
    if (der_parse(der, len, &cert) != 0 || cert.tag != DER_SEQUENCE)
        return -1;

    der_cur_t top;
    der_cur_init(&top, cert.content, cert.content_len);
    der_tlv_t tbs, sigalg, sigval;
    if (der_next(&top, &tbs) != 1 || tbs.tag != DER_SEQUENCE)
        return -1;
    if (der_next(&top, &sigalg) != 1 || sigalg.tag != DER_SEQUENCE)
        return -1;
    if (der_next(&top, &sigval) != 1 || sigval.tag != DER_BIT_STRING)
        return -1;

    out->tbs = tbs.hdr;
    out->tbs_len = tbs.total_len;

    /* signatureAlgorithm: first child is the OID. */
    der_cur_t sa;
    der_cur_init(&sa, sigalg.content, sigalg.content_len);
    der_tlv_t oid;
    if (der_next(&sa, &oid) != 1 || oid.tag != DER_OID)
        return -1;
    out->sig_alg_oid = oid.content;
    out->sig_alg_oid_len = oid.content_len;

    /* signatureValue BIT STRING: first content byte is the unused-bits count. */
    if (sigval.content_len < 1)
        return -1;
    out->sig_value = sigval.content + 1;
    out->sig_value_len = sigval.content_len - 1;

    /* Walk tbsCertificate. */
    der_cur_t tc;
    der_cur_init(&tc, tbs.content, tbs.content_len);
    der_tlv_t t;
    if (der_next(&tc, &t) != 1)
        return -1;
    if (t.tag == DER_CTX_0) { /* version [0] */
        if (der_next(&tc, &t) != 1)
            return -1;
    }
    /* t = serialNumber INTEGER */
    if (der_next(&tc, &t) != 1) /* signature AlgorithmIdentifier */
        return -1;
    if (der_next(&tc, &t) != 1 || t.tag != DER_SEQUENCE) /* issuer */
        return -1;
    out->issuer = t.hdr;
    out->issuer_len = t.total_len;
    if (der_next(&tc, &t) != 1 || t.tag != DER_SEQUENCE) /* validity */
        return -1;
    if (parse_validity(&t, out) != 0)
        return -1;
    if (der_next(&tc, &t) != 1 || t.tag != DER_SEQUENCE) /* subject */
        return -1;
    out->subject = t.hdr;
    out->subject_len = t.total_len;
    if (der_next(&tc, &t) != 1 || t.tag != DER_SEQUENCE) /* SPKI */
        return -1;
    out->spki = t.hdr;
    out->spki_len = t.total_len;

    /* Remaining optional fields: look for extensions [3]. */
    while (der_next(&tc, &t) == 1) {
        if (t.tag == DER_CTX_3) {
            parse_extensions(&t, out);
            break;
        }
    }
    return 0;
}

int x509_name_equal(const uint8_t *a, size_t alen, const uint8_t *b,
                    size_t blen) {
    return alen == blen && memcmp(a, b, alen) == 0;
}
