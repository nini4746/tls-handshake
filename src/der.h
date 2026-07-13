/* Minimal ASN.1 DER parser: a TLV (tag/length/value) cursor.
 * Not a general ASN.1 library - just enough to walk a certificate structure
 * (RFC 5280) by hand, keeping raw byte ranges so signatures verify against the
 * original encoding (SPEC C3: DER parsing hand-written). */
#ifndef TLS_DER_H
#define TLS_DER_H

#include <stdint.h>
#include <stddef.h>

/* Common DER tags. */
#define DER_BOOLEAN 0x01
#define DER_INTEGER 0x02
#define DER_BIT_STRING 0x03
#define DER_OCTET_STRING 0x04
#define DER_NULL 0x05
#define DER_OID 0x06
#define DER_UTF8STRING 0x0c
#define DER_PRINTABLESTRING 0x13
#define DER_IA5STRING 0x16
#define DER_UTCTIME 0x17
#define DER_GENERALIZEDTIME 0x18
#define DER_SEQUENCE 0x30
#define DER_SET 0x31
#define DER_CTX_0 0xa0 /* [0] constructed (explicit) */
#define DER_CTX_3 0xa3 /* [3] constructed (explicit) - extensions */

typedef struct {
    uint8_t tag;
    const uint8_t *hdr;      /* start of the TLV (tag byte) */
    const uint8_t *content;  /* value bytes */
    size_t content_len;      /* value length */
    size_t total_len;        /* tag + length octets + value */
} der_tlv_t;

/* Parse one TLV at p (bounded by len). Returns 0 on success, -1 on malformed. */
int der_parse(const uint8_t *p, size_t len, der_tlv_t *out);

/* Cursor iterating the children within a constructed value. */
typedef struct {
    const uint8_t *p;
    size_t len;
    size_t off;
    int err;
} der_cur_t;

void der_cur_init(der_cur_t *c, const uint8_t *p, size_t len);
/* Returns 1 and fills out with the next TLV, 0 at end, -1 on malformed. */
int der_next(der_cur_t *c, der_tlv_t *out);

#endif /* TLS_DER_H */
