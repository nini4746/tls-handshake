/* TLS record layer (RFC 8446 section 5.1).
 * A record is: type(1) + legacy_version(2) + length(2) + fragment[length].
 * The record boundary is independent of the handshake-message boundary; see
 * handshake_buf.h for reassembly. */
#ifndef TLS_RECORD_H
#define TLS_RECORD_H

#include <stdint.h>
#include <stddef.h>

/* ContentType values (RFC 8446 section 5.1). */
#define TLS_CT_CHANGE_CIPHER_SPEC 20
#define TLS_CT_ALERT 21
#define TLS_CT_HANDSHAKE 22
#define TLS_CT_APPLICATION_DATA 23

#define TLS_RECORD_HDR_LEN 5
/* Max fragment length we accept: 2^14 + 256 (TLSCiphertext ceiling). */
#define TLS_RECORD_MAX_FRAGMENT (16384 + 256)

typedef struct {
    uint8_t type;
    uint16_t version;   /* legacy_record_version */
    uint8_t hdr[TLS_RECORD_HDR_LEN]; /* raw 5-byte header, as received (AEAD AAD) */
    uint8_t *body;      /* malloc'd fragment; caller frees */
    size_t len;
} record_t;

/* Parse a 5-byte record header. Fills type/version/len.
 * Returns 0 on success, -1 if len exceeds TLS_RECORD_MAX_FRAGMENT. */
int record_parse_header(const uint8_t hdr[TLS_RECORD_HDR_LEN], uint8_t *type,
                        uint16_t *version, uint16_t *len);

/* Read one record from fd. Allocates out->body. Returns 0 ok, -1 on
 * error/EOF or oversized fragment. */
int record_read(int fd, record_t *out);

void record_free(record_t *r);

/* Write one record to fd with the given content type and fragment. */
int record_write(int fd, uint8_t type, const uint8_t *body, size_t len);

#endif /* TLS_RECORD_H */
