/* Growable byte buffer with big-endian append helpers and back-patched
 * length prefixes. TLS messages are full of nested "length-of-what-follows"
 * fields (extension block length -> extension length -> inner list length);
 * begin_uN / end_uN reserve a placeholder and fill it in once the enclosed
 * bytes are known, which is what keeps ClientHello assembly readable. */
#ifndef TLS_BUF_H
#define TLS_BUF_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} buf_t;

void buf_init(buf_t *b);
void buf_free(buf_t *b);
void buf_reset(buf_t *b);
void buf_reserve(buf_t *b, size_t additional);
void buf_append(buf_t *b, const void *p, size_t n);
void buf_u8(buf_t *b, uint8_t v);
void buf_u16(buf_t *b, uint16_t v);
void buf_u24(buf_t *b, uint32_t v);
void buf_u32(buf_t *b, uint32_t v);

/* Reserve an N-byte length placeholder; returns the offset of the placeholder.
 * The matching end_uN back-patches it with (bytes appended since the marker). */
size_t buf_begin_u8(buf_t *b);
size_t buf_begin_u16(buf_t *b);
size_t buf_begin_u24(buf_t *b);
void buf_end_u8(buf_t *b, size_t marker);
void buf_end_u16(buf_t *b, size_t marker);
void buf_end_u24(buf_t *b, size_t marker);

#endif /* TLS_BUF_H */
