/* Bounds-checked cursor for parsing wire formats (ServerHello, extensions,
 * handshake messages, DER later). Any read past the end sets a sticky error
 * flag and returns zero/NULL; callers check rd_ok() once at the end instead of
 * after every field. */
#ifndef TLS_READER_H
#define TLS_READER_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    const uint8_t *p;
    size_t len;
    size_t off;
    int err;
} rd_t;

void rd_init(rd_t *r, const uint8_t *p, size_t len);
uint8_t rd_u8(rd_t *r);
uint16_t rd_u16(rd_t *r);
uint32_t rd_u24(rd_t *r);
/* Return a pointer to n bytes and advance; NULL (and set err) if out of range. */
const uint8_t *rd_bytes(rd_t *r, size_t n);
size_t rd_remaining(const rd_t *r);
int rd_ok(const rd_t *r);

#endif /* TLS_READER_H */
