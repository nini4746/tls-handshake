#include "reader.h"
#include "int.h"

void rd_init(rd_t *r, const uint8_t *p, size_t len) {
    r->p = p;
    r->len = len;
    r->off = 0;
    r->err = 0;
}

static const uint8_t *take(rd_t *r, size_t n) {
    if (r->err || r->off + n > r->len) {
        r->err = 1;
        return NULL;
    }
    const uint8_t *p = r->p + r->off;
    r->off += n;
    return p;
}

uint8_t rd_u8(rd_t *r) {
    const uint8_t *p = take(r, 1);
    return p ? get_u8(p) : 0;
}

uint16_t rd_u16(rd_t *r) {
    const uint8_t *p = take(r, 2);
    return p ? get_u16(p) : 0;
}

uint32_t rd_u24(rd_t *r) {
    const uint8_t *p = take(r, 3);
    return p ? get_u24(p) : 0;
}

const uint8_t *rd_bytes(rd_t *r, size_t n) {
    return take(r, n);
}

size_t rd_remaining(const rd_t *r) {
    if (r->err || r->off > r->len)
        return 0;
    return r->len - r->off;
}

int rd_ok(const rd_t *r) {
    return !r->err;
}
