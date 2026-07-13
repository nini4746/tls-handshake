#include "der.h"

int der_parse(const uint8_t *p, size_t len, der_tlv_t *out) {
    if (len < 2)
        return -1;
    size_t i = 0;
    out->hdr = p;
    out->tag = p[i++];

    size_t l;
    uint8_t b = p[i++];
    if (b < 0x80) {
        l = b; /* short form */
    } else {
        int nb = b & 0x7f;
        if (nb == 0 || nb > 4) /* indefinite or absurdly long: reject */
            return -1;
        if (i + (size_t)nb > len)
            return -1;
        l = 0;
        for (int k = 0; k < nb; k++)
            l = (l << 8) | p[i++];
    }
    if (i + l > len)
        return -1;

    out->content = p + i;
    out->content_len = l;
    out->total_len = i + l;
    return 0;
}

void der_cur_init(der_cur_t *c, const uint8_t *p, size_t len) {
    c->p = p;
    c->len = len;
    c->off = 0;
    c->err = 0;
}

int der_next(der_cur_t *c, der_tlv_t *out) {
    if (c->err)
        return -1;
    if (c->off >= c->len)
        return 0;
    if (der_parse(c->p + c->off, c->len - c->off, out) != 0) {
        c->err = 1;
        return -1;
    }
    c->off += out->total_len;
    return 1;
}
