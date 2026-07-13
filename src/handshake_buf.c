#include "handshake_buf.h"
#include "int.h"

#include <string.h>

void hsbuf_init(hs_buf_t *h) {
    buf_init(&h->acc);
    h->consumed = 0;
}

void hsbuf_free(hs_buf_t *h) {
    buf_free(&h->acc);
    h->consumed = 0;
}

void hsbuf_push(hs_buf_t *h, const uint8_t *data, size_t n) {
    /* Compact: drop already-consumed prefix so the buffer can't grow forever.
     * Done before appending so pointers returned during the previous drain
     * loop are not disturbed mid-loop (the caller drains fully before pushing
     * again). */
    if (h->consumed > 0) {
        size_t remain = h->acc.len - h->consumed;
        if (remain > 0)
            memmove(h->acc.data, h->acc.data + h->consumed, remain);
        h->acc.len = remain;
        h->consumed = 0;
    }
    buf_append(&h->acc, data, n);
}

int hsbuf_next(hs_buf_t *h, uint8_t *type, const uint8_t **body, size_t *len) {
    size_t avail = h->acc.len - h->consumed;
    if (avail < 4)
        return 0; /* not even a full handshake header yet */

    const uint8_t *p = h->acc.data + h->consumed;
    uint32_t mlen = get_u24(p + 1);
    if (avail < (size_t)4 + mlen)
        return 0; /* header known, body incomplete */

    *type = p[0];
    *body = p + 4;
    *len = mlen;
    h->consumed += (size_t)4 + mlen;
    return 1;
}
