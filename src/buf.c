#include "buf.h"
#include "int.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void buf_die(void) {
    fprintf(stderr, "buf: out of memory\n");
    abort();
}

void buf_init(buf_t *b) {
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

void buf_free(buf_t *b) {
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

void buf_reset(buf_t *b) {
    b->len = 0;
}

void buf_reserve(buf_t *b, size_t additional) {
    if (b->len + additional <= b->cap)
        return;
    size_t ncap = b->cap ? b->cap : 64;
    while (ncap < b->len + additional)
        ncap *= 2;
    uint8_t *nd = realloc(b->data, ncap);
    if (!nd)
        buf_die();
    b->data = nd;
    b->cap = ncap;
}

void buf_append(buf_t *b, const void *p, size_t n) {
    if (n == 0)
        return;
    buf_reserve(b, n);
    memcpy(b->data + b->len, p, n);
    b->len += n;
}

void buf_u8(buf_t *b, uint8_t v) {
    buf_reserve(b, 1);
    b->data[b->len++] = v;
}

void buf_u16(buf_t *b, uint16_t v) {
    buf_reserve(b, 2);
    put_u16(b->data + b->len, v);
    b->len += 2;
}

void buf_u24(buf_t *b, uint32_t v) {
    buf_reserve(b, 3);
    put_u24(b->data + b->len, v);
    b->len += 3;
}

void buf_u32(buf_t *b, uint32_t v) {
    buf_reserve(b, 4);
    put_u32(b->data + b->len, v);
    b->len += 4;
}

size_t buf_begin_u8(buf_t *b) {
    size_t m = b->len;
    buf_u8(b, 0);
    return m;
}

size_t buf_begin_u16(buf_t *b) {
    size_t m = b->len;
    buf_u16(b, 0);
    return m;
}

size_t buf_begin_u24(buf_t *b) {
    size_t m = b->len;
    buf_u24(b, 0);
    return m;
}

void buf_end_u8(buf_t *b, size_t marker) {
    size_t body = b->len - marker - 1;
    put_u8(b->data + marker, (uint8_t)body);
}

void buf_end_u16(buf_t *b, size_t marker) {
    size_t body = b->len - marker - 2;
    put_u16(b->data + marker, (uint16_t)body);
}

void buf_end_u24(buf_t *b, size_t marker) {
    size_t body = b->len - marker - 3;
    put_u24(b->data + marker, (uint32_t)body);
}
