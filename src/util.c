#include "util.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

void print_banner(void) {
    /* SPEC N1: the Korean phrase is the required one; the English line mirrors
     * it for non-Korean readers. */
    fprintf(stderr, "========================================\n");
    fprintf(stderr, " 교육용 - 실서비스 사용 금지\n");
    fprintf(stderr, " educational - not for production use\n");
    fprintf(stderr, "========================================\n");
}

noreturn void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(1);
}

void warn(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "warning: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

static char hexdigit(int v) {
    return (char)(v < 10 ? '0' + v : 'a' + (v - 10));
}

void to_hex(char *out, const uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = hexdigit(buf[i] >> 4);
        out[2 * i + 1] = hexdigit(buf[i] & 0xf);
    }
    out[2 * n] = '\0';
}

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

size_t from_hex(uint8_t *dst, size_t dst_cap, const char *hex) {
    size_t n = 0;
    int hi = -1;
    for (const char *p = hex; *p; p++) {
        if (isspace((unsigned char)*p))
            continue;
        int v = hexval((unsigned char)*p);
        if (v < 0)
            return (size_t)-1;
        if (hi < 0) {
            hi = v;
        } else {
            if (n >= dst_cap)
                return (size_t)-1;
            dst[n++] = (uint8_t)((hi << 4) | v);
            hi = -1;
        }
    }
    if (hi >= 0)
        return (size_t)-1; /* odd number of nibbles */
    return n;
}

void dump_hex(const char *label, const uint8_t *buf, size_t n) {
    fprintf(stderr, "%s (%zu):", label, n);
    for (size_t i = 0; i < n; i++)
        fprintf(stderr, " %02x", buf[i]);
    fprintf(stderr, "\n");
}
