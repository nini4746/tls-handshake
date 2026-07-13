/* Big-endian integer read/write helpers.
 * TLS is big-endian ("network byte order") everywhere, so every plan builds
 * on these. u24 exists because TLS handshake message lengths are 3 bytes. */
#ifndef TLS_INT_H
#define TLS_INT_H

#include <stdint.h>
#include <stddef.h>

static inline void put_u8(uint8_t *p, uint8_t v) { p[0] = v; }

static inline void put_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xff);
}

static inline void put_u24(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)((v >> 16) & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
    p[2] = (uint8_t)(v & 0xff);
}

static inline void put_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)((v >> 24) & 0xff);
    p[1] = (uint8_t)((v >> 16) & 0xff);
    p[2] = (uint8_t)((v >> 8) & 0xff);
    p[3] = (uint8_t)(v & 0xff);
}

static inline uint8_t get_u8(const uint8_t *p) { return p[0]; }

static inline uint16_t get_u16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static inline uint32_t get_u24(const uint8_t *p) {
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}

static inline uint32_t get_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

#endif /* TLS_INT_H */
