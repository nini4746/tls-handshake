/* Small shared helpers: fatal error, warning, banner, hex dump. */
#ifndef TLS_UTIL_H
#define TLS_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <stdnoreturn.h>

/* Print "educational - not for production use" (SPEC N1). */
void print_banner(void);

noreturn void die(const char *fmt, ...);
void warn(const char *fmt, ...);

/* Append lowercase hex of buf into out (out must hold 2*n+1 bytes). */
void to_hex(char *out, const uint8_t *buf, size_t n);

/* Parse a hex string (ignoring spaces/newlines) into dst; returns bytes
 * written, or (size_t)-1 on malformed input / overflow. */
size_t from_hex(uint8_t *dst, size_t dst_cap, const char *hex);

/* Print "label: <hex>" to stderr, for debugging non-secret values. */
void dump_hex(const char *label, const uint8_t *buf, size_t n);

#endif /* TLS_UTIL_H */
