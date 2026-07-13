/* TLS alert level/description names (RFC 8446 section 6). */
#ifndef TLS_ALERT_H
#define TLS_ALERT_H

#include <stdint.h>
#include <stddef.h>

const char *alert_level_name(uint8_t level);
const char *alert_desc_name(uint8_t desc);

/* Print a received alert record body (level, description) to stderr. */
void alert_print(const uint8_t *body, size_t len);

#endif /* TLS_ALERT_H */
