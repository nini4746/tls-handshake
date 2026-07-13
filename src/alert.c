#include "alert.h"

#include <stdio.h>

const char *alert_level_name(uint8_t level) {
    switch (level) {
    case 1: return "warning";
    case 2: return "fatal";
    default: return "unknown";
    }
}

const char *alert_desc_name(uint8_t desc) {
    switch (desc) {
    case 0: return "close_notify";
    case 10: return "unexpected_message";
    case 20: return "bad_record_mac";
    case 22: return "record_overflow";
    case 40: return "handshake_failure";
    case 42: return "bad_certificate";
    case 43: return "unsupported_certificate";
    case 44: return "certificate_revoked";
    case 45: return "certificate_expired";
    case 46: return "certificate_unknown";
    case 47: return "illegal_parameter";
    case 48: return "unknown_ca";
    case 49: return "access_denied";
    case 50: return "decode_error";
    case 51: return "decrypt_error";
    case 70: return "protocol_version";
    case 71: return "insufficient_security";
    case 80: return "internal_error";
    case 86: return "inappropriate_fallback";
    case 90: return "user_canceled";
    case 109: return "missing_extension";
    case 110: return "unsupported_extension";
    case 112: return "unrecognized_name";
    case 116: return "certificate_required";
    case 120: return "no_application_protocol";
    default: return "unknown";
    }
}

void alert_print(const uint8_t *body, size_t len) {
    if (len < 2) {
        fprintf(stderr, "alert: (truncated)\n");
        return;
    }
    fprintf(stderr, "alert: level=%s(%u) description=%s(%u)\n",
            alert_level_name(body[0]), body[0], alert_desc_name(body[1]),
            body[1]);
}
