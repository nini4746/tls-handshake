#include "record.h"
#include "int.h"
#include "net.h"

#include <stdlib.h>
#include <string.h>

int record_parse_header(const uint8_t hdr[TLS_RECORD_HDR_LEN], uint8_t *type,
                        uint16_t *version, uint16_t *len) {
    uint8_t t = get_u8(hdr);
    uint16_t v = get_u16(hdr + 1);
    uint16_t l = get_u16(hdr + 3);
    if (l > TLS_RECORD_MAX_FRAGMENT)
        return -1;
    *type = t;
    *version = v;
    *len = l;
    return 0;
}

int record_read(int fd, record_t *out) {
    uint8_t hdr[TLS_RECORD_HDR_LEN];
    if (read_full(fd, hdr, TLS_RECORD_HDR_LEN) != 0)
        return -1;

    uint16_t len;
    if (record_parse_header(hdr, &out->type, &out->version, &len) != 0)
        return -1;

    uint8_t *body = NULL;
    if (len > 0) {
        body = malloc(len);
        if (!body)
            return -1;
        if (read_full(fd, body, len) != 0) {
            free(body);
            return -1;
        }
    }
    out->body = body;
    out->len = len;
    return 0;
}

void record_free(record_t *r) {
    free(r->body);
    r->body = NULL;
    r->len = 0;
}

int record_write(int fd, uint8_t type, const uint8_t *body, size_t len) {
    if (len > TLS_RECORD_MAX_FRAGMENT)
        return -1;
    uint8_t hdr[TLS_RECORD_HDR_LEN];
    put_u8(hdr, type);
    put_u16(hdr + 1, 0x0303); /* legacy_record_version: TLS 1.2 on the wire */
    put_u16(hdr + 3, (uint16_t)len);
    if (write_full(fd, hdr, TLS_RECORD_HDR_LEN) != 0)
        return -1;
    if (len > 0 && write_full(fd, body, len) != 0)
        return -1;
    return 0;
}
