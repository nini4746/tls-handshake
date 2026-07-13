/* Plan 01 verification: record header parsing, length limit, and handshake
 * reassembly across the two independent-boundary cases. No socket needed. */
#include "test_util.h"

#include "../src/record.h"
#include "../src/handshake_buf.h"
#include "../src/int.h"

#include <stdint.h>

static void test_header_parse(void) {
    /* handshake, version 0x0303, length 0x0010 */
    uint8_t hdr[5] = {22, 0x03, 0x03, 0x00, 0x10};
    uint8_t type;
    uint16_t ver, len;
    CHECK(record_parse_header(hdr, &type, &ver, &len) == 0);
    CHECK(type == 22);
    CHECK(ver == 0x0303);
    CHECK(len == 16);
}

static void test_length_limit(void) {
    uint8_t type;
    uint16_t ver, len;
    /* Exactly 2^14 + 256 is accepted. */
    uint8_t ok[5] = {23, 0x03, 0x03, 0x00, 0x00};
    put_u16(ok + 3, 16384 + 256);
    CHECK(record_parse_header(ok, &type, &ver, &len) == 0);
    CHECK(len == 16384 + 256);

    /* One over the limit is rejected. */
    uint8_t bad[5] = {23, 0x03, 0x03, 0x00, 0x00};
    put_u16(bad + 3, 16384 + 257);
    CHECK(record_parse_header(bad, &type, &ver, &len) == -1);
}

/* One handshake message spread across two record fragments. */
static void test_message_across_records(void) {
    hs_buf_t h;
    hsbuf_init(&h);

    /* One message: type=8 (EncryptedExtensions), length=6, body=010203040506 */
    uint8_t full[10] = {8, 0x00, 0x00, 0x06, 1, 2, 3, 4, 5, 6};

    uint8_t type;
    const uint8_t *body;
    size_t len;

    /* First fragment carries 5 bytes: header + 1 body byte. Incomplete. */
    hsbuf_push(&h, full, 5);
    CHECK(hsbuf_next(&h, &type, &body, &len) == 0);

    /* Second fragment carries the remaining 5 body bytes. Now complete. */
    hsbuf_push(&h, full + 5, 5);
    CHECK(hsbuf_next(&h, &type, &body, &len) == 1);
    CHECK(type == 8);
    CHECK(len == 6);
    uint8_t expect[6] = {1, 2, 3, 4, 5, 6};
    CHECK_MEM(body, expect, 6);
    /* The 4-byte handshake header sits just before body (used for transcript). */
    CHECK(body[-4] == 8);
    CHECK(get_u24(body - 3) == 6);

    /* Nothing left. */
    CHECK(hsbuf_next(&h, &type, &body, &len) == 0);
    hsbuf_free(&h);
}

/* Two handshake messages inside a single record fragment. */
static void test_two_messages_one_record(void) {
    hs_buf_t h;
    hsbuf_init(&h);

    uint8_t rec[12] = {
        20, 0x00, 0x00, 0x02, 0xaa, 0xbb, /* msg1: type=20 len=2 */
        11, 0x00, 0x00, 0x02, 0xcc, 0xdd, /* msg2: type=11 len=2 */
    };
    hsbuf_push(&h, rec, sizeof rec);

    uint8_t type;
    const uint8_t *body;
    size_t len;

    CHECK(hsbuf_next(&h, &type, &body, &len) == 1);
    CHECK(type == 20 && len == 2);
    CHECK(body[0] == 0xaa && body[1] == 0xbb);

    CHECK(hsbuf_next(&h, &type, &body, &len) == 1);
    CHECK(type == 11 && len == 2);
    CHECK(body[0] == 0xcc && body[1] == 0xdd);

    CHECK(hsbuf_next(&h, &type, &body, &len) == 0);
    hsbuf_free(&h);
}

/* Byte-at-a-time feed: simulates the worst-case partial-read boundary. */
static void test_byte_by_byte(void) {
    hs_buf_t h;
    hsbuf_init(&h);
    uint8_t full[10] = {8, 0x00, 0x00, 0x06, 1, 2, 3, 4, 5, 6};
    uint8_t type;
    const uint8_t *body;
    size_t len;
    for (size_t i = 0; i < 9; i++) {
        hsbuf_push(&h, full + i, 1);
        CHECK(hsbuf_next(&h, &type, &body, &len) == 0);
    }
    hsbuf_push(&h, full + 9, 1);
    CHECK(hsbuf_next(&h, &type, &body, &len) == 1);
    CHECK(type == 8 && len == 6);
    hsbuf_free(&h);
}

int main(void) {
    printf("test_record\n");
    test_header_parse();
    test_length_limit();
    test_message_across_records();
    test_two_messages_one_record();
    test_byte_by_byte();
    TEST_REPORT();
}
