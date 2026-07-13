/* tls-client entry point.
 * Plan 02: connect, send ClientHello, receive and parse ServerHello, print the
 * negotiated parameters. Later plans continue the handshake past ServerHello. */
#include "net.h"
#include "record.h"
#include "handshake_buf.h"
#include "hello.h"
#include "tls.h"
#include "util.h"

#include <stdio.h>
#include <string.h>

/* Receive handshake records until one full handshake message is available.
 * Plaintext only (valid up to ServerHello). Appends the message (with header)
 * to the transcript. Returns 0 and fills type/body/len, or -1 on error. */
static int recv_plaintext_handshake(tls_conn_t *c, hs_buf_t *hb, uint8_t *type,
                                     buf_t *msg_out) {
    for (;;) {
        const uint8_t *body;
        size_t len;
        if (hsbuf_next(hb, type, &body, &len)) {
            buf_reset(msg_out);
            buf_append(msg_out, body - 4, len + 4); /* include 4-byte header */
            buf_append(&c->transcript, body - 4, len + 4);
            return 0;
        }
        record_t rec;
        if (record_read(c->fd, &rec) != 0) {
            warn("record_read failed / connection closed");
            return -1;
        }
        if (rec.type == TLS_CT_HANDSHAKE) {
            hsbuf_push(hb, rec.body, rec.len);
        } else if (rec.type == TLS_CT_ALERT) {
            if (rec.len >= 2)
                warn("server alert: level=%u description=%u", rec.body[0],
                     rec.body[1]);
            record_free(&rec);
            return -1;
        }
        /* ignore ChangeCipherSpec (type 20) and anything else here */
        record_free(&rec);
    }
}

int main(int argc, char **argv) {
    print_banner();

    const char *host = argc > 1 ? argv[1] : "google.com";
    const char *port = argc > 2 ? argv[2] : "443";

    int fd = net_connect(host, port);
    if (fd < 0)
        die("TCP connect to %s:%s failed", host, port);
    printf("TCP connected to %s:%s\n", host, port);

    tls_conn_t c;
    tls_conn_init(&c, fd, host);
    hello_gen_keys(&c);

    buf_t ch;
    buf_init(&ch);
    hello_build_clienthello(&c, &ch);
    if (record_write(fd, TLS_CT_HANDSHAKE, ch.data, ch.len) != 0)
        die("failed to send ClientHello");
    printf("sent ClientHello (%zu bytes)\n", ch.len);
    buf_free(&ch);

    hs_buf_t hb;
    hsbuf_init(&hb);
    uint8_t type;
    buf_t msg;
    buf_init(&msg);
    if (recv_plaintext_handshake(&c, &hb, &type, &msg) != 0)
        die("did not receive ServerHello");
    if (type != HS_SERVER_HELLO)
        die("expected ServerHello, got handshake type %u", type);

    int rc = hello_parse_serverhello(&c, msg.data + 4, msg.len - 4);
    if (rc == -2)
        die("HelloRetryRequest is not supported");
    if (rc != 0)
        die("ServerHello parse/negotiation failed");

    printf("ServerHello OK\n");
    printf("  negotiated cipher suite: 0x%04x (TLS_AES_128_GCM_SHA256)\n",
           c.cipher_suite);
    char hex[2 * X25519_LEN + 1];
    to_hex(hex, c.server_pub, X25519_LEN);
    printf("  server key_share (x25519): %s\n", hex);

    buf_free(&msg);
    hsbuf_free(&hb);
    tls_conn_free(&c);
    net_close(fd);
    return 0;
}
