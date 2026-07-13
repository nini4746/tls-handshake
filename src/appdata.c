#include "appdata.h"
#include "aead.h"
#include "alert.h"
#include "handshake.h"
#include "net.h"
#include "record.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int tls_send_app(tls_conn_t *c, const uint8_t *data, size_t len) {
    buf_t rec;
    buf_init(&rec);
    int rc = aead_seal(&c->wr_app, TLS_CT_APPLICATION_DATA, data, len, &rec);
    if (rc == 0)
        rc = write_full(c->fd, rec.data, rec.len);
    buf_free(&rec);
    return rc;
}

int tls_recv_loop(tls_conn_t *c) {
    net_set_recv_timeout(c->fd, 10);
    for (;;) {
        record_t rec;
        if (record_read(c->fd, &rec) != 0)
            break; /* EOF / timeout */

        if (rec.type == TLS_CT_CHANGE_CIPHER_SPEC) {
            record_free(&rec);
            continue;
        }
        if (rec.type == TLS_CT_ALERT) { /* plaintext alert */
            alert_print(rec.body, rec.len);
            record_free(&rec);
            break;
        }
        if (rec.type != TLS_CT_APPLICATION_DATA) {
            record_free(&rec);
            continue;
        }

        uint8_t *plain = malloc(rec.len ? rec.len : 1);
        size_t plen;
        uint8_t inner;
        if (aead_open(&c->rd_app, rec.hdr, rec.body, rec.len, plain, &plen,
                      &inner) != 0) {
            warn("application record decryption failed");
            free(plain);
            record_free(&rec);
            break;
        }

        int stop = 0;
        if (inner == TLS_CT_APPLICATION_DATA) {
            fwrite(plain, 1, plen, stdout);
            fflush(stdout);
        } else if (inner == TLS_CT_HANDSHAKE) {
            hsbuf_push(&c->app_hsbuf, plain, plen);
            uint8_t t;
            const uint8_t *b;
            size_t l;
            while (hsbuf_next(&c->app_hsbuf, &t, &b, &l)) {
                if (t == HS_NEW_SESSION_TICKET)
                    fprintf(stderr,
                            "NewSessionTicket (%zu bytes) parsed and ignored "
                            "(no session resumption)\n",
                            l);
            }
        } else if (inner == TLS_CT_ALERT) {
            alert_print(plain, plen);
            stop = 1; /* close_notify or fatal: stop */
        }
        free(plain);
        record_free(&rec);
        if (stop)
            break;
    }
    net_set_recv_timeout(c->fd, 0);
    return 0;
}

void tls_close_notify(tls_conn_t *c) {
    /* Alert: level=warning(1), description=close_notify(0). */
    uint8_t alert[2] = {1, 0};
    buf_t rec;
    buf_init(&rec);
    if (aead_seal(&c->wr_app, TLS_CT_ALERT, alert, sizeof alert, &rec) == 0)
        (void)write_full(c->fd, rec.data, rec.len);
    buf_free(&rec);
}

static void keylog_line(FILE *f, const char *label, const uint8_t *cr,
                        const uint8_t *secret) {
    char cr_hex[2 * TLS_RANDOM_LEN + 1];
    char s_hex[2 * HASH_LEN + 1];
    to_hex(cr_hex, cr, TLS_RANDOM_LEN);
    to_hex(s_hex, secret, HASH_LEN);
    fprintf(f, "%s %s %s\n", label, cr_hex, s_hex);
}

void keylog_write(tls_conn_t *c) {
    if (!c->keylog) /* SPEC N5: only on explicit --keylog */
        return;
    FILE *f = fopen(c->keylog, "a");
    if (!f) {
        warn("cannot open keylog file '%s'", c->keylog);
        return;
    }
    keylog_line(f, "CLIENT_HANDSHAKE_TRAFFIC_SECRET", c->client_random,
                c->ks.client_hs_traffic);
    keylog_line(f, "SERVER_HANDSHAKE_TRAFFIC_SECRET", c->client_random,
                c->ks.server_hs_traffic);
    keylog_line(f, "CLIENT_TRAFFIC_SECRET_0", c->client_random,
                c->ks.client_ap_traffic);
    keylog_line(f, "SERVER_TRAFFIC_SECRET_0", c->client_random,
                c->ks.server_ap_traffic);
    fclose(f);
    fprintf(stderr, "wrote key log to %s\n", c->keylog);
}
