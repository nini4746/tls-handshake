/* Post-handshake application data (RFC 8446 section 4.6 / 6.1) and the
 * SSLKEYLOGFILE key log. */
#ifndef TLS_APPDATA_H
#define TLS_APPDATA_H

#include "tls.h"

/* Encrypt and send application data under the client application traffic key. */
int tls_send_app(tls_conn_t *c, const uint8_t *data, size_t len);

/* Receive loop: decrypt application_data records to stdout, discard
 * NewSessionTickets, stop on the server's close_notify or EOF. Returns 0. */
int tls_recv_loop(tls_conn_t *c);

/* Send a close_notify alert and note that the caller should close the socket. */
void tls_close_notify(tls_conn_t *c);

/* If c->keylog is set, append the four NSS-format traffic secrets so a capture
 * can be decrypted in Wireshark. No-op when keylog is NULL (SPEC N5). */
void keylog_write(tls_conn_t *c);

#endif /* TLS_APPDATA_H */
