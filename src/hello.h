/* ClientHello assembly and ServerHello parsing (RFC 8446 4.1.2 / 4.1.3). */
#ifndef TLS_HELLO_H
#define TLS_HELLO_H

#include "tls.h"

/* Generate the client's X25519 key pair, random, and legacy session id. */
void hello_gen_keys(tls_conn_t *c);

/* Build the ClientHello handshake message (type + 3-byte length + body) into
 * out, and append the same bytes to the transcript. */
void hello_build_clienthello(tls_conn_t *c, buf_t *out);

/* Parse a ServerHello handshake body (the bytes after the 4-byte handshake
 * header). On success stores server_random, cipher_suite, and server_pub.
 * Returns 0 on success. Returns -1 on parse error / unacceptable negotiation
 * (wrong version, un-offered cipher suite, non-x25519 key_share).
 * Returns -2 specifically if a HelloRetryRequest was detected (unsupported). */
int hello_parse_serverhello(tls_conn_t *c, const uint8_t *body, size_t len);

#endif /* TLS_HELLO_H */
