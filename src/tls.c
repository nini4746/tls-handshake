#include "tls.h"

#include <string.h>

void tls_conn_init(tls_conn_t *c, int fd, const char *host) {
    memset(c, 0, sizeof *c);
    c->fd = fd;
    c->host = host;
    buf_init(&c->transcript);
    buf_init(&c->cert_msg);
    buf_init(&c->cert_verify);
    hsbuf_init(&c->app_hsbuf);
}

void tls_conn_free(tls_conn_t *c) {
    buf_free(&c->transcript);
    buf_free(&c->cert_msg);
    buf_free(&c->cert_verify);
    hsbuf_free(&c->app_hsbuf);
}
