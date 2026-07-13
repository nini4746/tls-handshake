#include "tls.h"

#include <string.h>

void tls_conn_init(tls_conn_t *c, int fd, const char *host) {
    memset(c, 0, sizeof *c);
    c->fd = fd;
    c->host = host;
    buf_init(&c->transcript);
}

void tls_conn_free(tls_conn_t *c) {
    buf_free(&c->transcript);
}
