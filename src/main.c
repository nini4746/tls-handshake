/* tls-client entry point.
 * Plan 04: drive the full TLS 1.3 handshake - ClientHello/ServerHello,
 * handshake key derivation, the encrypted server flight, server/client
 * Finished, application key derivation - then drain NewSessionTickets.
 * (Plan 05 adds certificate verification; plan 06 adds application data.) */
#include "handshake.h"
#include "net.h"
#include "tls.h"
#include "util.h"

#include <stdio.h>
#include <string.h>

static void usage(const char *prog) {
    fprintf(stderr,
            "usage: %s <host> [port] [--cafile <pem>] [--keylog <file>]\n"
            "          [--insecure] [--dump-certs]\n",
            prog);
}

int main(int argc, char **argv) {
    print_banner();

    const char *host = NULL;
    const char *port = "443";
    const char *cafile = NULL;
    const char *keylog = NULL;
    int insecure = 0, dump_certs = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--cafile") == 0 && i + 1 < argc) {
            cafile = argv[++i];
        } else if (strcmp(argv[i], "--keylog") == 0 && i + 1 < argc) {
            keylog = argv[++i];
        } else if (strcmp(argv[i], "--insecure") == 0) {
            insecure = 1;
        } else if (strcmp(argv[i], "--dump-certs") == 0) {
            dump_certs = 1;
        } else if (argv[i][0] == '-') {
            usage(argv[0]);
            return 2;
        } else if (!host) {
            host = argv[i];
        } else {
            port = argv[i];
        }
    }
    if (!host) {
        usage(argv[0]);
        return 2;
    }

    int fd = net_connect(host, port);
    if (fd < 0)
        die("TCP connect to %s:%s failed", host, port);
    printf("TCP connected to %s:%s\n", host, port);

    tls_conn_t c;
    tls_conn_init(&c, fd, host);
    c.cafile = cafile;
    c.keylog = keylog;
    c.insecure = insecure;
    c.dump_certs = dump_certs;

    if (handshake_do_hello(&c) != 0)
        die("ClientHello/ServerHello exchange failed");
    printf("ServerHello OK: cipher suite 0x%04x\n", c.cipher_suite);

    if (handshake_run(&c) != 0)
        die("handshake failed");
    printf("handshake complete - server and client Finished verified\n");

    handshake_drain_tickets(&c);

    tls_conn_free(&c);
    net_close(fd);
    return 0;
}
