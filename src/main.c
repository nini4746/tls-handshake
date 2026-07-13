/* tls-client entry point.
 * Plan 01: banner + TCP connectivity smoke test. Later plans extend this into
 * the full TLS 1.3 handshake driver. */
#include "net.h"
#include "util.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    print_banner();

    const char *host = argc > 1 ? argv[1] : "google.com";
    const char *port = argc > 2 ? argv[2] : "443";

    printf("connecting to %s:%s ...\n", host, port);
    int fd = net_connect(host, port);
    if (fd < 0)
        die("TCP connect failed");
    printf("TCP connected (fd=%d)\n", fd);
    net_close(fd);
    return 0;
}
