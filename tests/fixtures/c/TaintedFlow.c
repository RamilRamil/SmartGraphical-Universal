#include <string.h>

/* Unguarded: untrusted recv() length flows into memcpy without a check. */
void handle_packet(int sock, char *src) {
    char dest[64];
    int n = recv(sock, dest, 64);
    memcpy(dest, src, n);
}

/* Guarded: a check on the tainted length intervenes before the sink. */
void handle_guarded(int sock, char *src) {
    char dest[64];
    int n = recv(sock, dest, 64);
    if (n > 0) {
        memcpy(dest, src, n);
    }
}
