#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <string.h>
#include "dns.h"

static void *dns_thread(void *arg) {
    struct dns_request *req = arg;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;      /* IPv4 e IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    req->result = NULL;
    req->status = getaddrinfo(req->host, req->service, &hints, &req->result);

    /* único contacto con el hilo principal: despertarlo. No hace más E/S. */
    selector_notify_block(req->s, req->notify_fd);
    return NULL;
}

int dns_resolve_async(struct dns_request *req) {
    pthread_t th;
    pthread_attr_t attr;
    if (pthread_attr_init(&attr) != 0) {
        return -1;
    }
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int rc = pthread_create(&th, &attr, dns_thread, req);
    pthread_attr_destroy(&attr);
    return rc == 0 ? 0 : -1;
}

void dns_request_clear(struct dns_request *req) {
    if (req != NULL && req->result != NULL) {
        freeaddrinfo(req->result);
        req->result = NULL;
    }
}
