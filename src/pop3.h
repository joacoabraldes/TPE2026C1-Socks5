#ifndef POP3_H
#define POP3_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define POP3_PORT 110

typedef void (*pop3_cred_cb)(void *ctx, const char *user, const char *pass);

struct pop3_sniffer {
    char   line[512];
    size_t len;
    bool   overflow;
    char   user[256];
    bool   have_user;
};

void pop3_sniffer_init(struct pop3_sniffer *p);

void pop3_sniffer_feed(struct pop3_sniffer *p, const uint8_t *data, size_t n,
                       pop3_cred_cb cb, void *ctx);

#endif
