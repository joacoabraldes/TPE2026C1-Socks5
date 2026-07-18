#include <strings.h>
#include <stdio.h>
#include "pop3.h"

void pop3_sniffer_init(struct pop3_sniffer *p) {
    p->len = 0;
    p->overflow = false;
    p->have_user = false;
    p->user[0] = '\0';
}

static void process_line(struct pop3_sniffer *p, pop3_cred_cb cb, void *ctx) {
    if (strncasecmp(p->line, "USER ", 5) == 0) {
        snprintf(p->user, sizeof(p->user), "%s", p->line + 5);
        p->have_user = true;
    } else if (strncasecmp(p->line, "PASS ", 5) == 0 && p->have_user) {
        cb(ctx, p->user, p->line + 5);
        p->have_user = false;
    }
}

void pop3_sniffer_feed(struct pop3_sniffer *p, const uint8_t *data, size_t n,
                       pop3_cred_cb cb, void *ctx) {
    for (size_t i = 0; i < n; i++) {
        const uint8_t c = data[i];
        if (c == '\n') {
            size_t end = p->len;
            if (end > 0 && p->line[end - 1] == '\r') {
                end--;
            }
            p->line[end] = '\0';
            if (!p->overflow) {
                process_line(p, cb, ctx);
            }
            p->len = 0;
            p->overflow = false;
        } else if (!p->overflow) {
            if (p->len < sizeof(p->line) - 1) {
                p->line[p->len++] = (char)c;
            } else {
                p->overflow = true;
            }
        }
    }
}
