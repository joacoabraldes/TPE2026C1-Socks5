#include "socks5_parsers.h"

/* ============================ HELLO ============================ */

void hello_parser_init(struct hello_parser *p) {
    p->state        = HELLO_VERSION;
    p->remaining    = 0;
    p->has_noauth   = false;
    p->has_userpass = false;
}

enum hello_state hello_parser_feed(struct hello_parser *p, uint8_t b) {
    switch (p->state) {
        case HELLO_VERSION:
            p->state = (b == 0x05) ? HELLO_NMETHODS : HELLO_ERROR;
            break;
        case HELLO_NMETHODS:
            p->remaining = b;
            p->state = (b == 0) ? HELLO_DONE : HELLO_METHODS;
            break;
        case HELLO_METHODS:
            if (b == SOCKS5_METHOD_NO_AUTH)  p->has_noauth = true;
            if (b == SOCKS5_METHOD_USERPASS) p->has_userpass = true;
            if (--p->remaining == 0) {
                p->state = HELLO_DONE;
            }
            break;
        case HELLO_DONE:
        case HELLO_ERROR:
            break;
    }
    return p->state;
}

bool hello_parser_consume(struct hello_parser *p, buffer *buf, bool *error) {
    while (buffer_can_read(buf)) {
        const uint8_t b = buffer_read(buf);
        hello_parser_feed(p, b);
        if (p->state == HELLO_DONE || p->state == HELLO_ERROR) {
            *error = (p->state == HELLO_ERROR);
            return true;
        }
    }
    return false;
}

/* ============================ AUTH ============================= */

void auth_parser_init(struct auth_parser *p) {
    p->state = AUTH_VERSION;
    p->ulen  = 0;
    p->plen  = 0;
    p->idx   = 0;
    p->username[0] = '\0';
    p->password[0] = '\0';
}

enum auth_state auth_parser_feed(struct auth_parser *p, uint8_t b) {
    switch (p->state) {
        case AUTH_VERSION:
            p->state = (b == 0x01) ? AUTH_ULEN : AUTH_ERROR;
            break;
        case AUTH_ULEN:
            p->ulen = b;
            p->idx  = 0;
            p->state = (b == 0) ? AUTH_ERROR : AUTH_UNAME;
            break;
        case AUTH_UNAME:
            p->username[p->idx++] = (char)b;
            if (p->idx == p->ulen) {
                p->username[p->idx] = '\0';
                p->state = AUTH_PLEN;
            }
            break;
        case AUTH_PLEN:
            p->plen = b;
            p->idx  = 0;
            p->state = (b == 0) ? AUTH_ERROR : AUTH_PASSWD;
            break;
        case AUTH_PASSWD:
            p->password[p->idx++] = (char)b;
            if (p->idx == p->plen) {
                p->password[p->idx] = '\0';
                p->state = AUTH_DONE;
            }
            break;
        case AUTH_DONE:
        case AUTH_ERROR:
            break;
    }
    return p->state;
}

bool auth_parser_consume(struct auth_parser *p, buffer *buf, bool *error) {
    while (buffer_can_read(buf)) {
        const uint8_t b = buffer_read(buf);
        auth_parser_feed(p, b);
        if (p->state == AUTH_DONE || p->state == AUTH_ERROR) {
            *error = (p->state == AUTH_ERROR);
            return true;
        }
    }
    return false;
}

/* ============================ REQUEST ========================= */

void request_parser_init(struct request_parser *p) {
    p->state    = REQ_VERSION;
    p->cmd      = 0;
    p->atyp     = 0;
    p->addr_len = 0;
    p->idx      = 0;
    p->port     = 0;
    p->port_idx = 0;
}

enum request_state request_parser_feed(struct request_parser *p, uint8_t b) {
    switch (p->state) {
        case REQ_VERSION:
            p->state = (b == 0x05) ? REQ_CMD : REQ_ERROR;
            break;
        case REQ_CMD:
            p->cmd = b;
            p->state = REQ_RSV;
            break;
        case REQ_RSV:
            p->state = (b == 0x00) ? REQ_ATYP : REQ_ERROR;
            break;
        case REQ_ATYP:
            p->atyp = b;
            p->idx  = 0;
            if (b == SOCKS5_ATYP_IPV4) {
                p->addr_len = 4;
                p->state = REQ_DADDR_IPV4;
            } else if (b == SOCKS5_ATYP_IPV6) {
                p->addr_len = 16;
                p->state = REQ_DADDR_IPV6;
            } else if (b == SOCKS5_ATYP_DOMAIN) {
                p->state = REQ_DADDR_DOMAIN_LEN;
            } else {
                p->state = REQ_ERROR;
            }
            break;
        case REQ_DADDR_IPV4:
            p->addr[p->idx++] = b;
            if (p->idx == 4) {
                p->port_idx = 0;
                p->state = REQ_DPORT;
            }
            break;
        case REQ_DADDR_DOMAIN_LEN:
            p->addr_len = b;
            p->idx = 0;
            if (b == 0) {
                p->state = REQ_ERROR;
            } else {
                p->state = REQ_DADDR_DOMAIN;
            }
            break;
        case REQ_DADDR_DOMAIN:
            p->addr[p->idx++] = b;
            if (p->idx == p->addr_len) {
                p->addr[p->idx] = '\0';   /* dominio como C-string */
                p->port_idx = 0;
                p->state = REQ_DPORT;
            }
            break;
        case REQ_DADDR_IPV6:
            p->addr[p->idx++] = b;
            if (p->idx == 16) {
                p->port_idx = 0;
                p->state = REQ_DPORT;
            }
            break;
        case REQ_DPORT:
            p->port = (uint16_t)((p->port << 8) | b);
            if (++p->port_idx == 2) {
                p->state = REQ_DONE;
            }
            break;
        case REQ_DONE:
        case REQ_ERROR:
            break;
    }
    return p->state;
}

bool request_parser_consume(struct request_parser *p, buffer *buf, bool *error) {
    while (buffer_can_read(buf)) {
        const uint8_t b = buffer_read(buf);
        request_parser_feed(p, b);
        if (p->state == REQ_DONE || p->state == REQ_ERROR) {
            *error = (p->state == REQ_ERROR);
            return true;
        }
    }
    return false;
}
