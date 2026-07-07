/* socks5_parsers.h - Parsers incrementales (byte a byte) para SOCKS5.
 * Toleran lecturas parciales: se alimentan con los bytes disponibles y avanzan
 * su estado interno; nunca bloquean ni asumen tener el mensaje completo. */
#ifndef SOCKS5_PARSERS_H
#define SOCKS5_PARSERS_H

#include <stdbool.h>
#include <stdint.h>
#include "buffer.h"

/* Métodos de autenticación SOCKS5 */
#define SOCKS5_METHOD_NO_AUTH   0x00
#define SOCKS5_METHOD_USERPASS  0x02
#define SOCKS5_METHOD_NONE      0xFF

/* Comandos SOCKS5 */
#define SOCKS5_CMD_CONNECT       0x01
#define SOCKS5_CMD_BIND          0x02
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03

/* Tipos de dirección (ATYP) */
#define SOCKS5_ATYP_IPV4   0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_ATYP_IPV6   0x04

/* Reply codes (REP) */
#define SOCKS5_REP_SUCCESS               0x00
#define SOCKS5_REP_GENERAL_FAILURE       0x01
#define SOCKS5_REP_NOT_ALLOWED           0x02
#define SOCKS5_REP_NETWORK_UNREACHABLE   0x03
#define SOCKS5_REP_HOST_UNREACHABLE      0x04
#define SOCKS5_REP_CONNECTION_REFUSED    0x05
#define SOCKS5_REP_TTL_EXPIRED           0x06
#define SOCKS5_REP_COMMAND_NOT_SUPPORTED 0x07
#define SOCKS5_REP_ATYP_NOT_SUPPORTED    0x08

/* ---------------- Greeting / negociación de método ---------------- */
enum hello_state {
    HELLO_VERSION,
    HELLO_NMETHODS,
    HELLO_METHODS,
    HELLO_DONE,
    HELLO_ERROR,
};

struct hello_parser {
    enum hello_state state;
    uint8_t          remaining;   /* métodos por leer */
    bool             has_noauth;
    bool             has_userpass;
};

void             hello_parser_init(struct hello_parser *p);
enum hello_state hello_parser_feed(struct hello_parser *p, uint8_t b);
/* Consume de `buf`. Devuelve true si terminó (DONE o ERROR). */
bool             hello_parser_consume(struct hello_parser *p, buffer *buf, bool *error);

/* ---------------- Autenticación user/pass (RFC1929) ---------------- */
enum auth_state {
    AUTH_VERSION,
    AUTH_ULEN,
    AUTH_UNAME,
    AUTH_PLEN,
    AUTH_PASSWD,
    AUTH_DONE,
    AUTH_ERROR,
};

struct auth_parser {
    enum auth_state state;
    uint8_t         ulen;
    uint8_t         plen;
    uint8_t         idx;
    char            username[256];
    char            password[256];
};

void            auth_parser_init(struct auth_parser *p);
enum auth_state auth_parser_feed(struct auth_parser *p, uint8_t b);
bool            auth_parser_consume(struct auth_parser *p, buffer *buf, bool *error);

/* ---------------- Request (CONNECT ...) --------------------------- */
enum request_state {
    REQ_VERSION,
    REQ_CMD,
    REQ_RSV,
    REQ_ATYP,
    REQ_DADDR_IPV4,
    REQ_DADDR_DOMAIN_LEN,
    REQ_DADDR_DOMAIN,
    REQ_DADDR_IPV6,
    REQ_DPORT,
    REQ_DONE,
    REQ_ERROR,
};

struct request_parser {
    enum request_state state;
    uint8_t            cmd;
    uint8_t            atyp;
    uint8_t            addr_len;      /* longitud de dominio */
    uint8_t            idx;
    uint8_t            addr[256];     /* IPv4(4) / IPv6(16) / dominio (str) */
    uint16_t           port;
    uint8_t            port_idx;
};

void               request_parser_init(struct request_parser *p);
enum request_state request_parser_feed(struct request_parser *p, uint8_t b);
bool               request_parser_consume(struct request_parser *p, buffer *buf, bool *error);

#endif /* SOCKS5_PARSERS_H */
