/* args.h - Parsing de argumentos de línea de comandos del servidor.
 * Módulo aislado (IEEE Std 1003.1-2008 / getopt) para poder reemplazarlo
 * por la implementación de la cátedra sin tocar el resto del código. */
#ifndef UTIL_ARGS_H
#define UTIL_ARGS_H

#include <stdbool.h>
#include <stddef.h>
#include "users.h"

struct args_user {
    char name[USERS_MAX_NAME + 1];
    char pass[USERS_MAX_PASS + 1];
};

struct socks5args {
    char           socks_addr[64];   /* "" => todas las interfaces */
    unsigned short socks_port;       /* default 1080               */
    char           mgmt_addr[64];    /* default 127.0.0.1          */
    unsigned short mgmt_port;        /* default 8080               */

    char           admin_user[USERS_MAX_NAME + 1];
    char           admin_pass[USERS_MAX_PASS + 1];

    bool           require_auth;     /* forzar user/pass (-N)      */
    bool           pop3_sniff;       /* disector POP3 (-d)         */

    struct args_user users[USERS_MAX];
    size_t           nusers;
};

/* Parsea argv. Ante error imprime a stderr y llama exit(1).
 * Ante -h/-v imprime y llama exit(0). */
void args_parse(int argc, char **argv, struct socks5args *out);

#endif /* UTIL_ARGS_H */
