#define _POSIX_C_SOURCE 200809L
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "args.h"

#define VERSION_STR "socks5d 1.0 - TPE Protocolos de Comunicacion 2026/1"

static void usage(const char *prog) {
    fprintf(stderr,
        "Uso: %s [OPCIONES]\n"
        "\n"
        "  -h                imprime esta ayuda y termina\n"
        "  -v                imprime version y termina\n"
        "  -l <addr>         direccion donde escucha el proxy SOCKS (default: todas)\n"
        "  -p <puerto>       puerto del proxy SOCKS (default: 1080)\n"
        "  -L <addr>         direccion del servicio de management (default: 127.0.0.1)\n"
        "  -P <puerto>       puerto del servicio de management (default: 8080)\n"
        "  -u <user:pass>    agrega un usuario del proxy (hasta %d, repetible)\n"
        "  -a <user:pass>    credenciales de admin del management (default: admin:admin)\n"
        "  -N                exige autenticacion user/pass (deshabilita NO_AUTH)\n"
        "\n",
        prog, USERS_MAX);
}

/* separa "user:pass" en dos campos acotados. Devuelve false si es inválido. */
static bool split_userpass(const char *arg, char *user, size_t ulen,
                           char *pass, size_t plen) {
    const char *colon = strchr(arg, ':');
    if (colon == NULL || colon == arg) {
        return false;
    }
    size_t un = (size_t)(colon - arg);
    size_t pn = strlen(colon + 1);
    if (un >= ulen || pn == 0 || pn >= plen) {
        return false;
    }
    memcpy(user, arg, un);
    user[un] = '\0';
    memcpy(pass, colon + 1, pn);
    pass[pn] = '\0';
    return true;
}

static unsigned short parse_port(const char *s) {
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (end == s || *end != '\0' || v < 1 || v > 65535) {
        fprintf(stderr, "puerto invalido: %s\n", s);
        exit(1);
    }
    return (unsigned short)v;
}

void args_parse(int argc, char **argv, struct socks5args *out) {
    memset(out, 0, sizeof(*out));
    out->socks_port = 1080;
    out->mgmt_port  = 8080;
    strcpy(out->mgmt_addr, "127.0.0.1");
    strcpy(out->admin_user, "admin");
    strcpy(out->admin_pass, "admin");
    out->require_auth = false;

    int c;
    opterr = 1;
    while ((c = getopt(argc, argv, "hvl:p:L:P:u:a:N")) != -1) {
        switch (c) {
            case 'h':
                usage(argv[0]);
                exit(0);
            case 'v':
                fprintf(stderr, "%s\n", VERSION_STR);
                exit(0);
            case 'l':
                strncpy(out->socks_addr, optarg, sizeof(out->socks_addr) - 1);
                out->socks_addr[sizeof(out->socks_addr) - 1] = '\0';
                break;
            case 'p':
                out->socks_port = parse_port(optarg);
                break;
            case 'L':
                strncpy(out->mgmt_addr, optarg, sizeof(out->mgmt_addr) - 1);
                out->mgmt_addr[sizeof(out->mgmt_addr) - 1] = '\0';
                break;
            case 'P':
                out->mgmt_port = parse_port(optarg);
                break;
            case 'u':
                if (out->nusers >= USERS_MAX) {
                    fprintf(stderr, "demasiados usuarios (max %d)\n", USERS_MAX);
                    exit(1);
                }
                if (!split_userpass(optarg,
                        out->users[out->nusers].name, USERS_MAX_NAME + 1,
                        out->users[out->nusers].pass, USERS_MAX_PASS + 1)) {
                    fprintf(stderr, "formato invalido en -u (esperado user:pass): %s\n",
                            optarg);
                    exit(1);
                }
                out->nusers++;
                break;
            case 'a':
                if (!split_userpass(optarg,
                        out->admin_user, sizeof(out->admin_user),
                        out->admin_pass, sizeof(out->admin_pass))) {
                    fprintf(stderr, "formato invalido en -a (esperado user:pass)\n");
                    exit(1);
                }
                break;
            case 'N':
                out->require_auth = true;
                break;
            default:
                usage(argv[0]);
                exit(1);
        }
    }
    if (optind < argc) {
        fprintf(stderr, "argumento no reconocido: %s\n", argv[optind]);
        usage(argv[0]);
        exit(1);
    }
}
