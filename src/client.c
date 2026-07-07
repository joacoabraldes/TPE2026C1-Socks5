/* client.c - Cliente de terminal del protocolo de monitoreo SMP/1.0.
 * I/O bloqueante (admitido por su simpleza). Ver docs/DISENO.md. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include "smp.h"

struct options {
    const char *host;
    const char *port;
    const char *user;
    const char *pass;
};

static void usage(const char *prog) {
    fprintf(stderr,
        "Uso: %s [-L host] [-P puerto] [-u admin] [-w pass] <subcomando> [args]\n"
        "\n"
        "Opciones:\n"
        "  -L host      host del management (default 127.0.0.1)\n"
        "  -P puerto    puerto del management (default 8080)\n"
        "  -u admin     usuario admin (default admin)\n"
        "  -w pass      password admin (default admin)\n"
        "\n"
        "Subcomandos:\n"
        "  metrics\n"
        "  add-user <nombre> <password>\n"
        "  del-user <nombre>\n"
        "  list-users\n"
        "  get-config\n"
        "  set-config <buffer-size|timeout|auth-required> <valor>\n",
        prog);
}

/* --------------------------- I/O helpers -------------------------- */

static int connect_to(const char *host, const char *port) {
    struct addrinfo hints, *res = NULL, *ai;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo(%s:%s): %s\n", host, port, gai_strerror(rc));
        return -1;
    }
    int fd = -1;
    for (ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) {
        fprintf(stderr, "no se pudo conectar a %s:%s\n", host, port);
    }
    return fd;
}

static int send_all(int fd, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static int recv_exact(int fd, uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = recv(fd, buf + off, len - off, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1; /* EOF prematuro */
        off += (size_t)n;
    }
    return 0;
}

static uint16_t get_u16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}
static uint32_t get_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static uint64_t get_u64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

/* --------------------------- protocolo ---------------------------- */

static int do_auth(int fd, const char *user, const char *pass) {
    uint8_t buf[3 + 255 + 255];
    size_t ulen = strlen(user), plen = strlen(pass);
    if (ulen == 0 || ulen > 255 || plen == 0 || plen > 255) {
        fprintf(stderr, "usuario/password admin invalido\n");
        return -1;
    }
    size_t i = 0;
    buf[i++] = SMP_VERSION;
    buf[i++] = (uint8_t)ulen;
    memcpy(buf + i, user, ulen); i += ulen;
    buf[i++] = (uint8_t)plen;
    memcpy(buf + i, pass, plen); i += plen;
    if (send_all(fd, buf, i) != 0) return -1;

    uint8_t resp[2];
    if (recv_exact(fd, resp, 2) != 0) return -1;
    if (resp[0] != SMP_VERSION || resp[1] != SMP_AUTH_OK) {
        fprintf(stderr, "autenticacion rechazada\n");
        return -1;
    }
    return 0;
}

static const char *status_str(uint8_t st) {
    switch (st) {
        case SMP_OK:                  return "OK";
        case SMP_AUTH_REQUIRED:       return "auth requerida";
        case SMP_UNKNOWN_COMMAND:     return "comando desconocido";
        case SMP_INVALID_ARGUMENTS:   return "argumentos invalidos";
        case SMP_USER_ALREADY_EXISTS: return "el usuario ya existe";
        case SMP_USER_NOT_FOUND:      return "usuario no encontrado";
        case SMP_USER_LIMIT_REACHED:  return "limite de usuarios alcanzado";
        case SMP_INTERNAL_ERROR:      return "error interno";
        default:                      return "estado desconocido";
    }
}

/* Envía un request y lee la respuesta (header + data). *data se aloja con
 * malloc (el llamador libera). Devuelve 0 ok, -1 error de transporte. */
static int do_request(int fd, const uint8_t *req, size_t reqlen,
                      uint8_t *cmd_out, uint8_t *status_out,
                      uint8_t **data_out, uint16_t *datalen_out) {
    if (send_all(fd, req, reqlen) != 0) return -1;
    uint8_t hdr[5];
    if (recv_exact(fd, hdr, 5) != 0) return -1;
    *cmd_out    = hdr[1];
    *status_out = hdr[2];
    uint16_t datalen = get_u16(hdr + 3);
    *datalen_out = datalen;
    *data_out = NULL;
    if (datalen > 0) {
        uint8_t *data = malloc(datalen);
        if (data == NULL) return -1;
        if (recv_exact(fd, data, datalen) != 0) {
            free(data);
            return -1;
        }
        *data_out = data;
    }
    return 0;
}

static int cmd_metrics(int fd) {
    uint8_t req[2] = { SMP_VERSION, SMP_CMD_METRICS };
    uint8_t cmd, st, *data; uint16_t dl;
    if (do_request(fd, req, sizeof(req), &cmd, &st, &data, &dl) != 0) return 1;
    if (st != SMP_OK || dl < 56) {
        fprintf(stderr, "metrics: %s\n", status_str(st));
        free(data);
        return 1;
    }
    printf("conexiones historicas : %llu\n", (unsigned long long)get_u64(data + 0));
    printf("conexiones actuales   : %llu\n", (unsigned long long)get_u64(data + 8));
    printf("bytes transferidos    : %llu\n", (unsigned long long)get_u64(data + 16));
    printf("conexiones fallidas   : %llu\n", (unsigned long long)get_u64(data + 24));
    printf("usuarios registrados  : %llu\n", (unsigned long long)get_u64(data + 32));
    printf("bytes enviados (c->o) : %llu\n", (unsigned long long)get_u64(data + 40));
    printf("bytes recibidos(o->c) : %llu\n", (unsigned long long)get_u64(data + 48));
    free(data);
    return 0;
}

static int cmd_get_config(int fd) {
    uint8_t req[2] = { SMP_VERSION, SMP_CMD_GET_CONFIG };
    uint8_t cmd, st, *data; uint16_t dl;
    if (do_request(fd, req, sizeof(req), &cmd, &st, &data, &dl) != 0) return 1;
    if (st != SMP_OK || dl < 9) {
        fprintf(stderr, "get-config: %s\n", status_str(st));
        free(data);
        return 1;
    }
    printf("io_buffer_size    : %u\n", get_u32(data + 0));
    printf("conn_timeout_secs : %u\n", get_u32(data + 4));
    printf("auth_required     : %s\n", data[8] ? "si" : "no");
    free(data);
    return 0;
}

static int cmd_list_users(int fd) {
    uint8_t req[2] = { SMP_VERSION, SMP_CMD_LIST_USERS };
    uint8_t cmd, st, *data; uint16_t dl;
    if (do_request(fd, req, sizeof(req), &cmd, &st, &data, &dl) != 0) return 1;
    if (st != SMP_OK || dl < 2) {
        fprintf(stderr, "list-users: %s\n", status_str(st));
        free(data);
        return 1;
    }
    uint16_t count = get_u16(data);
    size_t off = 2;
    printf("usuarios (%u):\n", count);
    for (uint16_t i = 0; i < count && off < dl; i++) {
        uint8_t ulen = data[off++];
        if (off + ulen > dl) break;
        printf("  %.*s\n", (int)ulen, data + off);
        off += ulen;
    }
    free(data);
    return 0;
}

static int cmd_add_user(int fd, const char *user, const char *pass) {
    size_t ulen = strlen(user), plen = strlen(pass);
    if (ulen == 0 || ulen > 255 || plen == 0 || plen > 255) {
        fprintf(stderr, "add-user: usuario/password invalido\n");
        return 1;
    }
    uint8_t req[3 + 255 + 1 + 255];
    size_t i = 0;
    req[i++] = SMP_VERSION;
    req[i++] = SMP_CMD_ADD_USER;
    req[i++] = (uint8_t)ulen;
    memcpy(req + i, user, ulen); i += ulen;
    req[i++] = (uint8_t)plen;
    memcpy(req + i, pass, plen); i += plen;
    uint8_t cmd, st, *data; uint16_t dl;
    if (do_request(fd, req, i, &cmd, &st, &data, &dl) != 0) return 1;
    free(data);
    printf("add-user: %s\n", status_str(st));
    return st == SMP_OK ? 0 : 1;
}

static int cmd_del_user(int fd, const char *user) {
    size_t ulen = strlen(user);
    if (ulen == 0 || ulen > 255) {
        fprintf(stderr, "del-user: usuario invalido\n");
        return 1;
    }
    uint8_t req[3 + 255];
    size_t i = 0;
    req[i++] = SMP_VERSION;
    req[i++] = SMP_CMD_DEL_USER;
    req[i++] = (uint8_t)ulen;
    memcpy(req + i, user, ulen); i += ulen;
    uint8_t cmd, st, *data; uint16_t dl;
    if (do_request(fd, req, i, &cmd, &st, &data, &dl) != 0) return 1;
    free(data);
    printf("del-user: %s\n", status_str(st));
    return st == SMP_OK ? 0 : 1;
}

static int cmd_set_config(int fd, const char *key, const char *value) {
    uint8_t req[7];
    size_t i = 0;
    req[i++] = SMP_VERSION;
    req[i++] = SMP_CMD_SET_CONFIG;
    if (strcmp(key, "buffer-size") == 0) {
        req[i++] = SMP_CFG_IO_BUFFER_SIZE;
        uint32_t v = (uint32_t)strtoul(value, NULL, 10);
        req[i++] = (uint8_t)(v >> 24); req[i++] = (uint8_t)(v >> 16);
        req[i++] = (uint8_t)(v >> 8);  req[i++] = (uint8_t)v;
    } else if (strcmp(key, "timeout") == 0) {
        req[i++] = SMP_CFG_CONN_TIMEOUT;
        uint32_t v = (uint32_t)strtoul(value, NULL, 10);
        req[i++] = (uint8_t)(v >> 24); req[i++] = (uint8_t)(v >> 16);
        req[i++] = (uint8_t)(v >> 8);  req[i++] = (uint8_t)v;
    } else if (strcmp(key, "auth-required") == 0) {
        req[i++] = SMP_CFG_AUTH_REQUIRED;
        req[i++] = (uint8_t)(strtoul(value, NULL, 10) != 0 ? 1 : 0);
    } else {
        fprintf(stderr, "set-config: clave desconocida '%s' "
                        "(buffer-size|timeout|auth-required)\n", key);
        return 1;
    }
    uint8_t cmd, st, *data; uint16_t dl;
    if (do_request(fd, req, i, &cmd, &st, &data, &dl) != 0) return 1;
    free(data);
    printf("set-config: %s\n", status_str(st));
    return st == SMP_OK ? 0 : 1;
}

int main(int argc, char **argv) {
    struct options o = { "127.0.0.1", "8080", "admin", "admin" };
    int c;
    while ((c = getopt(argc, argv, "L:P:u:w:h")) != -1) {
        switch (c) {
            case 'L': o.host = optarg; break;
            case 'P': o.port = optarg; break;
            case 'u': o.user = optarg; break;
            case 'w': o.pass = optarg; break;
            case 'h': usage(argv[0]); return 0;
            default:  usage(argv[0]); return 1;
        }
    }
    if (optind >= argc) {
        usage(argv[0]);
        return 1;
    }
    const char *sub = argv[optind++];
    int nrest = argc - optind;
    char **rest = argv + optind;

    int fd = connect_to(o.host, o.port);
    if (fd < 0) return 1;
    if (do_auth(fd, o.user, o.pass) != 0) {
        close(fd);
        return 1;
    }

    int rc;
    if (strcmp(sub, "metrics") == 0 && nrest == 0) {
        rc = cmd_metrics(fd);
    } else if (strcmp(sub, "get-config") == 0 && nrest == 0) {
        rc = cmd_get_config(fd);
    } else if (strcmp(sub, "list-users") == 0 && nrest == 0) {
        rc = cmd_list_users(fd);
    } else if (strcmp(sub, "add-user") == 0 && nrest == 2) {
        rc = cmd_add_user(fd, rest[0], rest[1]);
    } else if (strcmp(sub, "del-user") == 0 && nrest == 1) {
        rc = cmd_del_user(fd, rest[0]);
    } else if (strcmp(sub, "set-config") == 0 && nrest == 2) {
        rc = cmd_set_config(fd, rest[0], rest[1]);
    } else {
        usage(argv[0]);
        rc = 1;
    }
    close(fd);
    return rc;
}
