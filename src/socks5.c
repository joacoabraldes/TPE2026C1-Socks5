#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "socks5.h"
#include "socks5_parsers.h"
#include "buffer.h"
#include "stm.h"
#include "config.h"
#include "users.h"
#include "metrics.h"
#include "logger.h"
#include "netutils.h"
#include "dns.h"
#include "pop3.h"

/* MSG_NOSIGNAL no existe en todas las plataformas (p. ej. Solaris/pampero).
 * Como además ignoramos SIGPIPE globalmente, 0 es un fallback seguro. */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define ATTACH(key) ((struct socks5 *)((key)->data))
#define MAX_ADDRS   16
#define N(x)        (sizeof(x) / sizeof((x)[0]))

enum socks5_state {
    HELLO_READ = 0,
    HELLO_WRITE,
    AUTH_READ,
    AUTH_WRITE,
    REQUEST_READ,
    REQUEST_RESOLV,
    REQUEST_CONNECTING,
    REQUEST_WRITE,
    COPY,
    DONE,
    ERROR_STATE,
};

struct socks5 {
    int                     client_fd;
    int                     origin_fd;
    struct sockaddr_storage client_addr;
    socklen_t               client_addr_len;

    struct state_machine    stm;

    struct hello_parser     hello;
    struct auth_parser      auth;
    struct request_parser   request;

    uint8_t                 method;        /* método negociado          */
    bool                    auth_ok;
    char                    username[256];

    /* destino elegido / candidatos */
    struct sockaddr_storage addrs[MAX_ADDRS];
    socklen_t               addr_lens[MAX_ADDRS];
    uint8_t                 naddrs;
    uint8_t                 addr_idx;

    struct dns_request      dns;
    bool                    resolving;

    char                    dest_host[256];
    uint16_t                dest_port;
    uint8_t                 reply;         /* código de reply SOCKS      */

    /* relay */
    bool                    client_eof;
    bool                    origin_eof;
    bool                    client_wr_shut;
    bool                    origin_wr_shut;

    /* disector POP3 */
    bool                    sniff_pop3;
    struct pop3_sniffer     pop3;

    /* buffers */
    uint8_t                *raw_read;
    uint8_t                *raw_write;
    buffer                  read_buffer;   /* cliente -> origen */
    buffer                  write_buffer;  /* origen  -> cliente */
    size_t                  buffer_size;

    unsigned                references;
    struct socks5          *next;          /* freelist */
};

/* ----------------------- pool de conexiones ----------------------- */
static struct socks5 *pool = NULL;
static unsigned       pool_size = 0;
#define MAX_POOL 128

static const struct fd_handler socks5_handler;

static struct socks5 *socks5_new(int client_fd);
static void           socks5_destroy(struct socks5 *s);
static void           socksv5_done(struct selector_key *key);

/* ----------------------- helpers de estado ------------------------ */

static uint8_t errno_to_reply(int e) {
    switch (e) {
        case 0:            return SOCKS5_REP_SUCCESS;
        case ECONNREFUSED: return SOCKS5_REP_CONNECTION_REFUSED;
        case ENETUNREACH:  return SOCKS5_REP_NETWORK_UNREACHABLE;
        case ENETDOWN:     return SOCKS5_REP_NETWORK_UNREACHABLE;
        case EHOSTUNREACH: return SOCKS5_REP_HOST_UNREACHABLE;
        case EHOSTDOWN:    return SOCKS5_REP_HOST_UNREACHABLE;
        case ETIMEDOUT:    return SOCKS5_REP_TTL_EXPIRED;
        default:           return SOCKS5_REP_GENERAL_FAILURE;
    }
}

/* Construye el reply SOCKS en write_buffer. */
static void build_reply(struct socks5 *s, uint8_t rep) {
    buffer_reset(&s->write_buffer);
    buffer_write(&s->write_buffer, 0x05);
    buffer_write(&s->write_buffer, rep);
    buffer_write(&s->write_buffer, 0x00);

    struct sockaddr_storage local;
    socklen_t local_len = sizeof(local);
    bool have_local = false;
    if (rep == SOCKS5_REP_SUCCESS && s->origin_fd >= 0 &&
        getsockname(s->origin_fd, (struct sockaddr *)&local, &local_len) == 0) {
        have_local = true;
    }

    if (have_local && local.ss_family == AF_INET6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&local;
        buffer_write(&s->write_buffer, SOCKS5_ATYP_IPV6);
        const uint8_t *ip = (const uint8_t *)&a->sin6_addr;
        for (int i = 0; i < 16; i++) buffer_write(&s->write_buffer, ip[i]);
        uint16_t p = ntohs(a->sin6_port);
        buffer_write(&s->write_buffer, (uint8_t)(p >> 8));
        buffer_write(&s->write_buffer, (uint8_t)(p & 0xFF));
    } else if (have_local) {
        struct sockaddr_in *a = (struct sockaddr_in *)&local;
        buffer_write(&s->write_buffer, SOCKS5_ATYP_IPV4);
        const uint8_t *ip = (const uint8_t *)&a->sin_addr;
        for (int i = 0; i < 4; i++) buffer_write(&s->write_buffer, ip[i]);
        uint16_t p = ntohs(a->sin_port);
        buffer_write(&s->write_buffer, (uint8_t)(p >> 8));
        buffer_write(&s->write_buffer, (uint8_t)(p & 0xFF));
    } else {
        /* error o sin info local: BND = 0.0.0.0:0 */
        buffer_write(&s->write_buffer, SOCKS5_ATYP_IPV4);
        for (int i = 0; i < 6; i++) buffer_write(&s->write_buffer, 0x00);
    }
}

static void origin_string(struct socks5 *s, char *buf, size_t n) {
    sockaddr_to_human(buf, n, (const struct sockaddr *)&s->client_addr);
}

/* Intenta conectar al candidato addr_idx (y sucesivos si fallan al toque).
 * Devuelve el próximo estado. */
static unsigned start_connection(struct selector_key *key) {
    struct socks5 *s = ATTACH(key);

    while (s->addr_idx < s->naddrs) {
        struct sockaddr_storage *ss = &s->addrs[s->addr_idx];
        int fd = socket(ss->ss_family, SOCK_STREAM, IPPROTO_TCP);
        if (fd < 0) {
            s->reply = errno_to_reply(errno);
            s->addr_idx++;
            continue;
        }
        if (selector_fd_set_nio(fd) < 0) {
            close(fd);
            s->addr_idx++;
            continue;
        }
        int r = connect(fd, (struct sockaddr *)ss, s->addr_lens[s->addr_idx]);
        if (r == 0) {
            /* conexión inmediata (raro en no bloqueante) */
            if (selector_register(key->s, fd, &socks5_handler, OP_NOOP, s)
                    != SELECTOR_SUCCESS) {
                close(fd);
                s->addr_idx++;
                continue;
            }
            s->origin_fd = fd;
            s->references++;
            s->reply = SOCKS5_REP_SUCCESS;
            return REQUEST_WRITE;
        } else if (errno == EINPROGRESS || errno == EINTR) {
            /* la conexión sigue en curso: esperamos writable */
            if (selector_register(key->s, fd, &socks5_handler, OP_WRITE, s)
                    != SELECTOR_SUCCESS) {
                close(fd);
                s->addr_idx++;
                continue;
            }
            s->origin_fd = fd;
            s->references++;
            return REQUEST_CONNECTING;
        } else {
            s->reply = errno_to_reply(errno);
            close(fd);
            s->addr_idx++;
        }
    }
    /* candidatos agotados */
    if (s->reply == SOCKS5_REP_SUCCESS) {
        s->reply = SOCKS5_REP_HOST_UNREACHABLE;
    }
    return REQUEST_WRITE;
}

/* --------------------------- HELLO -------------------------------- */

static unsigned choose_method(struct socks5 *s) {
    struct proxy_config *cfg = config_get();
    if (cfg->auth_required) {
        return s->hello.has_userpass ? SOCKS5_METHOD_USERPASS : SOCKS5_METHOD_NONE;
    }
    if (s->hello.has_noauth) {
        return SOCKS5_METHOD_NO_AUTH;
    }
    if (s->hello.has_userpass) {
        return SOCKS5_METHOD_USERPASS;
    }
    return SOCKS5_METHOD_NONE;
}

static unsigned hello_read(struct selector_key *key) {
    struct socks5 *s = ATTACH(key);
    size_t space;
    uint8_t *ptr = buffer_write_ptr(&s->read_buffer, &space);
    ssize_t n = recv(s->client_fd, ptr, space, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return HELLO_READ;
        return ERROR_STATE;
    }
    if (n == 0) return ERROR_STATE;
    buffer_write_adv(&s->read_buffer, n);

    bool error = false;
    if (!hello_parser_consume(&s->hello, &s->read_buffer, &error)) {
        return HELLO_READ;
    }
    if (error) {
        return ERROR_STATE;
    }
    s->method = (uint8_t)choose_method(s);

    buffer_reset(&s->write_buffer);
    buffer_write(&s->write_buffer, 0x05);
    buffer_write(&s->write_buffer, s->method);
    if (selector_set_interest(key->s, s->client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
        return ERROR_STATE;
    }
    return HELLO_WRITE;
}

static unsigned hello_write(struct selector_key *key) {
    struct socks5 *s = ATTACH(key);
    size_t n;
    uint8_t *ptr = buffer_read_ptr(&s->write_buffer, &n);
    ssize_t w = send(s->client_fd, ptr, n, MSG_NOSIGNAL);
    if (w < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return HELLO_WRITE;
        return ERROR_STATE;
    }
    buffer_read_adv(&s->write_buffer, w);
    if (buffer_can_read(&s->write_buffer)) {
        return HELLO_WRITE;
    }
    if (s->method == SOCKS5_METHOD_NONE) {
        return DONE;   /* no hay método aceptable: cerrar */
    }
    if (selector_set_interest(key->s, s->client_fd, OP_READ) != SELECTOR_SUCCESS) {
        return ERROR_STATE;
    }
    return (s->method == SOCKS5_METHOD_USERPASS) ? AUTH_READ : REQUEST_READ;
}

/* --------------------------- AUTH --------------------------------- */

static unsigned auth_read(struct selector_key *key) {
    struct socks5 *s = ATTACH(key);
    size_t space;
    uint8_t *ptr = buffer_write_ptr(&s->read_buffer, &space);
    ssize_t n = recv(s->client_fd, ptr, space, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return AUTH_READ;
        return ERROR_STATE;
    }
    if (n == 0) return ERROR_STATE;
    buffer_write_adv(&s->read_buffer, n);

    bool error = false;
    if (!auth_parser_consume(&s->auth, &s->read_buffer, &error)) {
        return AUTH_READ;
    }
    if (error) {
        return ERROR_STATE;
    }
    s->auth_ok = users_check(s->auth.username, s->auth.password);
    strncpy(s->username, s->auth.username, sizeof(s->username) - 1);
    s->username[sizeof(s->username) - 1] = '\0';

    buffer_reset(&s->write_buffer);
    buffer_write(&s->write_buffer, 0x01);
    buffer_write(&s->write_buffer, s->auth_ok ? 0x00 : 0x01);
    if (selector_set_interest(key->s, s->client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
        return ERROR_STATE;
    }
    return AUTH_WRITE;
}

static unsigned auth_write(struct selector_key *key) {
    struct socks5 *s = ATTACH(key);
    size_t n;
    uint8_t *ptr = buffer_read_ptr(&s->write_buffer, &n);
    ssize_t w = send(s->client_fd, ptr, n, MSG_NOSIGNAL);
    if (w < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return AUTH_WRITE;
        return ERROR_STATE;
    }
    buffer_read_adv(&s->write_buffer, w);
    if (buffer_can_read(&s->write_buffer)) {
        return AUTH_WRITE;
    }
    if (!s->auth_ok) {
        return DONE;
    }
    if (selector_set_interest(key->s, s->client_fd, OP_READ) != SELECTOR_SUCCESS) {
        return ERROR_STATE;
    }
    return REQUEST_READ;
}

/* --------------------------- REQUEST ------------------------------ */

/* Prepara los candidatos y lanza conexión/resolución. */
static unsigned process_request(struct selector_key *key) {
    struct socks5 *s = ATTACH(key);

    if (s->request.cmd != SOCKS5_CMD_CONNECT) {
        s->reply = SOCKS5_REP_COMMAND_NOT_SUPPORTED;
        return REQUEST_WRITE;
    }

    s->dest_port = s->request.port;

    if (s->request.atyp == SOCKS5_ATYP_IPV4) {
        struct sockaddr_in *a = (struct sockaddr_in *)&s->addrs[0];
        memset(a, 0, sizeof(*a));
        a->sin_family = AF_INET;
        memcpy(&a->sin_addr, s->request.addr, 4);
        a->sin_port = htons(s->request.port);
        s->addr_lens[0] = sizeof(*a);
        s->naddrs = 1;
        s->addr_idx = 0;
        inet_ntop(AF_INET, &a->sin_addr, s->dest_host, sizeof(s->dest_host));
        return start_connection(key);
    }
    if (s->request.atyp == SOCKS5_ATYP_IPV6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&s->addrs[0];
        memset(a, 0, sizeof(*a));
        a->sin6_family = AF_INET6;
        memcpy(&a->sin6_addr, s->request.addr, 16);
        a->sin6_port = htons(s->request.port);
        s->addr_lens[0] = sizeof(*a);
        s->naddrs = 1;
        s->addr_idx = 0;
        inet_ntop(AF_INET6, &a->sin6_addr, s->dest_host, sizeof(s->dest_host));
        return start_connection(key);
    }
    if (s->request.atyp == SOCKS5_ATYP_DOMAIN) {
        strncpy(s->dest_host, (char *)s->request.addr, sizeof(s->dest_host) - 1);
        s->dest_host[sizeof(s->dest_host) - 1] = '\0';
        memset(&s->dns, 0, sizeof(s->dns));
        s->dns.s = key->s;
        s->dns.notify_fd = s->client_fd;
        s->dns.conn = s;
        snprintf(s->dns.host, sizeof(s->dns.host), "%s", s->dest_host);
        snprintf(s->dns.service, sizeof(s->dns.service), "%u", s->request.port);
        if (dns_resolve_async(&s->dns) != 0) {
            s->reply = SOCKS5_REP_GENERAL_FAILURE;
            return REQUEST_WRITE;
        }
        s->resolving = true;
        return REQUEST_RESOLV;
    }

    s->reply = SOCKS5_REP_ATYP_NOT_SUPPORTED;
    return REQUEST_WRITE;
}

static unsigned request_read(struct selector_key *key) {
    struct socks5 *s = ATTACH(key);
    size_t space;
    uint8_t *ptr = buffer_write_ptr(&s->read_buffer, &space);
    ssize_t n = recv(s->client_fd, ptr, space, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return REQUEST_READ;
        return ERROR_STATE;
    }
    if (n == 0) return ERROR_STATE;
    buffer_write_adv(&s->read_buffer, n);

    bool error = false;
    if (!request_parser_consume(&s->request, &s->read_buffer, &error)) {
        return REQUEST_READ;
    }
    /* dejamos de leer del cliente mientras conectamos/resolvemos */
    selector_set_interest(key->s, s->client_fd, OP_NOOP);
    if (error) {
        s->reply = SOCKS5_REP_GENERAL_FAILURE;
        return REQUEST_WRITE;
    }
    return process_request(key);
}

/* ------------------------- RESOLV (block) ------------------------- */

static void resolv_arrival(unsigned state, struct selector_key *key) {
    (void)state;
    selector_set_interest(key->s, ATTACH(key)->client_fd, OP_NOOP);
}

static unsigned resolv_block(struct selector_key *key) {
    struct socks5 *s = ATTACH(key);
    s->resolving = false;

    if (s->dns.status != 0 || s->dns.result == NULL) {
        s->reply = SOCKS5_REP_HOST_UNREACHABLE;
        dns_request_clear(&s->dns);
        return REQUEST_WRITE;
    }

    s->naddrs = 0;
    s->addr_idx = 0;
    for (struct addrinfo *ai = s->dns.result;
         ai != NULL && s->naddrs < MAX_ADDRS; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET || ai->ai_family == AF_INET6) {
            memcpy(&s->addrs[s->naddrs], ai->ai_addr, ai->ai_addrlen);
            s->addr_lens[s->naddrs] = ai->ai_addrlen;
            s->naddrs++;
        }
    }
    dns_request_clear(&s->dns);

    if (s->naddrs == 0) {
        s->reply = SOCKS5_REP_HOST_UNREACHABLE;
        return REQUEST_WRITE;
    }
    return start_connection(key);
}

/* ------------------------- CONNECTING ----------------------------- */

static unsigned connecting_write(struct selector_key *key) {
    struct socks5 *s = ATTACH(key);
    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(s->origin_fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        error = errno;
    }
    if (error == 0) {
        s->reply = SOCKS5_REP_SUCCESS;
        return REQUEST_WRITE;
    }
    /* falló: registramos motivo, cerramos este origen y probamos el siguiente */
    s->reply = errno_to_reply(error);
    selector_unregister_fd(key->s, s->origin_fd);  /* cierra fd y baja refcount */
    s->origin_fd = -1;
    s->addr_idx++;
    return start_connection(key);
}

/* ------------------------- REQUEST_WRITE -------------------------- */

static void request_write_arrival(unsigned state, struct selector_key *key) {
    (void)state;
    struct socks5 *s = ATTACH(key);
    build_reply(s, s->reply);
    if (s->origin_fd >= 0) {
        selector_set_interest(key->s, s->origin_fd, OP_NOOP);
    }
    selector_set_interest(key->s, s->client_fd, OP_WRITE);
}

static unsigned request_write(struct selector_key *key) {
    struct socks5 *s = ATTACH(key);
    size_t n;
    uint8_t *ptr = buffer_read_ptr(&s->write_buffer, &n);
    ssize_t w = send(s->client_fd, ptr, n, MSG_NOSIGNAL);
    if (w < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return REQUEST_WRITE;
        return ERROR_STATE;
    }
    buffer_read_adv(&s->write_buffer, w);
    if (buffer_can_read(&s->write_buffer)) {
        return REQUEST_WRITE;
    }

    char origin[SOCKADDR_TO_HUMAN_MIN];
    char dest[300];
    origin_string(s, origin, sizeof(origin));
    snprintf(dest, sizeof(dest), "%s:%u", s->dest_host, s->dest_port);
    logger_access(s->username[0] ? s->username : "-", "CONNECT",
                  origin, dest, s->reply);

    if (s->reply != SOCKS5_REP_SUCCESS) {
        metrics_connection_failed();
        return DONE;
    }
    return COPY;
}

/* ----------------------------- COPY ------------------------------- */

static void copy_compute_interests(fd_selector sel, struct socks5 *s) {
    fd_interest cif = OP_NOOP;
    if (!s->client_eof && buffer_can_write(&s->read_buffer))  cif |= OP_READ;
    if (buffer_can_read(&s->write_buffer))                    cif |= OP_WRITE;

    fd_interest oif = OP_NOOP;
    if (!s->origin_eof && buffer_can_write(&s->write_buffer)) oif |= OP_READ;
    if (buffer_can_read(&s->read_buffer))                     oif |= OP_WRITE;

    selector_set_interest(sel, s->client_fd, cif);
    selector_set_interest(sel, s->origin_fd, oif);
}

static void copy_arrival(unsigned state, struct selector_key *key) {
    (void)state;
    struct socks5 *s = ATTACH(key);
    s->client_eof = s->origin_eof = false;
    s->client_wr_shut = s->origin_wr_shut = false;
    s->sniff_pop3 = (s->dest_port == POP3_PORT) && config_get()->pop3_sniff;
    copy_compute_interests(key->s, s);
}

static void on_pop3_credential(void *ctx, const char *user, const char *pass) {
    struct socks5 *s = ctx;
    char origin[SOCKADDR_TO_HUMAN_MIN];
    char dest[300];
    origin_string(s, origin, sizeof(origin));
    snprintf(dest, sizeof(dest), "%s:%u", s->dest_host, s->dest_port);
    logger_pop3(s->username[0] ? s->username : "-", origin, dest, user, pass);
}

static unsigned copy_update(struct selector_key *key) {
    struct socks5 *s = ATTACH(key);

    if (s->client_eof && !buffer_can_read(&s->read_buffer) && !s->origin_wr_shut) {
        shutdown(s->origin_fd, SHUT_WR);
        s->origin_wr_shut = true;
    }
    if (s->origin_eof && !buffer_can_read(&s->write_buffer) && !s->client_wr_shut) {
        shutdown(s->client_fd, SHUT_WR);
        s->client_wr_shut = true;
    }
    bool c2o_done = s->client_eof && !buffer_can_read(&s->read_buffer);
    bool o2c_done = s->origin_eof && !buffer_can_read(&s->write_buffer);
    if (c2o_done && o2c_done) {
        return DONE;
    }
    copy_compute_interests(key->s, s);
    return COPY;
}

/* Drena b hacia dst; si el socket se llena deja el resto para reintentar.
 * Devuelve true ante error duro (hay que cerrar la conexion). */
static bool copy_pump(int dst, buffer *b) {
    while (buffer_can_read(b)) {
        size_t n;
        uint8_t *p = buffer_read_ptr(b, &n);
        ssize_t w = send(dst, p, n, MSG_NOSIGNAL);
        if (w > 0) {
            buffer_read_adv(b, w);
        } else if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        } else {
            return true;
        }
    }
    return false;
}

static unsigned copy_read(struct selector_key *key) {
    struct socks5 *s = ATTACH(key);
    if (key->fd == s->client_fd) {
        size_t space;
        uint8_t *ptr = buffer_write_ptr(&s->read_buffer, &space);
        if (space > 0) {
            ssize_t n = recv(s->client_fd, ptr, space, 0);
            if (n > 0) {
                buffer_write_adv(&s->read_buffer, n);
                metrics_add_sent((uint64_t)n);
                if (s->sniff_pop3) {
                    pop3_sniffer_feed(&s->pop3, ptr, (size_t)n,
                                      on_pop3_credential, s);
                }
                /* write optimista: select -> read -> write, sin otra vuelta */
                if (copy_pump(s->origin_fd, &s->read_buffer)) {
                    return DONE;
                }
            } else if (n == 0) {
                s->client_eof = true;
            } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                s->client_eof = true;
            }
        }
    } else {
        size_t space;
        uint8_t *ptr = buffer_write_ptr(&s->write_buffer, &space);
        if (space > 0) {
            ssize_t n = recv(s->origin_fd, ptr, space, 0);
            if (n > 0) {
                buffer_write_adv(&s->write_buffer, n);
                metrics_add_received((uint64_t)n);
                if (copy_pump(s->client_fd, &s->write_buffer)) {
                    return DONE;
                }
            } else if (n == 0) {
                s->origin_eof = true;
            } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                s->origin_eof = true;
            }
        }
    }
    return copy_update(key);
}

/* Solo se llega aca con sobrante de una escritura parcial anterior. */
static unsigned copy_write(struct selector_key *key) {
    struct socks5 *s = ATTACH(key);
    if (key->fd == s->client_fd) {
        if (copy_pump(s->client_fd, &s->write_buffer)) {
            return DONE;
        }
    } else {
        if (copy_pump(s->origin_fd, &s->read_buffer)) {
            return DONE;
        }
    }
    return copy_update(key);
}

/* ------------------- tabla de estados de la stm ------------------- */

static const struct state_definition states[] = {
    { .state = HELLO_READ,         .on_read_ready  = hello_read },
    { .state = HELLO_WRITE,        .on_write_ready = hello_write },
    { .state = AUTH_READ,          .on_read_ready  = auth_read },
    { .state = AUTH_WRITE,         .on_write_ready = auth_write },
    { .state = REQUEST_READ,       .on_read_ready  = request_read },
    { .state = REQUEST_RESOLV,     .on_arrival = resolv_arrival,
                                   .on_block_ready = resolv_block },
    { .state = REQUEST_CONNECTING, .on_write_ready = connecting_write },
    { .state = REQUEST_WRITE,      .on_arrival = request_write_arrival,
                                   .on_write_ready = request_write },
    { .state = COPY,               .on_arrival = copy_arrival,
                                   .on_read_ready  = copy_read,
                                   .on_write_ready = copy_write },
    { .state = DONE,        },
    { .state = ERROR_STATE, },
};

/* ------------------------- fd_handler ----------------------------- */

static void socksv5_read(struct selector_key *key) {
    struct state_machine *stm = &ATTACH(key)->stm;
    const enum socks5_state st = (enum socks5_state)stm_handler_read(stm, key);
    if (st == DONE || st == ERROR_STATE) {
        socksv5_done(key);
    }
}

static void socksv5_write(struct selector_key *key) {
    struct state_machine *stm = &ATTACH(key)->stm;
    const enum socks5_state st = (enum socks5_state)stm_handler_write(stm, key);
    if (st == DONE || st == ERROR_STATE) {
        socksv5_done(key);
    }
}

static void socksv5_block(struct selector_key *key) {
    struct state_machine *stm = &ATTACH(key)->stm;
    const enum socks5_state st = (enum socks5_state)stm_handler_block(stm, key);
    if (st == DONE || st == ERROR_STATE) {
        socksv5_done(key);
    }
}

static void socksv5_close(struct selector_key *key) {
    struct socks5 *s = ATTACH(key);
    close(key->fd);
    if (s->references > 0) {
        s->references--;
    }
    if (s->references == 0) {
        metrics_connection_closed();
        socks5_destroy(s);
    }
}

static const struct fd_handler socks5_handler = {
    .handle_read  = socksv5_read,
    .handle_write = socksv5_write,
    .handle_block = socksv5_block,
    .handle_close = socksv5_close,
};

static void socksv5_done(struct selector_key *key) {
    struct socks5 *s = ATTACH(key);
    const int fds[] = { s->client_fd, s->origin_fd };
    for (unsigned i = 0; i < N(fds); i++) {
        if (fds[i] != -1) {
            selector_unregister_fd(key->s, fds[i]);
        }
    }
}

/* ------------------------- ciclo de vida -------------------------- */

static struct socks5 *socks5_new(int client_fd) {
    struct socks5 *s;
    if (pool != NULL) {
        s = pool;
        pool = pool->next;
        pool_size--;
        uint8_t *rr = s->raw_read, *rw = s->raw_write;
        size_t bs = s->buffer_size;
        memset(s, 0, sizeof(*s));
        s->raw_read = rr;
        s->raw_write = rw;
        s->buffer_size = bs;
    } else {
        s = calloc(1, sizeof(*s));
        if (s == NULL) {
            return NULL;
        }
    }

    size_t want = config_get()->io_buffer_size;
    if (want < CONFIG_MIN_BUFFER) want = CONFIG_MIN_BUFFER;
    if (s->raw_read == NULL || s->buffer_size != want) {
        free(s->raw_read);
        free(s->raw_write);
        s->raw_read = malloc(want);
        s->raw_write = malloc(want);
        s->buffer_size = want;
        if (s->raw_read == NULL || s->raw_write == NULL) {
            free(s->raw_read);
            free(s->raw_write);
            free(s);
            return NULL;
        }
    }

    s->client_fd = client_fd;
    s->origin_fd = -1;
    s->references = 0;
    s->username[0] = '\0';
    s->reply = SOCKS5_REP_SUCCESS;

    buffer_init(&s->read_buffer, s->buffer_size, s->raw_read);
    buffer_init(&s->write_buffer, s->buffer_size, s->raw_write);

    s->sniff_pop3 = false;
    pop3_sniffer_init(&s->pop3);

    hello_parser_init(&s->hello);
    auth_parser_init(&s->auth);
    request_parser_init(&s->request);

    s->stm.initial   = HELLO_READ;
    s->stm.max_state = ERROR_STATE;
    s->stm.states    = states;
    stm_init(&s->stm);

    return s;
}

static void socks5_destroy(struct socks5 *s) {
    if (s == NULL) {
        return;
    }
    if (s->resolving) {
        /* resolución DNS en vuelo: no liberar para evitar use-after-free.
         * Se pierde (leak acotado). Ver Limitaciones en el informe. */
        return;
    }
    dns_request_clear(&s->dns);
    if (pool_size < MAX_POOL) {
        s->next = pool;
        pool = s;
        pool_size++;
    } else {
        free(s->raw_read);
        free(s->raw_write);
        free(s);
    }
}

void socksv5_pool_destroy(void) {
    struct socks5 *s = pool;
    while (s != NULL) {
        struct socks5 *next = s->next;
        free(s->raw_read);
        free(s->raw_write);
        free(s);
        s = next;
    }
    pool = NULL;
    pool_size = 0;
}

void socksv5_passive_accept(struct selector_key *key) {
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    const int client = accept(key->fd, (struct sockaddr *)&client_addr,
                              &client_addr_len);
    if (client < 0) {
        return;
    }
    if (selector_fd_set_nio(client) < 0) {
        close(client);
        return;
    }
    struct socks5 *s = socks5_new(client);
    if (s == NULL) {
        close(client);
        return;
    }
    memcpy(&s->client_addr, &client_addr, client_addr_len);
    s->client_addr_len = client_addr_len;

    if (selector_register(key->s, client, &socks5_handler, OP_READ, s)
            != SELECTOR_SUCCESS) {
        socks5_destroy(s);
        close(client);
        return;
    }
    s->references = 1;
    metrics_connection_opened();
}
