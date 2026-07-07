#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "mgmt.h"
#include "smp.h"
#include "buffer.h"
#include "config.h"
#include "users.h"
#include "metrics.h"
#include "logger.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define MGMT_RBUF 4096
#define MGMT_WBUF 65536

#define ATTACH(key) ((struct mgmt_conn *)((key)->data))

enum mgmt_state {
    MGMT_AUTH,      /* leyendo handshake            */
    MGMT_AUTH_REPLY,/* escribiendo respuesta de auth*/
    MGMT_REQUEST,   /* leyendo un request           */
    MGMT_RESPONSE,  /* escribiendo una respuesta    */
};

struct mgmt_conn {
    int              fd;
    enum mgmt_state  state;
    bool             auth_ok;
    bool             close_after_write;

    uint8_t          rraw[MGMT_RBUF];
    buffer           rbuf;
    uint8_t          wraw[MGMT_WBUF];
    buffer           wbuf;
};

/* ---------------------- serialización BE -------------------------- */

static void put_u16(buffer *b, uint16_t v) {
    buffer_write(b, (uint8_t)(v >> 8));
    buffer_write(b, (uint8_t)(v & 0xFF));
}
static void put_u32(buffer *b, uint32_t v) {
    buffer_write(b, (uint8_t)(v >> 24));
    buffer_write(b, (uint8_t)(v >> 16));
    buffer_write(b, (uint8_t)(v >> 8));
    buffer_write(b, (uint8_t)(v));
}
static void put_u64(buffer *b, uint64_t v) {
    for (int i = 7; i >= 0; i--) {
        buffer_write(b, (uint8_t)(v >> (i * 8)));
    }
}

/* ---------------------- parsers de request ------------------------ */

struct mgmt_req {
    uint8_t  cmd;
    char     user[256];
    char     pass[256];
    uint8_t  key;
    uint32_t u32;
    uint8_t  u8;
};

/* -1 error, 0 need more, >0 bytes consumidos */
static int parse_auth(const uint8_t *p, size_t len, char *user, char *pass) {
    if (len < 2)          return 0;
    if (p[0] != SMP_VERSION) return -1;
    uint8_t ulen = p[1];
    if (ulen == 0)        return -1;
    if (len < (size_t)(2 + ulen + 1)) return 0;
    uint8_t plen = p[2 + ulen];
    if (plen == 0)        return -1;
    size_t need = (size_t)(2 + ulen + 1 + plen);
    if (len < need)       return 0;
    memcpy(user, p + 2, ulen);          user[ulen] = '\0';
    memcpy(pass, p + 3 + ulen, plen);   pass[plen] = '\0';
    return (int)need;
}

/* -1 error, 0 need more, >0 bytes consumidos */
static int parse_request(const uint8_t *p, size_t len, struct mgmt_req *r) {
    if (len < 2)          return 0;
    if (p[0] != SMP_VERSION) return -1;
    r->cmd = p[1];
    switch (r->cmd) {
        case SMP_CMD_METRICS:
        case SMP_CMD_LIST_USERS:
        case SMP_CMD_GET_CONFIG:
            return 2;
        case SMP_CMD_ADD_USER: {
            if (len < 3) return 0;
            uint8_t ulen = p[2];
            if (ulen == 0) return -1;
            if (len < (size_t)(3 + ulen + 1)) return 0;
            uint8_t plen = p[3 + ulen];
            if (plen == 0) return -1;
            size_t need = (size_t)(3 + ulen + 1 + plen);
            if (len < need) return 0;
            memcpy(r->user, p + 3, ulen);        r->user[ulen] = '\0';
            memcpy(r->pass, p + 4 + ulen, plen); r->pass[plen] = '\0';
            return (int)need;
        }
        case SMP_CMD_DEL_USER: {
            if (len < 3) return 0;
            uint8_t ulen = p[2];
            if (ulen == 0) return -1;
            size_t need = (size_t)(3 + ulen);
            if (len < need) return 0;
            memcpy(r->user, p + 3, ulen); r->user[ulen] = '\0';
            return (int)need;
        }
        case SMP_CMD_SET_CONFIG: {
            if (len < 3) return 0;
            r->key = p[2];
            if (r->key == SMP_CFG_AUTH_REQUIRED) {
                if (len < 4) return 0;
                r->u8 = p[3];
                return 4;
            } else {
                if (len < 7) return 0;
                r->u32 = ((uint32_t)p[3] << 24) | ((uint32_t)p[4] << 16) |
                         ((uint32_t)p[5] << 8) | (uint32_t)p[6];
                return 7;
            }
        }
        default:
            return -2; /* comando desconocido (consumimos 2) */
    }
}

/* ---------------------- construcción de respuestas ---------------- */

static void resp_header(buffer *b, uint8_t cmd, uint8_t status, uint16_t datalen) {
    buffer_write(b, SMP_VERSION);
    buffer_write(b, cmd);
    buffer_write(b, status);
    put_u16(b, datalen);
}

static void resp_simple(buffer *b, uint8_t cmd, uint8_t status) {
    resp_header(b, cmd, status, 0);
}

static void resp_metrics(buffer *b) {
    struct metrics *m = metrics_get();
    resp_header(b, SMP_CMD_METRICS, SMP_OK, 56);
    put_u64(b, m->historic_connections);
    put_u64(b, m->current_connections);
    put_u64(b, metrics_bytes_transferred());
    put_u64(b, m->failed_connections);
    put_u64(b, (uint64_t)users_count());
    put_u64(b, m->bytes_sent);
    put_u64(b, m->bytes_received);
}

static void resp_get_config(buffer *b) {
    struct proxy_config *c = config_get();
    resp_header(b, SMP_CMD_GET_CONFIG, SMP_OK, 9);
    put_u32(b, (uint32_t)c->io_buffer_size);
    put_u32(b, c->conn_timeout_secs);
    buffer_write(b, c->auth_required ? 1 : 0);
}

static void resp_list_users(buffer *b) {
    size_t count = users_count();
    uint32_t datalen = 2;
    for (size_t i = 0; i < count; i++) {
        const char *n = users_name_at(i);
        datalen += 1 + (uint32_t)strlen(n);
    }
    resp_header(b, SMP_CMD_LIST_USERS, SMP_OK, (uint16_t)datalen);
    put_u16(b, (uint16_t)count);
    for (size_t i = 0; i < count; i++) {
        const char *n = users_name_at(i);
        size_t l = strlen(n);
        buffer_write(b, (uint8_t)l);
        for (size_t j = 0; j < l; j++) {
            buffer_write(b, (uint8_t)n[j]);
        }
    }
}

static void process_request(struct mgmt_conn *c, struct mgmt_req *r) {
    switch (r->cmd) {
        case SMP_CMD_METRICS:
            resp_metrics(&c->wbuf);
            break;
        case SMP_CMD_GET_CONFIG:
            resp_get_config(&c->wbuf);
            break;
        case SMP_CMD_LIST_USERS:
            resp_list_users(&c->wbuf);
            break;
        case SMP_CMD_ADD_USER: {
            enum users_result ur = users_add(r->user, r->pass);
            uint8_t st = SMP_OK;
            if (ur == USERS_FULL)         st = SMP_USER_LIMIT_REACHED;
            else if (ur == USERS_INVALID) st = SMP_INVALID_ARGUMENTS;
            resp_simple(&c->wbuf, r->cmd, st);
            break;
        }
        case SMP_CMD_DEL_USER: {
            enum users_result ur = users_del(r->user);
            uint8_t st = (ur == USERS_OK) ? SMP_OK :
                         (ur == USERS_NOT_FOUND) ? SMP_USER_NOT_FOUND
                                                 : SMP_INVALID_ARGUMENTS;
            resp_simple(&c->wbuf, r->cmd, st);
            break;
        }
        case SMP_CMD_SET_CONFIG: {
            struct proxy_config *cfg = config_get();
            uint8_t st = SMP_OK;
            switch (r->key) {
                case SMP_CFG_IO_BUFFER_SIZE:
                    if (r->u32 < CONFIG_MIN_BUFFER) r->u32 = CONFIG_MIN_BUFFER;
                    if (r->u32 > CONFIG_MAX_BUFFER) r->u32 = CONFIG_MAX_BUFFER;
                    cfg->io_buffer_size = r->u32;
                    break;
                case SMP_CFG_CONN_TIMEOUT:
                    cfg->conn_timeout_secs = r->u32;
                    break;
                case SMP_CFG_AUTH_REQUIRED:
                    cfg->auth_required = (r->u8 != 0);
                    break;
                default:
                    st = SMP_INVALID_ARGUMENTS;
                    break;
            }
            resp_simple(&c->wbuf, r->cmd, st);
            break;
        }
        default:
            resp_simple(&c->wbuf, r->cmd, SMP_UNKNOWN_COMMAND);
            break;
    }
}

/* ---------------------------- handlers ---------------------------- */

static void mgmt_done(struct selector_key *key) {
    selector_unregister_fd(key->s, key->fd);
}

static void mgmt_close(struct selector_key *key) {
    struct mgmt_conn *c = ATTACH(key);
    close(key->fd);
    free(c);
}

static const struct fd_handler mgmt_handler;

/* Intenta consumir el buffer de lectura y avanzar de estado. */
static void mgmt_try_process(struct selector_key *key) {
    struct mgmt_conn *c = ATTACH(key);

    for (;;) {
        size_t avail;
        uint8_t *p = buffer_read_ptr(&c->rbuf, &avail);

        if (c->state == MGMT_AUTH) {
            char user[256], pass[256];
            int rc = parse_auth(p, avail, user, pass);
            if (rc == 0) {
                return; /* falta más */
            }
            if (rc < 0) {
                mgmt_done(key);
                return;
            }
            buffer_read_adv(&c->rbuf, rc);
            struct proxy_config *cfg = config_get();
            c->auth_ok = (strcmp(user, cfg->admin_user) == 0 &&
                          strcmp(pass, cfg->admin_pass) == 0);
            buffer_reset(&c->wbuf);
            buffer_write(&c->wbuf, SMP_VERSION);
            buffer_write(&c->wbuf, c->auth_ok ? SMP_AUTH_OK : SMP_AUTH_FAILED);
            c->close_after_write = !c->auth_ok;
            c->state = MGMT_AUTH_REPLY;
            selector_set_interest(key->s, c->fd, OP_WRITE);
            return;
        } else if (c->state == MGMT_REQUEST) {
            struct mgmt_req r;
            memset(&r, 0, sizeof(r));
            int rc = parse_request(p, avail, &r);
            if (rc == 0) {
                return;
            }
            buffer_reset(&c->wbuf);
            if (rc == -1) {
                mgmt_done(key);
                return;
            }
            if (rc == -2) {
                /* comando desconocido: consumimos VER+CMD y respondemos */
                buffer_read_adv(&c->rbuf, 2);
                resp_simple(&c->wbuf, r.cmd, SMP_UNKNOWN_COMMAND);
            } else {
                buffer_read_adv(&c->rbuf, rc);
                process_request(c, &r);
            }
            c->state = MGMT_RESPONSE;
            selector_set_interest(key->s, c->fd, OP_WRITE);
            return;
        } else {
            return; /* en estados de escritura no procesamos */
        }
    }
}

static void mgmt_read(struct selector_key *key) {
    struct mgmt_conn *c = ATTACH(key);
    size_t space;
    uint8_t *ptr = buffer_write_ptr(&c->rbuf, &space);
    if (space == 0) {
        mgmt_done(key);
        return;
    }
    ssize_t n = recv(c->fd, ptr, space, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return;
        mgmt_done(key);
        return;
    }
    if (n == 0) {
        mgmt_done(key);
        return;
    }
    buffer_write_adv(&c->rbuf, n);
    mgmt_try_process(key);
}

static void mgmt_write(struct selector_key *key) {
    struct mgmt_conn *c = ATTACH(key);
    size_t n;
    uint8_t *ptr = buffer_read_ptr(&c->wbuf, &n);
    ssize_t w = send(c->fd, ptr, n, MSG_NOSIGNAL);
    if (w < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return;
        mgmt_done(key);
        return;
    }
    buffer_read_adv(&c->wbuf, w);
    if (buffer_can_read(&c->wbuf)) {
        return; /* falta escribir */
    }
    if (c->close_after_write) {
        mgmt_done(key);
        return;
    }
    /* respuesta enviada: volvemos a esperar requests */
    c->state = (c->state == MGMT_AUTH_REPLY) ? MGMT_REQUEST : MGMT_REQUEST;
    selector_set_interest(key->s, c->fd, OP_READ);
    /* puede haber quedado un request pipelined en rbuf */
    mgmt_try_process(key);
}

static const struct fd_handler mgmt_handler = {
    .handle_read  = mgmt_read,
    .handle_write = mgmt_write,
    .handle_block = NULL,
    .handle_close = mgmt_close,
};

void mgmt_passive_accept(struct selector_key *key) {
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    int fd = accept(key->fd, (struct sockaddr *)&addr, &addr_len);
    if (fd < 0) {
        return;
    }
    if (selector_fd_set_nio(fd) < 0) {
        close(fd);
        return;
    }
    struct mgmt_conn *c = calloc(1, sizeof(*c));
    if (c == NULL) {
        close(fd);
        return;
    }
    c->fd = fd;
    c->state = MGMT_AUTH;
    buffer_init(&c->rbuf, MGMT_RBUF, c->rraw);
    buffer_init(&c->wbuf, MGMT_WBUF, c->wraw);
    if (selector_register(key->s, fd, &mgmt_handler, OP_READ, c)
            != SELECTOR_SUCCESS) {
        free(c);
        close(fd);
        return;
    }
}
