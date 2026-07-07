#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include "selector.h"
#include "socks5.h"
#include "mgmt.h"
#include "args.h"
#include "config.h"
#include "users.h"
#include "metrics.h"
#include "logger.h"

#define MAX_LISTENERS 4

/* señal usada por el selector para notificar resoluciones DNS listas */
#define SELECTOR_SIGNAL SIGUSR1

/* Crea un socket pasivo TCP no bloqueante en (addr, port). addr NULL => any. */
static int create_passive_socket(const char *addr, unsigned short port,
                                 int family, int backlog) {
    int fd = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        return -1;
    }
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (family == AF_INET6) {
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
    }

    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    socklen_t sslen;
    if (family == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)&ss;
        a->sin_family = AF_INET;
        a->sin_port   = htons(port);
        if (addr == NULL) {
            a->sin_addr.s_addr = htonl(INADDR_ANY);
        } else if (inet_pton(AF_INET, addr, &a->sin_addr) != 1) {
            close(fd);
            return -1;
        }
        sslen = sizeof(*a);
    } else {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
        a->sin6_family = AF_INET6;
        a->sin6_port   = htons(port);
        if (addr == NULL) {
            a->sin6_addr = in6addr_any;
        } else if (inet_pton(AF_INET6, addr, &a->sin6_addr) != 1) {
            close(fd);
            return -1;
        }
        sslen = sizeof(*a);
    }
    if (bind(fd, (struct sockaddr *)&ss, sslen) < 0 ||
        listen(fd, backlog) < 0 ||
        selector_fd_set_nio(fd) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static volatile sig_atomic_t g_sigcount = 0;

static void on_signal(int sig) {
    (void)sig;
    g_sigcount++;
}

static void listener_close(struct selector_key *key) {
    close(key->fd);
}

static const struct fd_handler socks_listener_handler = {
    .handle_read  = socksv5_passive_accept,
    .handle_close = listener_close,
};

static const struct fd_handler mgmt_listener_handler = {
    .handle_read  = mgmt_passive_accept,
    .handle_close = listener_close,
};

/* Sube el límite de descriptores para soportar >=500 conexiones (2 fds c/u). */
static void raise_fd_limit(void) {
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        rlim_t want = 4096;
        if (rl.rlim_max != RLIM_INFINITY && want > rl.rlim_max) {
            want = rl.rlim_max;
        }
        if (rl.rlim_cur < want) {
            rl.rlim_cur = want;
            if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
                log_warn("no se pudo subir RLIMIT_NOFILE: %s", strerror(errno));
            }
        }
    }
}

/* Registra un listener y lo agrega al arreglo. Devuelve 0 si ok. */
static int add_listener(fd_selector s, const char *addr, unsigned short port,
                        int family, const struct fd_handler *h,
                        int *fds, size_t *nfds) {
    int fd = create_passive_socket(addr, port, family, 512);
    if (fd < 0) {
        return -1;
    }
    if (selector_register(s, fd, h, OP_READ, NULL) != SELECTOR_SUCCESS) {
        close(fd);
        return -1;
    }
    fds[(*nfds)++] = fd;
    return 0;
}

static bool looks_ipv6(const char *addr) {
    return addr != NULL && strchr(addr, ':') != NULL;
}

int main(int argc, char **argv) {
    struct socks5args args;
    args_parse(argc, argv, &args);

    /* --- inicialización de subsistemas --- */
    metrics_init();
    users_init();
    config_init_defaults();
    logger_init(stdout);

    struct proxy_config *cfg = config_get();
    strncpy(cfg->admin_user, args.admin_user, CONFIG_ADMIN_MAX);
    cfg->admin_user[CONFIG_ADMIN_MAX] = '\0';
    strncpy(cfg->admin_pass, args.admin_pass, CONFIG_ADMIN_MAX);
    cfg->admin_pass[CONFIG_ADMIN_MAX] = '\0';
    cfg->auth_required = args.require_auth || (args.nusers > 0);
    for (size_t i = 0; i < args.nusers; i++) {
        users_add(args.users[i].name, args.users[i].pass);
    }

    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    raise_fd_limit();

    struct selector_init sel_conf = {
        .signal         = SELECTOR_SIGNAL,
        .select_timeout = { .tv_sec = 10, .tv_nsec = 0 },
    };
    if (selector_init(&sel_conf) != SELECTOR_SUCCESS) {
        log_error("no se pudo inicializar el selector");
        return 1;
    }
    fd_selector s = selector_new(1024);
    if (s == NULL) {
        log_error("no se pudo crear el selector");
        return 1;
    }

    int listeners[MAX_LISTENERS];
    size_t nlisteners = 0;

    /* --- listeners SOCKS --- */
    const char *socks_addr = args.socks_addr[0] ? args.socks_addr : NULL;
    if (socks_addr == NULL) {
        /* todas las interfaces: IPv4 e IPv6 */
        add_listener(s, NULL, args.socks_port, AF_INET,
                     &socks_listener_handler, listeners, &nlisteners);
        add_listener(s, "::", args.socks_port, AF_INET6,
                     &socks_listener_handler, listeners, &nlisteners);
    } else {
        int fam = looks_ipv6(socks_addr) ? AF_INET6 : AF_INET;
        if (add_listener(s, socks_addr, args.socks_port, fam,
                         &socks_listener_handler, listeners, &nlisteners) != 0) {
            log_error("no se pudo abrir el listener SOCKS en %s:%u",
                      socks_addr, args.socks_port);
            return 1;
        }
    }
    if (nlisteners == 0) {
        log_error("no se pudo abrir ningun listener SOCKS");
        return 1;
    }

    /* --- listener de management --- */
    {
        int fam = looks_ipv6(args.mgmt_addr) ? AF_INET6 : AF_INET;
        if (add_listener(s, args.mgmt_addr, args.mgmt_port, fam,
                         &mgmt_listener_handler, listeners, &nlisteners) != 0) {
            log_error("no se pudo abrir el listener de management en %s:%u",
                      args.mgmt_addr, args.mgmt_port);
            return 1;
        }
    }

    log_info("socks5d escuchando SOCKS en puerto %u, management en %s:%u",
             args.socks_port, args.mgmt_addr, args.mgmt_port);

    /* --- bucle principal --- */
    bool shutting_down = false;
    for (;;) {
        selector_status st = selector_select(s);
        if (st != SELECTOR_SUCCESS) {
            log_error("selector_select: %s", selector_error(st));
            break;
        }
        if (g_sigcount >= 2) {
            log_info("segunda senal: apagado forzado");
            break;
        }
        if (g_sigcount >= 1 && !shutting_down) {
            shutting_down = true;
            log_info("senal recibida: dejando de aceptar; esperando %llu conexiones",
                     (unsigned long long)metrics_get()->current_connections);
            for (size_t i = 0; i < nlisteners; i++) {
                selector_unregister_fd(s, listeners[i]);
            }
            nlisteners = 0;
        }
        if (shutting_down && metrics_get()->current_connections == 0) {
            log_info("apagado controlado completo");
            break;
        }
    }

    for (size_t i = 0; i < nlisteners; i++) {
        selector_unregister_fd(s, listeners[i]);
    }
    selector_destroy(s);
    selector_close();
    socksv5_pool_destroy();
    return 0;
}
