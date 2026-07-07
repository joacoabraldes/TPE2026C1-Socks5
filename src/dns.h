/* dns.h - Resolución de nombres asíncrona.
 *
 * Único uso permitido de hilos adicionales: un hilo (detached) por resolución
 * ejecuta getaddrinfo() y NO hace ninguna otra E/S; al terminar despierta al
 * hilo principal con selector_notify_block(). El hilo principal recupera el
 * resultado desde el propio struct dns_request.
 */
#ifndef DNS_DNS_H
#define DNS_DNS_H

#include <netdb.h>
#include <stdint.h>
#include "selector.h"

struct dns_request {
    fd_selector      s;          /* selector a despertar        */
    int              notify_fd;  /* fd sobre el que correr block */
    void            *conn;       /* back-pointer (struct socks5) */

    char             host[256];
    char             service[8]; /* puerto como string          */

    /* completado por el hilo resolver: */
    struct addrinfo *result;     /* lista (owned) o NULL         */
    int              status;     /* valor de retorno de getaddrinfo */
};

/* Lanza la resolución en un hilo detached. `req` debe seguir vivo hasta que se
 * procese la notificación. Devuelve 0 si se lanzó el hilo, -1 en error. */
int  dns_resolve_async(struct dns_request *req);

/* Libera la lista de addrinfo asociada (no libera el propio req). */
void dns_request_clear(struct dns_request *req);

#endif /* DNS_DNS_H */
