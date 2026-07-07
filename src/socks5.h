/* socks5.h - Servidor SOCKS5: aceptación de conexiones y máquina de estados. */
#ifndef SOCKS5_SOCKS5_H
#define SOCKS5_SOCKS5_H

#include "selector.h"

/* Handler de aceptación para el socket pasivo SOCKS. */
void socksv5_passive_accept(struct selector_key *key);

/* Libera recursos del pool de conexiones (al apagar). */
void socksv5_pool_destroy(void);

#endif /* SOCKS5_SOCKS5_H */
