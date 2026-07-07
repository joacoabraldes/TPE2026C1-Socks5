/* mgmt.h - Servidor del protocolo de monitoreo y configuración (SMP/1.0).
 * Socket pasivo propio, en el mismo event loop no bloqueante. */
#ifndef MGMT_MGMT_H
#define MGMT_MGMT_H

#include "selector.h"

void mgmt_passive_accept(struct selector_key *key);

#endif /* MGMT_MGMT_H */
