/* metrics.h - Métricas globales volátiles del proxy.
 * Todas se leen/escriben sólo desde el hilo principal (no requieren atómicos). */
#ifndef UTIL_METRICS_H
#define UTIL_METRICS_H

#include <stdint.h>

struct metrics {
    uint64_t historic_connections;  /* conexiones aceptadas históricas       */
    uint64_t current_connections;   /* conexiones concurrentes actuales       */
    uint64_t failed_connections;    /* requests que terminaron en error       */
    uint64_t bytes_sent;            /* cliente -> origen                       */
    uint64_t bytes_received;        /* origen -> cliente                       */
};

void  metrics_init(void);
struct metrics *metrics_get(void);

void metrics_connection_opened(void);
void metrics_connection_closed(void);
void metrics_connection_failed(void);
void metrics_add_sent(uint64_t n);
void metrics_add_received(uint64_t n);

uint64_t metrics_bytes_transferred(void); /* sent + received */

#endif /* UTIL_METRICS_H */
