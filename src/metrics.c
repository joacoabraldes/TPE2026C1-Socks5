#include <string.h>
#include "metrics.h"

static struct metrics m;

void metrics_init(void) {
    memset(&m, 0, sizeof(m));
}

struct metrics *metrics_get(void) {
    return &m;
}

void metrics_connection_opened(void) {
    m.historic_connections++;
    m.current_connections++;
}

void metrics_connection_closed(void) {
    if (m.current_connections > 0) {
        m.current_connections--;
    }
}

void metrics_connection_failed(void) {
    m.failed_connections++;
}

void metrics_add_sent(uint64_t n) {
    m.bytes_sent += n;
}

void metrics_add_received(uint64_t n) {
    m.bytes_received += n;
}

uint64_t metrics_bytes_transferred(void) {
    return m.bytes_sent + m.bytes_received;
}
