#include <string.h>
#include "config.h"

static struct proxy_config cfg;

void config_init_defaults(void) {
    memset(&cfg, 0, sizeof(cfg));
    cfg.io_buffer_size    = 8192;
    cfg.conn_timeout_secs = 0;      /* sin timeout por defecto */
    cfg.auth_required     = false;  /* se ajusta según usuarios/args */
    strcpy(cfg.admin_user, "admin");
    strcpy(cfg.admin_pass, "admin");
}

struct proxy_config *config_get(void) {
    return &cfg;
}
