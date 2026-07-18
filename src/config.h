/* config.h - Configuración del proxy modificable en tiempo de ejecución
 * (vía protocolo de monitoreo). Singleton global. */
#ifndef UTIL_CONFIG_H
#define UTIL_CONFIG_H

#include <stdbool.h>
#include <stddef.h>

#define CONFIG_ADMIN_MAX 255

#define CONFIG_MIN_BUFFER   256
#define CONFIG_MAX_BUFFER   (1 << 20)   /* 1 MiB por sentido, tope de sanidad */

struct proxy_config {
    size_t   io_buffer_size;     /* bytes por sentido; aplica a conexiones nuevas */
    unsigned conn_timeout_secs;  /* timeout de inactividad (0 = sin timeout)      */
    bool     auth_required;      /* true: exige user/pass; false: admite NO_AUTH  */
    bool     pop3_sniff;         /* disector de credenciales POP3 activo (-d)     */
    char     admin_user[CONFIG_ADMIN_MAX + 1];
    char     admin_pass[CONFIG_ADMIN_MAX + 1];
};

void config_init_defaults(void);
struct proxy_config *config_get(void);

#endif /* UTIL_CONFIG_H */
