/* logger.h - Registro de acceso y logging general.
 * El access log responde "quién se conectó a tal destino y cuándo". */
#ifndef UTIL_LOGGER_H
#define UTIL_LOGGER_H

#include <stdio.h>

void logger_init(FILE *access_out);

/* Registra un acceso SOCKS.
 *   user   : usuario autenticado ("-" si anónimo)
 *   cmd    : "CONNECT", etc.
 *   origin : "ip:puerto" del cliente
 *   dest   : "host:puerto" destino
 *   status : código de reply SOCKS (0 = éxito) */
void logger_access(const char *user, const char *cmd,
                   const char *origin, const char *dest, int status);

#if defined(__GNUC__)
#define LOGGER_PRINTF(a, b) __attribute__((format(printf, a, b)))
#else
#define LOGGER_PRINTF(a, b)
#endif

/* Log general con timestamp a stderr. */
void logger_log(const char *level, const char *fmt, ...) LOGGER_PRINTF(2, 3);

#define log_info(...)  logger_log("INFO",  __VA_ARGS__)
#define log_warn(...)  logger_log("WARN",  __VA_ARGS__)
#define log_error(...) logger_log("ERROR", __VA_ARGS__)

#endif /* UTIL_LOGGER_H */
