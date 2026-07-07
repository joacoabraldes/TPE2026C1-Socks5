/* users.h - Base de datos en memoria de usuarios del proxy (RFC1929).
 * Manipulable en tiempo de ejecución vía el protocolo de monitoreo. */
#ifndef UTIL_USERS_H
#define UTIL_USERS_H

#include <stdbool.h>
#include <stddef.h>

#define USERS_MAX          64
#define USERS_MAX_NAME     255
#define USERS_MAX_PASS     255

enum users_result {
    USERS_OK = 0,
    USERS_EXISTS,
    USERS_NOT_FOUND,
    USERS_FULL,
    USERS_INVALID,
};

void users_init(void);

/* Alta. Si el usuario ya existe, actualiza la contraseña. */
enum users_result users_add(const char *name, const char *pass);
enum users_result users_del(const char *name);

/* Verifica credenciales. true si coinciden. */
bool users_check(const char *name, const char *pass);
bool users_exists(const char *name);

size_t users_count(void);
/* Devuelve el nombre en el índice i (0..count-1) o NULL. */
const char *users_name_at(size_t i);

#endif /* UTIL_USERS_H */
