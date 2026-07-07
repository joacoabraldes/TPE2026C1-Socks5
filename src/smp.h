/* smp.h - Constantes del protocolo de monitoreo SMP/1.0.
 * Compartido por el servidor (src/mgmt) y el cliente (src/client).
 * Ver docs/DISENO.md para la especificación completa. */
#ifndef MGMT_SMP_H
#define MGMT_SMP_H

#define SMP_VERSION 0x01

/* Comandos (campo CMD) */
enum smp_cmd {
    SMP_CMD_METRICS     = 0x00,
    SMP_CMD_ADD_USER    = 0x01,
    SMP_CMD_DEL_USER    = 0x02,
    SMP_CMD_LIST_USERS  = 0x03,
    SMP_CMD_GET_CONFIG  = 0x04,
    SMP_CMD_SET_CONFIG  = 0x05,
};

/* Códigos de estado (campo STATUS) */
enum smp_status {
    SMP_OK                  = 0x00,
    SMP_AUTH_REQUIRED       = 0x01,
    SMP_UNKNOWN_COMMAND     = 0x02,
    SMP_INVALID_ARGUMENTS   = 0x03,
    SMP_USER_ALREADY_EXISTS = 0x04,
    SMP_USER_NOT_FOUND      = 0x05,
    SMP_USER_LIMIT_REACHED  = 0x06,
    SMP_INTERNAL_ERROR      = 0x07,
};

/* Resultado del handshake de autenticación (campo STATUS del auth) */
enum smp_auth_status {
    SMP_AUTH_OK     = 0x00,
    SMP_AUTH_FAILED = 0x01,
};

/* Claves para SET_CONFIG */
enum smp_config_key {
    SMP_CFG_IO_BUFFER_SIZE = 0x01,
    SMP_CFG_CONN_TIMEOUT   = 0x02,
    SMP_CFG_AUTH_REQUIRED  = 0x03,
};

/* Límites de framing */
#define SMP_MAX_FIELD 255   /* longitud máxima de user/pass (LEN de 1 byte) */

#endif /* MGMT_SMP_H */
