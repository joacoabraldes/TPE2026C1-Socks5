# Documento de Diseño — Proxy SOCKS5 + Protocolo de Monitoreo (SMP)

Materia: Protocolos de Comunicación (ITBA) — TPE 2026/1

Este documento describe (1) la arquitectura general del servidor y (2) el
protocolo propio de monitoreo y configuración **SMP** en estilo RFC. El
protocolo SOCKS5 en sí (RFC1928/RFC1929) no se re-documenta acá; sólo lo que
diseñamos nosotros.

---

## 1. Arquitectura general

- **Un único hilo principal** con multiplexación de E/S no bloqueante (`epoll`
  en Linux, con *fallback* a `poll` en otros POSIX), encapsulado en el módulo
  `selector`.
- **Todos** los descriptores (listeners SOCKS y de management, conexiones de
  cliente, conexiones al origen, pipe de despertar de DNS) son `O_NONBLOCK` y se
  operan mediante **suscripciones** al selector (interés de lectura/escritura),
  nunca con llamadas bloqueantes.
- **Un único hilo adicional permitido**: el *pool* de resolución de nombres
  (`getaddrinfo`). Ese hilo **no** hace ninguna otra E/S: resuelve y despierta al
  hilo principal escribiendo un byte en un *self-pipe* registrado en el selector.
- **Máquina de estados por conexión** (`stm`): cada conexión SOCKS avanza
  `HELLO → AUTH → REQUEST → RESOLVE → CONNECTING → REPLY → COPY → DONE/ERROR`.
- **Buffers acotados** por conexión (uno por sentido). *Backpressure*: si un
  extremo no drena, se quita el interés de lectura del extremo rápido.

Ver `src/` para la división en `selector/`, `socks5/`, `mgmt/`, `dns/`, `util/`.

---

## 2. Protocolo de Monitoreo y Configuración — **SMP/1.0**

### 2.1. Alcance

SMP (*Socks Management Protocol*) permite a un administrador, **en tiempo de
ejecución y sin reiniciar** el servidor:

- consultar métricas de operación,
- listar / agregar / borrar usuarios del proxy,
- consultar y modificar parámetros de configuración (tamaño de buffer de E/S,
  *timeout* de inactividad, si se admite el método SOCKS *sin autenticación*).

**No** es una extensión de SOCKS: es un protocolo independiente escuchando en
**otro socket pasivo, en otro puerto**, dentro del mismo proceso y el mismo
*event loop* no bloqueante.

### 2.2. Decisiones de diseño y justificación

- **Transporte: TCP.** Las operaciones de administración son de tipo
  petición/respuesta, requieren entrega confiable y ordenada (agregar un usuario
  no puede perderse ni duplicarse), y los mensajes son chicos. TCP nos da esa
  confiabilidad sin reimplementarla. Se descartó UDP para no manejar
  retransmisión/duplicados a mano.
- **Codificación: binaria, de longitud explícita.** Frente a un protocolo de
  texto (más simple de depurar con `netcat`, pero justamente la consigna lo
  prohíbe como interfaz), elegimos binario por ser compacto y *unívoco* al
  parsear: cada campo variable va precedido por su longitud, y los enteros van en
  **network byte order (big-endian)**. Esto evita ambigüedades de *encoding* y
  hace trivial el manejo de lecturas parciales (se conoce de antemano cuántos
  bytes falta leer).
- **Serialización:** campos de tamaño fijo concatenados; los de tamaño variable
  (nombres de usuario, contraseñas) usan el patrón `LEN(1) || bytes`. No usamos
  *padding* ni alineación: el formato es *byte-oriented*, independiente del
  compilador y de la arquitectura.
- **Autenticación:** esquema usuario/contraseña de administrador, con un
  *handshake* inspirado en RFC1929 (mismo patrón `LEN || valor`). Es simple,
  suficiente para el alcance y homogéneo con el resto del protocolo. Las
  credenciales de admin son **independientes** de los usuarios del proxy y se
  configuran por línea de comandos (`-a user:pass`, por defecto `admin:admin`).
  > Nota de seguridad: SMP viaja en claro; se recomienda exponerlo sólo en
  > `loopback` (default) o sobre un canal seguro. Documentado como limitación.

### 2.3. Modelo de interacción

Una conexión SMP consiste en:

```
  1. Handshake de autenticación   (1 request / 1 response)
  2. 0..N pares Request/Response   (la conexión se puede reutilizar)
  3. Cierre por cualquiera de las partes
```

Todos los enteros multibyte son **big-endian**. `uint8` = 1 byte, `uint16` = 2,
`uint32` = 4, `uint64` = 8.

### 2.4. Handshake de autenticación

```
   Cliente -> Servidor:
     +-----+------+----------+------+----------+
     | VER | ULEN |  UNAME   | PLEN |  PASSWD  |
     +-----+------+----------+------+----------+
     |  1  |  1   | 1..255   |  1   | 1..255   |
     +-----+------+----------+------+----------+

   VER   = 0x01  (versión de SMP)
   ULEN  = longitud del nombre de usuario admin
   UNAME = nombre de usuario admin (ULEN bytes)
   PLEN  = longitud de la contraseña
   PASSWD= contraseña admin (PLEN bytes)

   Servidor -> Cliente:
     +-----+--------+
     | VER | STATUS |
     +-----+--------+
     |  1  |   1    |
     +-----+--------+

   STATUS = 0x00 OK  |  0x01 credenciales inválidas
```

Si la autenticación falla, el servidor responde con `STATUS != 0` y **cierra**
la conexión.

### 2.5. Request / Response (post-autenticación)

**Request:**

```
     +-----+-----+---------------------+
     | VER | CMD |     ARGS (var.)     |
     +-----+-----+---------------------+
     |  1  |  1  |     0..N bytes      |
     +-----+-----+---------------------+
```

**Response:**

```
     +-----+-----+--------+---------+------------------+
     | VER | CMD | STATUS | DATALEN |      DATA        |
     +-----+-----+--------+---------+------------------+
     |  1  |  1  |   1    |    2    |   DATALEN bytes  |
     +-----+-----+--------+---------+------------------+

   VER     = 0x01
   CMD     = eco del comando pedido
   STATUS  = código de resultado (ver 2.7)
   DATALEN = uint16 big-endian, longitud del payload DATA
   DATA    = payload dependiente del comando (ver 2.6)
```

### 2.6. Comandos

| CMD  | Nombre       | ARGS del request                                   | DATA de la respuesta (si STATUS=OK)                |
|------|--------------|----------------------------------------------------|----------------------------------------------------|
| 0x00 | METRICS      | (ninguno)                                          | bloque de métricas (2.6.1)                          |
| 0x01 | ADD_USER     | `ULEN‖UNAME‖PLEN‖PASSWD`                            | (vacío)                                             |
| 0x02 | DEL_USER     | `ULEN‖UNAME`                                        | (vacío)                                             |
| 0x03 | LIST_USERS   | (ninguno)                                          | `COUNT(2) ‖ [ULEN‖UNAME]*`                          |
| 0x04 | GET_CONFIG   | (ninguno)                                          | bloque de config (2.6.2)                            |
| 0x05 | SET_CONFIG   | `KEY(1) ‖ VALUE(var.)` (2.6.2)                      | (vacío)                                             |

#### 2.6.1. Bloque de métricas (respuesta de METRICS)

Todos los contadores `uint64` big-endian, en este orden:

```
   historic_connections   (8)   conexiones históricas totales
   current_connections    (8)   conexiones concurrentes actuales
   bytes_transferred      (8)   bytes proxeados (ambos sentidos)
   failed_connections     (8)   conexiones que terminaron en error
   current_users          (8)   cantidad de usuarios registrados
   bytes_sent             (8)   bytes cliente -> origen
   bytes_received         (8)   bytes origen -> cliente
```

#### 2.6.2. Configuración (GET_CONFIG / SET_CONFIG)

`GET_CONFIG` devuelve, en orden:

```
   io_buffer_size     (uint32)  tamaño del buffer de E/S por sentido (bytes)
   conn_timeout_secs  (uint32)  timeout de inactividad por conexión (segundos)
   auth_required      (uint8)   1 = se exige user/pass, 0 = se admite NO_AUTH
```

`SET_CONFIG` recibe `KEY(1) ‖ VALUE`:

```
   KEY 0x01  io_buffer_size     VALUE = uint32   (se aplica a conexiones NUEVAS)
   KEY 0x02  conn_timeout_secs  VALUE = uint32
   KEY 0x03  auth_required      VALUE = uint8 (0/1)
```

### 2.7. Códigos de estado (STATUS)

```
   0x00  OK
   0x01  AUTH_REQUIRED       (comando antes de autenticar)
   0x02  UNKNOWN_COMMAND
   0x03  INVALID_ARGUMENTS
   0x04  USER_ALREADY_EXISTS
   0x05  USER_NOT_FOUND
   0x06  USER_LIMIT_REACHED
   0x07  INTERNAL_ERROR
```

### 2.8. Cliente de terminal

Se provee el ejecutable `socks5-mgmt` (I/O bloqueante, admitido por su
simpleza). Subcomandos:

```
   socks5-mgmt [-L host] [-P port] [-u admin] [-w pass] <subcomando> [args]

   metrics
   add-user <nombre> <password>
   del-user <nombre>
   list-users
   get-config
   set-config <buffer-size|timeout|auth-required> <valor>
```

El cliente arma los mensajes binarios descritos arriba; **no** se admite usar
`netcat` como cliente.

---

## 3. Registro de acceso (access log)

Por cada request SOCKS atendido se emite una línea (a `stdout`/archivo) con:

```
   <timestamp ISO-8601> <usuario> <cmd> <origen-ip:puerto> -> <destino:puerto> <status>
```

Pensado para responder "quién se conectó a tal destino y cuándo".

---

## 4. Métricas

Volátiles (en memoria). Las expuestas por SMP están en 2.6.1. Extra sobre el
mínimo pedido: `failed_connections`, `bytes_sent`, `bytes_received`,
`current_users`.
