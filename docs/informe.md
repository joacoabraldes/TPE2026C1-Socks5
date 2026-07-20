% Trabajo Practico Especial - Proxy SOCKS5
% Protocolos de Comunicacion - ITBA - 2026/1
%

---

# 1. Indice

1. Indice
2. Descripcion de los protocolos disenados y las aplicaciones
3. Problemas encontrados durante el diseno y la implementacion
4. Limitaciones de la aplicacion
5. Posibles extensiones
6. Conclusiones
7. Ejemplos de prueba
8. Guia de instalacion
9. Instrucciones para la configuracion
10. Ejemplos de configuracion y monitoreo
11. Documento de diseno (arquitectura)

---

# 2. Descripcion de los protocolos disenados y las aplicaciones

Se implemento un servidor proxy **SOCKS5** (RFC 1928) con autenticacion
usuario/contrasena (RFC 1929), y ademas se disenio un **protocolo propio de
monitoreo y configuracion (SMP)** con su cliente de terminal. El servidor SOCKS
y el servicio de monitoreo corren en el mismo proceso, en un unico hilo, con E/S
no bloqueante multiplexada.

Aplicaciones entregadas:

- **`socks5d`**: el servidor. Atiende el proxy SOCKS5 y, en otro puerto, el
  servicio de monitoreo SMP.
- **`socks5-mgmt`**: cliente de terminal del protocolo de monitoreo (I/O
  bloqueante, admitido por su simpleza). Ofrece subcomandos como
  `metrics`, `add-user`, `list-users`, etc.

La descripcion completa y agnostica al lenguaje del protocolo SMP esta en la
seccion 11 (Documento de diseno), en estilo RFC.

---

# 3. Problemas encontrados durante el diseno y la implementacion

Esta seccion resume lo que mas costo resolver.

## 3.1 Escrituras y lecturas parciales

En E/S no bloqueante, un `recv`/`send` puede transferir **menos** bytes de los
pedidos. Todo el codigo avanza los buffers segun los bytes reales devueltos, y
los parsers de SOCKS son **incrementales** (consumen byte a byte y guardan su
estado), de modo que un mensaje que llega cortado no rompe nada: se espera a que
llegue el resto.

## 3.2 connect() no bloqueante

Sobre un socket no bloqueante, `connect` normalmente **no** completa en el acto:
devuelve `-1` con `errno == EINPROGRESS`. El error tipico es asumir que conecto.
La solucion: registrar el fd del origen para escritura y, cuando queda writable,
verificar el resultado real con `getsockopt(fd, SOL_SOCKET, SO_ERROR, ...)`.
Recien ahi se sabe si conecto o con que error fallo (que se traduce al reply code
correspondiente).

## 3.3 El ciclo de E/S del relay (escritura optimista)

La primera version hacia `select -> read -> select -> write`: leia un bloque, lo
guardaba en el buffer, marcaba interes de escritura, y recien en la siguiente
vuelta del selector lo mandaba. Eso gasta dos vueltas del selector por bloque.
Se cambio a **escritura optimista** (`select -> read -> write`): apenas se lee,
se intenta reenviar en el acto; solo si el socket destino no acepta todo
(`EWOULDBLOCK`) se guarda el sobrante y se espera a que se libere. Se verifico
con `strace` que el `recvfrom` queda seguido directo del `sendto`, sin un
`pselect` intermedio.

## 3.4 Half-close

Cerrar toda la conexion cuando un extremo manda EOF cortaba respuestas cuando el
cliente cerraba solo su mitad de escritura pero todavia esperaba datos. Se separo
el cierre por sentido: cuando un lado termina y se drena su buffer, se hace
`shutdown(SHUT_WR)` del otro lado, y recien se cierra cuando terminaron las dos
direcciones. Ademas, como una conexion usa dos descriptores que cierran en
momentos distintos, se libera con **conteo de referencias** (se libera cuando se
desregistra el ultimo de los dos fds).

## 3.5 Ciclo de vida del hilo de DNS

`getaddrinfo` es bloqueante, asi que corre en un hilo aparte. El riesgo: si la
conexion se cerrara mientras su resolucion esta en vuelo, el hilo escribiria en
memoria ya liberada. Se evita no liberando la conexion mientras esta resolviendo.

## 3.6 Integracion de los modulos de la catedra y un bug en el selector

Los modulos provistos (`selector`, `buffer`, `stm`, `netutils`) no compilaban
limpio con `-Wall -Wextra -pedantic` ni linkeaban con el `-fno-common` por
defecto de gcc moderno; se hicieron cambios minimos, documentados en
`docs/catedra/README.md`. Ademas se encontro un bug real en el selector:
`selector_fd_set_nio` leia los flags con `fcntl(fd, F_GETFD, ...)` cuando
`O_NONBLOCK` es un *file status flag* (`F_GETFL`/`F_SETFL`), no un *file
descriptor flag*. En Linux "funcionaba" por casualidad, pero es incorrecto; se
corrigio a `F_GETFL`.

## 3.7 Build incremental inconsistente (stale object file)

Al agregar un campo a la estructura de configuracion (`config.h`), se corrio el
offset de un campo usado por el modulo de management. Como el Makefile no
rastreaba dependencias de headers, `make` no recompilo el `.o` de ese modulo, que
quedo con el layout viejo de la struct y leia el campo en el offset equivocado
(la autenticacion de admin fallaba). Se soluciono agregando generacion automatica
de dependencias (`-MMD -MP`) al Makefile, para que un cambio en un `.h` recompile
todos los `.c` que lo incluyen. Es un caso clasico de "stale object / cambio de
layout de struct".

---

# 4. Limitaciones de la aplicacion

- El **timeout de inactividad** se puede configurar por SMP pero todavia no se
  aplica (el tamano de buffer de E/S si se aplica a las conexiones nuevas).
- El maximo de conexiones concurrentes esta acotado por `FD_SETSIZE` (1024
  descriptores), es decir ~500 conexiones (2 fds c/u), por usar el selector
  basado en `pselect`. Cumple el minimo pedido.
- Se lanza **un hilo por resolucion de DNS**; bajo mucha carga simultanea eso
  crea muchos hilos cortos (no hay pool).
- El protocolo SMP viaja en claro; se recomienda exponerlo solo en loopback.
- El reintento sobre multiples IPs esta implementado pero no se forzo en pruebas
  con un FQDN cuya primera IP este caida.

---

# 5. Posibles extensiones

- Cambiar el backend del selector de `pselect` a `epoll(7)` para superar el techo
  de `FD_SETSIZE` y escalar a miles de conexiones.
- Aplicar el timeout de inactividad para cerrar conexiones colgadas.
- Un pool de hilos (o `getaddrinfo_a`) para las resoluciones de DNS.
- Exponer el toggle del disector POP3 y otros parametros por SMP en caliente.
- Cifrar el canal de SMP.

---

# 6. Conclusiones

El trabajo permitio entender en profundidad la programacion de servidores con
E/S no bloqueante multiplexada: el modelo de un solo hilo con un selector, las
maquinas de estado por conexion, el manejo cuidadoso de lecturas y escrituras
parciales, el `connect` asincronico, y el backpressure/half-close en un relay
bidireccional. Tambien implico disenar un protocolo de aplicacion propio (SMP) y
justificar decisiones como transporte, codificacion binaria y framing. Los
problemas que mas ensenaron fueron los sutiles: el `connect` con `SO_ERROR`, el
half-close, y el bug de build incremental por el cambio de layout de una struct.

---

# 7. Ejemplos de prueba

Con el servidor levantado (`bin/socks5d -u test:test -d`):

```
# CONNECT a IPv4, IPv6 y FQDN (los tres devuelven 200)
curl -x socks5://test:test@127.0.0.1:1080 http://example.com/
curl -x socks5://test:test@127.0.0.1:1080 'http://[::1]:8000/'
curl -x socks5h://test:test@127.0.0.1:1080 http://example.com/

# Autenticacion invalida: falla (exit 97)
curl -x socks5://malo:malo@127.0.0.1:1080 http://example.com/

# Destino con el puerto cerrado: reply code 5 (connection refused)
curl -x socks5://test:test@127.0.0.1:1080 http://127.0.0.1:9/
# en el access log: ... -> 127.0.0.1:9  status=5
```

**Disector POP3**: conectando por el proxy a un POP3 en el puerto 110 y enviando
`USER`/`PASS`, el servidor registra las credenciales (esnifadas del trafico):

```
POP3   test   127.0.0.1:36282 -> pop.gmx.com:110   user=bob   pass=s3cr3t!
```

**Escritura optimista**: bajo `strace -e trace=pselect6,recvfrom,sendto`, el
`recvfrom` del pedido queda seguido directo del `sendto` al origen, sin un
`pselect` intermedio de escritura.

**Pruebas de estres**: `scripts/stress.sh <concurrencia> <host:puerto> <user>
<pass> <url>` lanza N conexiones en paralelo a traves del proxy y reporta cuantas
terminan con `HTTP 200` y el throughput aproximado. Preguntas de interes:

- *Maxima cantidad de conexiones simultaneas*: acotada por `FD_SETSIZE` (~500).
  Se sube el limite del shell con `ulimit -n 8192` antes de la prueba.
- *Degradacion del throughput*: si el throughput (req/s) se mantiene y la latencia
  total crece de forma aproximadamente lineal con la concurrencia, el servidor
  escala bien; un salto en fallas indica saturacion.

Durante las pruebas, `bin/socks5-mgmt metrics` muestra el pico de conexiones
concurrentes y los bytes transferidos.

---

# 8. Guia de instalacion

Requiere `gcc`/`cc` con C11, `make` y pthreads (entorno POSIX/Linux).

```
make            # compila servidor (bin/socks5d) y cliente (bin/socks5-mgmt)
make DEBUG=1    # build de debug (con -g, sin optimizar)
make clean
```

Compila con `-std=c11 -Wall -Wextra -pedantic` sin warnings. Artefactos: los
binarios quedan en `bin/`, los objetos en `obj/`.

---

# 9. Instrucciones para la configuracion

Servidor `socks5d`:

```
-l <addr>       direccion de escucha SOCKS (default: todas las interfaces)
-p <puerto>     puerto SOCKS (default 1080)
-L <addr>       direccion del monitoreo (default 127.0.0.1)
-P <puerto>     puerto del monitoreo (default 8080)
-u <user:pass>  agrega un usuario del proxy (repetible, hasta 64)
-a <user:pass>  credenciales de admin del monitoreo (default admin:admin)
-N              exige autenticacion user/pass (deshabilita NO_AUTH)
-d              activa el disector de credenciales POP3
-v / -h         version / ayuda
```

Comportamiento de autenticacion: si hay al menos un usuario (`-u`) o se pasa `-N`,
el proxy exige user/pass; si no, admite el metodo sin autenticacion. En caliente,
por SMP, se pueden cambiar el tamano de buffer de E/S, el timeout y si se exige
autenticacion.

Cliente `socks5-mgmt`:

```
socks5-mgmt [-L host] [-P puerto] [-u admin] [-w pass] <subcomando> [args]
  metrics | add-user <u> <p> | del-user <u> | list-users
  get-config | set-config <buffer-size|timeout|auth-required> <valor>
```

---

# 10. Ejemplos de configuracion y monitoreo

```
bin/socks5-mgmt metrics
bin/socks5-mgmt add-user pablito pass1234
bin/socks5-mgmt list-users
bin/socks5-mgmt set-config buffer-size 16384
bin/socks5-mgmt get-config
bin/socks5-mgmt -u admin -w admin del-user pablito
```

`metrics` devuelve, por ejemplo: conexiones historicas y concurrentes, bytes
transferidos, conexiones fallidas y usuarios registrados.

> Nota (maquina compartida): en un servidor con varios usuarios (p. ej. pampero)
> conviene usar puertos altos unicos (`-p`, `-P`) para no colisionar con otros, y
> apuntar el cliente con el `-P` correcto.

---

# 11. Documento de diseno (arquitectura)

## 11.1 Modelo de ejecucion

El servidor corre en un solo hilo con E/S no bloqueante multiplexada. Se usa el
selector provisto por la catedra, que por dentro se apoya en **`pselect(2)`**:
mantiene dos `fd_set` maestros (lectura y escritura), y en cada iteracion los
copia, llama a `pselect` y despacha los descriptores listos a sus handlers. Cada
fd se registra con un conjunto de callbacks (`fd_handler`) y un interes
(`OP_READ`/`OP_WRITE`), que se cambia segun el estado de la conexion.

El limite de descriptores esta dado por `FD_SETSIZE` (1024). Como cada conexion
SOCKS usa dos descriptores (cliente y origen), el techo real ronda las 500
conexiones concurrentes. Todos los descriptores se ponen en `O_NONBLOCK` antes
de registrarse; no hay ninguna llamada bloqueante dentro del ciclo de eventos.

## 11.2 Maquina de estados por conexion

Cada conexion SOCKS es una maquina de estados (motor `stm`). Estados:

```
HELLO_READ -> HELLO_WRITE -> AUTH_READ -> AUTH_WRITE -> REQUEST_READ
   -> REQUEST_RESOLV (solo si el destino es un FQDN)
   -> REQUEST_CONNECTING -> REQUEST_WRITE -> COPY -> (DONE | ERROR)
```

- HELLO: negociacion de metodo (RFC 1928). Se elige metodo segun la config: si
  hay que autenticar se pide user/pass; si no, se acepta "sin autenticacion".
- AUTH: solo si se nego user/pass (RFC 1929). Se valida contra la base de usuarios
  en memoria.
- REQUEST: se parsea el pedido (CMD, ATYP, direccion, puerto).
- RESOLV: si el destino es un nombre, se dispara la resolucion asincronica.
- CONNECTING: `connect` no bloqueante al origen.
- REQUEST_WRITE: se responde al cliente con el reply code que corresponda.
- COPY: relay bidireccional.
- DONE/ERROR: cierre (se desregistran los dos fds; conteo de referencias).

## 11.3 Resolucion de nombres

Por cada FQDN se lanza un hilo detached que solo hace `getaddrinfo` (y ninguna
otra E/S). Al terminar, deja el resultado en la conexion y despierta al hilo
principal con una **senal** (`pthread_kill`), que interrumpe el `pselect` (que
corre con esa senal en su mascara). Al volver, el selector ejecuta el callback de
"trabajo listo" de esa conexion. Asi el hilo principal nunca toca `getaddrinfo` y
los handlers no lidian con concurrencia. Si el FQDN resuelve a varias direcciones
y una falla al conectar, se prueba con la siguiente (reintento multi-IP).

## 11.4 Relay, buffers, backpressure y half-close

En COPY cada conexion tiene dos buffers acotados, uno por sentido (por defecto
8 KiB). Escritura optimista: al leer un bloque se intenta reenviar en el acto;
solo si el socket destino se llena se guarda el sobrante. Backpressure: si un lado
escribe mas rapido de lo que el otro drena, su buffer se llena y se deja de leer
del rapido. Half-close: se hace `shutdown(SHUT_WR)` por sentido y se cierra cuando
terminaron las dos direcciones.

## 11.5 Reporte de fallas

El `errno` del `connect` se mapea al reply code de RFC 1928: `ECONNREFUSED` -> 5
(connection refused), `ENETUNREACH` -> 3 (network unreachable), `EHOSTUNREACH` ->
4 (host unreachable), `ETIMEDOUT` -> 6 (TTL expired), etc. Un FQDN que no resuelve
da host unreachable; un comando distinto de CONNECT da command not supported.

## 11.6 Disector de credenciales POP3

Con el flag `-d`, para conexiones cuyo destino es el puerto 110, se esnifa el
sentido cliente->origen buscando los comandos `USER`/`PASS` (POP3 es texto, con
lineas terminadas en `\r\n`). Se registra el par usuario/contrasena sin importar
que el servidor lo acepte, ya que se esnifa lo que envia el cliente. El parseo es
por lineas y acotado (buffer de linea de tamano fijo).

## 11.7 Estructura del codigo

`src/` es plano. Modulos de la catedra: `selector` (pselect), `buffer`, `stm`,
`netutils` (ver `docs/catedra/`). Modulos propios: `socks5` y `socks5_parsers`,
`dns`, `mgmt` + `smp.h`, `pop3`, `args`, `config`, `users`, `metrics`, `logger`,
`main` (servidor) y `client` (cliente de monitoreo).

---

# Anexo A: Protocolo de monitoreo SMP/1.0 (estilo RFC)

SMP es un protocolo propio, distinto de SOCKS, que escucha en otro puerto (por
defecto 8080) dentro del mismo proceso y el mismo event loop no bloqueante.
Permite, sin reiniciar el servidor: consultar metricas, administrar usuarios del
proxy y consultar/cambiar configuracion.

## A.1 Decisiones de diseno

- **Transporte: TCP.** Las operaciones son peticion/respuesta y necesitan entrega
  confiable y ordenada (agregar un usuario no puede perderse ni duplicarse). TCP
  da eso sin reimplementarlo; se descarto UDP.
- **Codificacion: binaria, de longitud explicita.** Compacta y univoca al
  parsear, y hace directo el manejo de lecturas parciales (siempre se sabe cuantos
  bytes faltan). La ventaja del texto (debug con netcat) no aplica porque la
  consigna prohibe usar netcat como cliente.
- **Framing por longitud, no por delimitador.** El header tiene tamanos fijos y
  campos de longitud; no se usa `\n` como separador, porque con datos binarios
  cualquier byte (incluido 0x0A) puede aparecer en el contenido.
- **Serializacion agnostica al lenguaje.** Enteros en big-endian (network byte
  order), byte-oriented, sin padding ni alineacion (no se envian structs crudos).
- **Autenticacion:** usuario/contrasena de administrador, independiente de los
  usuarios del proxy, con handshake con el patron `LEN || valor`.

## A.2 Modelo de interaccion

Una conexion SMP consiste en: (1) handshake de autenticacion, (2) 0..N pares
request/response (la conexion se reutiliza), (3) cierre. Todos los enteros
multibyte son big-endian.

## A.3 Handshake de autenticacion

```
Cliente -> Servidor
  +-----+------+----------+------+----------+
  | VER | ULEN |  UNAME   | PLEN |  PASSWD  |
  +-----+------+----------+------+----------+
  |  1  |  1   | 1..255   |  1   | 1..255   |

Servidor -> Cliente
  +-----+--------+
  | VER | STATUS |     STATUS: 0x00 OK | 0x01 credenciales invalidas
  +-----+--------+
```

`VER = 0x01`. Si la autenticacion falla, el servidor responde con `STATUS != 0`
y cierra la conexion.

## A.4 Request / Response

```
Request                          Response
  +-----+-----+---------+          +-----+-----+--------+---------+----------+
  | VER | CMD |  ARGS   |          | VER | CMD | STATUS | DATALEN |   DATA   |
  +-----+-----+---------+          +-----+-----+--------+---------+----------+
  |  1  |  1  | 0..N    |          |  1  |  1  |   1    |    2    | DATALEN  |
```

`CMD` en la respuesta es el eco del pedido. `DATALEN` es un uint16 big-endian.

## A.5 Comandos

| CMD  | Nombre      | ARGS del request            | DATA de la respuesta (si OK)     |
|------|-------------|-----------------------------|----------------------------------|
| 0x00 | METRICS     | (ninguno)                   | 7 contadores uint64 (A.6)        |
| 0x01 | ADD_USER    | `ULEN\|UNAME\|PLEN\|PASSWD` | (vacio)                          |
| 0x02 | DEL_USER    | `ULEN\|UNAME`               | (vacio)                          |
| 0x03 | LIST_USERS  | (ninguno)                   | `COUNT(2) \| [ULEN\|UNAME]*`     |
| 0x04 | GET_CONFIG  | (ninguno)                   | config (A.6)                     |
| 0x05 | SET_CONFIG  | `KEY(1) \| VALUE`           | (vacio)                          |

## A.6 Payloads

METRICS devuelve 7 uint64 big-endian, en orden: conexiones historicas, conexiones
concurrentes, bytes transferidos, conexiones fallidas, usuarios registrados,
bytes cliente->origen, bytes origen->cliente.

GET_CONFIG devuelve `io_buffer_size (uint32)`, `conn_timeout_secs (uint32)`,
`auth_required (uint8)`.

SET_CONFIG recibe `KEY(1) | VALUE`: `0x01` io_buffer_size (uint32), `0x02`
conn_timeout_secs (uint32), `0x03` auth_required (uint8, 0/1).

## A.7 Codigos de estado

`0x00` OK, `0x01` auth requerida, `0x02` comando desconocido, `0x03` argumentos
invalidos, `0x04` usuario ya existe, `0x05` usuario no encontrado, `0x06` limite
de usuarios, `0x07` error interno.

## A.8 Registro de acceso

Por cada pedido SOCKS atendido se emite una linea con timestamp, usuario, comando,
origen (ip:puerto) y destino (host:puerto), y el resultado. Pensado para responder
quien se conecto a que destino y cuando.
