# TPE Protocolos de Comunicación 2026/1 — Proxy SOCKS5

Servidor proxy **SOCKS5** (RFC1928 / RFC1929) no bloqueante y de un solo hilo,
con un **protocolo propio de monitoreo y configuración (SMP)** y su cliente de
terminal.

## Ubicación de los materiales

| Material | Ruta |
|----------|------|
| Consigna del TP | `docs/Consigna TPE 2026C1 - Socks5.pdf` |
| Documento de diseño (arquitectura + protocolo SMP estilo RFC) | `docs/DISENO.md` |
| Pruebas de estrés (metodología + script) | `docs/PRUEBAS.md` |
| Código fuente | `src/` |
| Módulos provistos por la cátedra (patches originales + atribución) | `docs/catedra/` |
| Build | `Makefile` |

Los módulos de la cátedra (selector, buffer, stm, netutils, parser) ya están
aplicados dentro de `src/`. Los `*.patch` originales y las modificaciones
mínimas que se les hicieron están documentados en `docs/catedra/README.md`.

## Compilación

Requiere `gcc`/`cc` con soporte C11 y `make` (entorno POSIX/Linux).

```sh
make            # compila servidor y cliente
make server     # sólo el servidor
make client     # sólo el cliente de monitoreo
make clean
```

Se compila con `-std=c11 -Wall -Wextra -pedantic` sin warnings.

## Artefactos generados

| Artefacto | Descripción |
|-----------|-------------|
| `bin/socks5d` | servidor proxy SOCKS5 + servicio de management |
| `bin/socks5-mgmt` | cliente de terminal del protocolo de monitoreo |
| `obj/` | objetos intermedios |

## Ejecución del servidor: `socks5d`

```sh
bin/socks5d [OPCIONES]

  -h                ayuda
  -v                versión
  -l <addr>         dirección de escucha SOCKS (default: todas las interfaces)
  -p <puerto>       puerto SOCKS (default: 1080)
  -L <addr>         dirección del management (default: 127.0.0.1)
  -P <puerto>       puerto del management (default: 8080)
  -u <user:pass>    agrega un usuario del proxy (repetible, hasta 64)
  -a <user:pass>    credenciales de admin del management (default: admin:admin)
  -N                exige autenticación user/pass (deshabilita NO_AUTH)
```

Comportamiento de autenticación: si se configura al menos un usuario (`-u`) o se
pasa `-N`, el proxy exige autenticación user/pass. Si no, admite el método
NO_AUTH (proxy abierto). Esto también se puede cambiar en caliente por SMP.

Ejemplos:

```sh
# proxy con un usuario, en puertos por defecto (SOCKS 1080, mgmt 8080)
bin/socks5d -u pablito:pass1234

# proxy abierto (sin auth) escuchando SOCKS en 0.0.0.0:1080
bin/socks5d

# admin de management personalizado y puerto de mgmt 9090
bin/socks5d -u ana:secreta -a root:toor -P 9090
```

Soporta destinos **IPv4, IPv6 y FQDN** (resueltos en un hilo de DNS aparte),
con reintento sobre múltiples direcciones y reporte de fallas usando todos los
reply codes del protocolo. El registro de acceso se emite por `stdout`.

## Ejecución del cliente de monitoreo: `socks5-mgmt`

```sh
bin/socks5-mgmt [-L host] [-P puerto] [-u admin] [-w pass] <subcomando> [args]

  metrics
  add-user <nombre> <password>
  del-user <nombre>
  list-users
  get-config
  set-config <buffer-size|timeout|auth-required> <valor>
```

Ejemplos:

```sh
bin/socks5-mgmt metrics
bin/socks5-mgmt add-user pablito pass1234
bin/socks5-mgmt list-users
bin/socks5-mgmt set-config buffer-size 16384
bin/socks5-mgmt -u root -w toor -P 9090 del-user pablito
```

El protocolo SMP es **binario** y está documentado en `docs/DISENO.md`. No se
admite usar `netcat` como cliente.

## Prueba rápida

```sh
bin/socks5d -u test:test &
curl -x socks5h://test:test@127.0.0.1:1080 http://example.com/
bin/socks5-mgmt metrics
kill %1     # SIGTERM: apagado controlado
```

## Graceful shutdown

`SIGTERM`/`SIGINT` inician un apagado controlado: el servidor deja de aceptar
conexiones nuevas y espera a que terminen las existentes. Una **segunda** señal
fuerza el apagado inmediato.

## Pruebas de estrés

Ver `docs/PRUEBAS.md` (incluye `scripts/stress.sh`).
