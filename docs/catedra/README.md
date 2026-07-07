# Módulos provistos por la cátedra

Estos `*.patch` son los archivos publicados por la cátedra de Protocolos de
Comunicación (ITBA) y usados en este trabajo. Se conservan acá para
**trazabilidad y atribución**; el código ya está aplicado dentro de `src/`.

| Patch | Módulo | Ubicación aplicada |
|-------|--------|--------------------|
| `0001-test.h-*.patch`         | helpers de testing        | `src/tests.h` |
| `0003-buffer.c-*.patch`       | buffer de E/S             | `src/buffer.{c,h}` |
| `0004-netutils.c-*.patch`     | utilidades de red         | `src/netutils.{c,h}` |
| `0005-parser.c-*.patch`       | motor de parsers          | `src/parser.{c,h}` |
| `0006-parser_utils.c-*.patch` | factory de parsers        | `src/parser_utils.{c,h}` |
| `0007-selector.c-*.patch`     | multiplexor de E/S (pselect) | `src/selector.{c,h}` |
| `0008-stm.c-*.patch`          | máquina de estados        | `src/stm.{c,h}` |

## Modificaciones mínimas sobre los archivos de la cátedra

Para compilar sin warnings con `-Wall -Wextra -pedantic` y linkear con el
default `-fno-common` de GCC moderno, se aplicaron cambios menores:

- `src/stm.h`: se cambió un `struct selector_key *key;` (variable global suelta
  que causaba *multiple definition* con `-fno-common`) por la forward
  declaration `struct selector_key;`.
- `src/selector.c`: se agregó `(void)signal;` en `wake_handler` (parámetro no
  usado, `-Wextra`) y se cambió `#include <sys/signal.h>` por `<signal.h>`.
- `src/buffer.h`: se agregó `#include <stdint.h>` (usa `uint8_t`).
- `src/netutils.c`: fallback `#ifndef MSG_NOSIGNAL` para portabilidad.

## Aplicar los patches desde cero (si hiciera falta)

```sh
git apply docs/catedra/0001-*.patch docs/catedra/0003-*.patch \
          docs/catedra/0004-*.patch docs/catedra/0005-*.patch \
          docs/catedra/0006-*.patch docs/catedra/0007-*.patch \
          docs/catedra/0008-*.patch
```
