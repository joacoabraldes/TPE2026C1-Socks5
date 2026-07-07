# Pruebas de estrés

Este documento describe cómo medir (1) la **máxima cantidad de conexiones
simultáneas** que soporta el proxy y (2) la **degradación de throughput** bajo
carga.

## Preparación

El proxy usa 2 descriptores por conexión (cliente + origen). Para sostener
≥500 conexiones concurrentes hay que subir el límite de descriptores del
proceso. El servidor ya intenta subir `RLIMIT_NOFILE` a 4096 al iniciar, pero
conviene además subir el límite del shell que lanza las pruebas:

```sh
ulimit -n 8192
```

Levantar el servidor:

```sh
make
bin/socks5d -u test:test          # SOCKS en :1080, mgmt en 127.0.0.1:8080
```

## 1. Máxima cantidad de conexiones simultáneas

Estrategia: hacer un *ramp-up* de la concurrencia hasta que aparezcan fallas.

```sh
for n in 100 250 500 750 1000; do
    echo "== concurrencia $n =="
    scripts/stress.sh "$n" 127.0.0.1:1080 test test http://example.com/
done
```

`scripts/stress.sh` lanza `n` requests en paralelo a través del proxy, cuenta
cuántas terminan con `HTTP 200` y reporta el tiempo total y el throughput
aproximado (req/s).

Mientras corre, se puede observar el pico de concurrencia real desde el otro
lado con el cliente de monitoreo:

```sh
watch -n1 bin/socks5-mgmt metrics
```

La métrica `conexiones concurrentes` muestra el pico sostenido; la máxima
soportada es el mayor `n` para el cual `Fallidas = 0`.

### Límite teórico

Con el selector provisto por la cátedra (basado en `pselect(2)`), el límite
duro es `FD_SETSIZE` (1024) descriptores por proceso, es decir ~500 conexiones
concurrentes (2 fds c/u) más los listeners y el pipe/DNS. Esto satisface el
requerimiento de "al menos 500". Para escalar más habría que reemplazar el
backend del selector por `epoll(7)` (ver Limitaciones en el informe).

## 2. Degradación de throughput

Medir el tiempo por request a medida que crece la concurrencia: si el
throughput (req/s) se mantiene aproximadamente constante y la latencia total
crece de forma lineal con `n`, el servidor escala bien. Un salto abrupto en
fallas o en el tiempo total indica saturación (límite de fds, CPU del hilo
único, o el `backlog` de `listen`).

Para medir throughput de datos (no sólo de conexiones), descargar un archivo
grande a través del proxy y comparar con la descarga directa:

```sh
# directo
curl -s -o /dev/null -w 'directo:  %{speed_download} B/s\n' http://<host>/archivo

# vía proxy
curl -s -o /dev/null -w 'via proxy: %{speed_download} B/s\n' \
     -x socks5h://test:test@127.0.0.1:1080 http://<host>/archivo
```

El tamaño del buffer de E/S por sentido afecta el throughput; se puede ajustar
en caliente y volver a medir:

```sh
bin/socks5-mgmt set-config buffer-size 65536
```

## Métricas relevantes

Durante y después de las pruebas, `bin/socks5-mgmt metrics` reporta:

- `conexiones historicas` — total acumulado (sirve para validar que se
  atendieron todas las de la prueba).
- `conexiones actuales` — concurrencia instantánea.
- `bytes transferidos` — throughput agregado.
- `conexiones fallidas` — fallas por origen inalcanzable/rechazado, etc.
