#!/bin/sh
# stress.sh — prueba de estrés simple para el proxy SOCKS5.
#
# Mide (1) máxima cantidad de conexiones concurrentes atendidas con éxito y
# (2) degradación de throughput, lanzando N requests en paralelo a través del
# proxy y contando éxitos + tiempo total.
#
# Uso:
#   scripts/stress.sh [CONCURRENCY] [PROXY_HOST:PORT] [USER] [PASS] [URL]
#
# Ejemplo:
#   scripts/stress.sh 500 127.0.0.1:1080 test test http://example.com/
#
# Requiere: curl. Ajustar ulimit -n si CONCURRENCY es alto (ver docs/PRUEBAS.md).

set -u

CONC="${1:-500}"
PROXY="${2:-127.0.0.1:1080}"
USER="${3:-}"
PASS="${4:-}"
URL="${5:-http://example.com/}"
TIMEOUT=30

if [ -n "$USER" ]; then
    AUTH="${USER}:${PASS}@"
else
    AUTH=""
fi
PROXYARG="socks5h://${AUTH}${PROXY}"

RESDIR="$(mktemp -d)"
trap 'rm -rf "$RESDIR"' EXIT

echo "Lanzando $CONC requests concurrentes a $URL vía $PROXY ..."
START=$(date +%s.%N)

i=0
while [ "$i" -lt "$CONC" ]; do
    (
        code=$(curl -s -o /dev/null -w '%{http_code}' \
                    --max-time "$TIMEOUT" -x "$PROXYARG" "$URL" 2>/dev/null)
        echo "$code" > "$RESDIR/$i"
    ) &
    i=$((i + 1))
done
wait

END=$(date +%s.%N)
ELAPSED=$(awk "BEGIN{printf \"%.2f\", $END - $START}")

OK=$(cat "$RESDIR"/* 2>/dev/null | grep -c '^200$')
FAIL=$((CONC - OK))

echo "--------------------------------------------------"
echo "Concurrencia solicitada : $CONC"
echo "Exitosas (HTTP 200)     : $OK"
echo "Fallidas                : $FAIL"
echo "Tiempo total            : ${ELAPSED}s"
if [ "$OK" -gt 0 ]; then
    RPS=$(awk "BEGIN{printf \"%.1f\", $OK / $ELAPSED}")
    echo "Throughput aprox        : ${RPS} req/s"
fi
echo "--------------------------------------------------"
echo "Consultá métricas con:  bin/socks5-mgmt metrics"
