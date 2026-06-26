#!/bin/sh
set -eu

INTERVAL_SECONDS="${AGENTLESS_INTERVAL_SECONDS:-1200}"
RUN_ONCE="${AGENTLESS_RUN_ONCE:-false}"

case "$INTERVAL_SECONDS" in
  ''|*[!0-9]*)
    echo "[agentless-worker] AGENTLESS_INTERVAL_SECONDS invalido: $INTERVAL_SECONDS" >&2
    exit 2
    ;;
esac

while true; do
  echo "[agentless-worker] Iniciando ciclo: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  python save_agentless_txt.py
  EXIT_CODE=$?
  echo "[agentless-worker] Ciclo finalizado com codigo: $EXIT_CODE"

  if [ "$RUN_ONCE" = "true" ]; then
    exit "$EXIT_CODE"
  fi

  echo "[agentless-worker] Aguardando ${INTERVAL_SECONDS}s para proximo ciclo"
  sleep "$INTERVAL_SECONDS"
done
