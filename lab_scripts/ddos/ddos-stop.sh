#!/bin/sh
PIDFILE=/tmp/aegis-ddos-victim.pid
if [ ! -f "$PIDFILE" ]; then
  echo "[AegisNet] victim listener is not running"
  exit 0
fi
pid=$(cat "$PIDFILE" 2>/dev/null)
kill "$pid" 2>/dev/null || true
rm -f "$PIDFILE"
echo "[AegisNet] victim listener stopped"
