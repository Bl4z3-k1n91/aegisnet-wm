#!/bin/sh
PORT=9993
PIDFILE=/tmp/aegis-ddos-victim.pid
if [ -f "$PIDFILE" ]; then
  oldpid=$(cat "$PIDFILE" 2>/dev/null)
  kill "$oldpid" 2>/dev/null || true
  rm -f "$PIDFILE"
fi
(while true; do nc -u -l -p $PORT >/dev/null 2>&1; done) >/tmp/aegis-ddos-victim.log 2>&1 &
echo $! > "$PIDFILE"
echo "[AegisNet] APP-DC UDP victim listening on port $PORT"
echo "[AegisNet] pid $(cat $PIDFILE)"
echo "[AegisNet] stop: kill $(cat $PIDFILE)"
