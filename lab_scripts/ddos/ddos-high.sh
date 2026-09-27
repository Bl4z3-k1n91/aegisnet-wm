#!/bin/sh
TARGET=10.20.10.10
PORT=9993
BURSTS=10
KIB=64
echo "[AegisNet] bounded DDoS HIGH source -> $TARGET:$PORT"
i=1
while [ "$i" -le "$BURSTS" ]; do
  dd if=/dev/zero bs=1024 count=$KIB 2>/dev/null | nc -u -w 1 $TARGET $PORT >/dev/null 2>&1
  echo "[AegisNet] burst $i/$BURSTS"
  i=$((i+1))
  sleep 1
done
echo "[AegisNet] HIGH source complete"
