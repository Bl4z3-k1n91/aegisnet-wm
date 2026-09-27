#!/bin/sh
set -eu

CIDR="${1:?usage: setup_endpoint.sh <ip/cidr> <gateway> [server|client]}"
GATEWAY="${2:?usage: setup_endpoint.sh <ip/cidr> <gateway> [server|client]}"
ROLE="${3:-client}"

if command -v apk >/dev/null 2>&1; then
  apk add --no-cache iproute2 iperf3 curl openssh
fi

ip link set eth0 up
ip address flush dev eth0
ip address add "$CIDR" dev eth0
ip route replace default via "$GATEWAY"

if [ "$ROLE" = "server" ]; then
  if command -v iperf3 >/dev/null 2>&1; then
    pkill iperf3 2>/dev/null || true
    iperf3 -s -p 5201 -D
    iperf3 -s -p 5202 -D
    iperf3 -s -p 5203 -D
  else
    echo "iperf3 is not installed; IP connectivity is configured." >&2
  fi
fi

if command -v ssh-keygen >/dev/null 2>&1; then
  ssh-keygen -A
fi
if [ -n "${AUTHORIZED_KEY:-}" ] && command -v sshd >/dev/null 2>&1; then
  install -d -m 700 /root/.ssh
  printf '%s\n' "$AUTHORIZED_KEY" > /root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys
fi
if command -v rc-update >/dev/null 2>&1; then
  rc-update add sshd default 2>/dev/null || true
  rc-service sshd restart 2>/dev/null || /usr/sbin/sshd || true
elif command -v sshd >/dev/null 2>&1; then
  /usr/sbin/sshd || true
fi

# TinyCore persistence. Alpine and other images keep their own network state.
if [ -f /opt/bootlocal.sh ] && command -v filetool.sh >/dev/null 2>&1; then
  sed -i '/COPILOT_ENDPOINT/d' /opt/bootlocal.sh
  printf '%s\n' \
    "ip link set eth0 up; ip address flush dev eth0; ip address add $CIDR dev eth0; ip route replace default via $GATEWAY # COPILOT_ENDPOINT" \
    >> /opt/bootlocal.sh
  filetool.sh -b
fi

echo "Endpoint configured: $CIDR via $GATEWAY role=$ROLE"
