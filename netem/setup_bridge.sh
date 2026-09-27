#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root." >&2
  exit 1
fi

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

if command -v apk >/dev/null 2>&1; then
  apk add --no-cache iproute2 iperf3 openssh bridge-utils
fi

ip link set eth0 up
ip link set eth1 up
ip address flush dev eth0
ip address flush dev eth1
ip link add br0 type bridge 2>/dev/null || true
ip link set br0 type bridge stp_state 0 forward_delay 0
ip link set eth0 master br0
ip link set eth1 master br0
ip link set br0 up

mkdir -p /opt/copilot-netem
cp "$SCRIPT_DIR/apply_profile.sh" /opt/copilot-netem/apply_profile.sh
chmod 700 /opt/copilot-netem/apply_profile.sh
/opt/copilot-netem/apply_profile.sh baseline

ssh-keygen -A
if [ -n "${AUTHORIZED_KEY:-}" ]; then
  install -d -m 700 /root/.ssh
  printf '%s\n' "$AUTHORIZED_KEY" > /root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys
fi
rc-update add sshd default 2>/dev/null || true
rc-service sshd restart 2>/dev/null || /usr/sbin/sshd || true

cat <<'EOF'
Transparent impairment bridge is ready.
Data path: eth0 <-> br0 <-> eth1
Management: EVE console (stock linux-netem has no third management NIC)
Profiles: /opt/copilot-netem/apply_profile.sh <profile>
EOF
