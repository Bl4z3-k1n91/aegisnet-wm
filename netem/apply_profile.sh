#!/bin/sh
set -eu

PROFILE="${1:-baseline}"
LOG_FILE="/var/log/copilot-netem.log"
DATA_INTERFACES="eth0 eth1"

clear_qdisc() {
  for dev in $DATA_INTERFACES; do
    tc qdisc del dev "$dev" root 2>/dev/null || true
    ip link set "$dev" up
  done
}

apply_tbf_netem() {
  rate="$1"
  delay="$2"
  jitter="$3"
  loss="$4"
  for dev in $DATA_INTERFACES; do
    tc qdisc add dev "$dev" root handle 1: tbf \
      rate "$rate" burst 32kbit latency 400ms
    tc qdisc add dev "$dev" parent 1:1 handle 10: netem \
      delay "$delay" "$jitter" distribution normal loss "$loss"
  done
}

clear_qdisc

case "$PROFILE" in
  baseline)
    ;;
  congestion-1)
    apply_tbf_netem 4mbit 10ms 2ms 0.1%
    ;;
  congestion-2)
    apply_tbf_netem 2mbit 25ms 5ms 0.5%
    ;;
  congestion-3)
    apply_tbf_netem 1mbit 60ms 15ms 2%
    ;;
  jitter)
    apply_tbf_netem 5mbit 35ms 25ms 0.5%
    ;;
  loss-burst)
    apply_tbf_netem 5mbit 10ms 2ms 10%
    ;;
  down)
    for dev in $DATA_INTERFACES; do
      ip link set "$dev" down
    done
    ;;
  *)
    echo "Unknown profile: $PROFILE" >&2
    echo "Use baseline, congestion-1, congestion-2, congestion-3, jitter, loss-burst, or down." >&2
    exit 2
    ;;
esac

printf '%s profile=%s\n' "$(date -Iseconds)" "$PROFILE" >> "$LOG_FILE"
echo "Applied profile: $PROFILE"
for dev in $DATA_INTERFACES; do
  tc -s qdisc show dev "$dev"
done
