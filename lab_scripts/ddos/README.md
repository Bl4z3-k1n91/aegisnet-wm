# AegisNet-WM bounded DDoS lab

Fixed victim: APP-DC 10.20.10.10 UDP/9993

Roles:
- APP-DC: ddos-victim.sh / ddos-stop.sh
- CLIENT-BR1: ddos-low.sh, ddos-medium.sh, ddos-high.sh
- CLIENT-BR2: ddos-medium.sh, ddos-high.sh
- SERVICE-HUB: ddos-high.sh

Severity demos:
- LOW: victim + CLIENT-BR1 ddos-low.sh
- MEDIUM: victim + CLIENT-BR1 and CLIENT-BR2 ddos-medium.sh together
- HIGH: victim + CLIENT-BR1, CLIENT-BR2 and SERVICE-HUB ddos-high.sh together

All source scripts are bounded and terminate automatically.
