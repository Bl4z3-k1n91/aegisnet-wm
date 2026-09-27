# EVE-NG Topology and Validation

## Physical Links

Every IOS node uses `FastEthernet0/0` for OOB management. Port adapters provide
`FastEthernet1/0` through `FastEthernet4/0`.

| Node | Fa1/0 | Fa2/0 | Fa3/0 | Fa4/0 |
|---|---|---|---|---|
| P1 | PE1 | PE2 | — | — |
| P2 | PE1 | PE2 | — | — |
| PE1 | P1 | P2 | HUB MPLS | BR1 MPLS via netem |
| PE2 | P1 | P2 | BR2 MPLS | DC MPLS |
| INET | HUB | BR1 via netem | BR2 | DC |
| HUB | PE1/MPLS | INET | HUB LAN | — |
| BR1 | PE1/MPLS via netem | INET via netem | BR1 LAN | — |
| BR2 | PE2/MPLS | INET | BR2 LAN | — |
| DC | PE2/MPLS | INET | DC LAN | — |

## Address Plan

| Link | Side A | Side B |
|---|---|---|
| PE1–P1 | PE1 `10.0.0.1/30` | P1 `10.0.0.2/30` |
| PE1–P2 | PE1 `10.0.0.5/30` | P2 `10.0.0.6/30` |
| P1–PE2 | P1 `10.0.0.9/30` | PE2 `10.0.0.10/30` |
| P2–PE2 | P2 `10.0.0.13/30` | PE2 `10.0.0.14/30` |
| HUB MPLS | PE1 `10.100.10.1/30` | HUB `10.100.10.2/30` |
| BR1 MPLS | PE1 `10.100.11.1/30` | BR1 `10.100.11.2/30` |
| BR2 MPLS | PE2 `10.100.12.1/30` | BR2 `10.100.12.2/30` |
| DC MPLS | PE2 `10.100.20.1/30` | DC `10.100.20.2/30` |
| HUB Internet | INET `198.18.10.1/30` | HUB `198.18.10.2/30` |
| BR1 Internet | INET `198.18.11.1/30` | BR1 `198.18.11.2/30` |
| BR2 Internet | INET `198.18.12.1/30` | BR2 `198.18.12.2/30` |
| DC Internet | INET `198.18.20.1/30` | DC `198.18.20.2/30` |

DMVPN MPLS addresses are `172.20.100.1/11/12/20`; Internet DMVPN addresses
are `172.20.200.1/11/12/20` for HUB, BR1, BR2 and DC respectively.

OOB management uses `192.168.58.10` through `.18` for IOS nodes and
`192.168.58.1` for the Windows collector. These static router addresses sit
below VMnet8's DHCP pool (`.128` through `.254`). The stock two-NIC netem appliances are managed
through their EVE consoles; both NICs remain dedicated to the transparent path.

## Routing and Encryption

- P1/P2/PE1/PE2: OSPF area 0 and MPLS LDP.
- PE1/PE2: MP-BGP VPNv4 AS 65000 with VRF `SDWAN-MPLS`.
- Site ASNs: BR1 65101, BR2 65102, HUB 65110, DC 65120.
- INET AS: 64500; it advertises only a default route to each site.
- Service LAN routes exist only in named EIGRP AS 100 over the encrypted overlay.
- HUB is NHS for Tunnel100 and Tunnel200.
- Spokes use NHRP shortcut; HUB uses NHRP redirect.
- MPLS tunnel delay is lower than Internet, so MPLS is the normal routing path.
- BR1 and BR2 use PBR to keep voice/business on MPLS and bulk traffic on
  Internet, with IP SLA tracked fallback.
- Both DMVPN clouds use IKEv2, AES-256, SHA-256, DH14 and IPsec transport mode.

## Telemetry Contract

| Signal | Destination |
|---|---|
| NetFlow v9 | `192.168.58.1:2055/UDP` |
| Syslog | `192.168.58.1:5514/UDP` |
| SNMPv3 | Collector polls router OOB addresses on UDP 161 |
| IP SLA | Five-second probes across both DMVPN clouds |

The router export source is always `FastEthernet0/0`. Site and provider
interfaces have ingress NetFlow enabled.

## Fault Map

| Scenario | Injection |
|---|---|
| Progressive congestion | NETEM-BR1-MPLS: 4 → 2 → 1 Mbps with increasing delay/loss |
| Tunnel degradation | Jitter or loss-burst profile on BR1 MPLS |
| MPLS access failure | Shutdown BR1 Fa1/0; Internet DMVPN remains |
| Core failure | Shutdown P1 Fa2/0; OSPF/LDP reroute through P2 |
| BGP instability | Repeatedly shut/unshut BR2's PE BGP neighbor |
| Policy drift | Change HUB WAN shaper from 5 Mbps to 750 Kbps |

## IOS Acceptance Commands

Provider:

```text
show ip ospf neighbor
show mpls ldp neighbor
show mpls forwarding-table
show bgp vpnv4 unicast all summary
show ip route vrf SDWAN-MPLS
```

Sites:

```text
show ip bgp summary
show dmvpn
show ip nhrp
show crypto ikev2 sa
show crypto ipsec sa
show ip eigrp neighbors
show ip route eigrp
show ip sla statistics
show track
show route-map
show policy-map interface FastEthernet1/0
```

Generate BR1-to-DC traffic, then verify that BR1 and DC show a dynamic NHRP
spoke shortcut rather than sending all traffic through HUB.
