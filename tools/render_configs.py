#!/usr/bin/env python3
"""Render deterministic IOS startup configurations for the EVE-NG lab."""

from __future__ import annotations

import argparse
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "configs" / "routers"
COLLECTOR_IP = "192.168.58.1"

DEFAULT_SECRETS = {
    "LAB_IKEV2_MPLS_PSK": "CHANGEME_MPLS_PSK_2026",
    "LAB_IKEV2_INET_PSK": "CHANGEME_INET_PSK_2026",
    "LAB_ENABLE_SECRET": "CHANGEME_ENABLE_SECRET_2026",
    "LAB_ADMIN_SECRET": "CHANGEME_ADMIN_SECRET_2026",
    "LAB_SNMP_AUTH": "CHANGEME_SNMP_AUTH_2026",
    "LAB_SNMP_PRIV": "CHANGEME_SNMP_PRIV_2026",
}


def ios_local_secret(value: str) -> str:
    """Return a secret accepted by legacy IOS (maximum 25 characters)."""
    return value[:25]

MGMT = {
    "P1": "192.168.58.10",
    "P2": "192.168.58.11",
    "PE1": "192.168.58.12",
    "PE2": "192.168.58.13",
    "INET": "192.168.58.14",
    "BR1": "192.168.58.15",
    "BR2": "192.168.58.16",
    "HUB": "192.168.58.17",
    "DC": "192.168.58.18",
}

LOOPBACK = {
    "P1": "10.255.0.1",
    "P2": "10.255.0.2",
    "PE1": "10.255.0.11",
    "PE2": "10.255.0.12",
    "INET": "10.255.200.1",
    "BR1": "10.255.1.1",
    "BR2": "10.255.2.1",
    "HUB": "10.255.10.1",
    "DC": "10.255.20.1",
}

SITES = {
    "HUB": {
        "asn": 65110,
        "mpls_local": "10.100.10.2",
        "mpls_peer": "10.100.10.1",
        "inet_local": "198.18.10.2",
        "inet_peer": "198.18.10.1",
        "lan": "10.10.10.1",
        "lan_network": "10.10.10.0",
        "t100": "172.20.100.1",
        "t200": "172.20.200.1",
        "hub": True,
    },
    "BR1": {
        "asn": 65101,
        "mpls_local": "10.100.11.2",
        "mpls_peer": "10.100.11.1",
        "inet_local": "198.18.11.2",
        "inet_peer": "198.18.11.1",
        "lan": "10.1.10.1",
        "lan_network": "10.1.10.0",
        "t100": "172.20.100.11",
        "t200": "172.20.200.11",
        "hub": False,
    },
    "BR2": {
        "asn": 65102,
        "mpls_local": "10.100.12.2",
        "mpls_peer": "10.100.12.1",
        "inet_local": "198.18.12.2",
        "inet_peer": "198.18.12.1",
        "lan": "10.2.10.1",
        "lan_network": "10.2.10.0",
        "t100": "172.20.100.12",
        "t200": "172.20.200.12",
        "hub": False,
    },
    "DC": {
        "asn": 65120,
        "mpls_local": "10.100.20.2",
        "mpls_peer": "10.100.20.1",
        "inet_local": "198.18.20.2",
        "inet_peer": "198.18.20.1",
        "lan": "10.20.10.1",
        "lan_network": "10.20.10.0",
        "t100": "172.20.100.20",
        "t200": "172.20.200.20",
        "hub": False,
    },
}


def load_env(path: Path | None) -> dict[str, str]:
    values = dict(DEFAULT_SECRETS)
    if path and path.exists():
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    for key in values:
        values[key] = os.environ.get(key, values[key])
    return values


def block(lines: list[str]) -> str:
    return "\n".join(lines).rstrip() + "\n"


def common(hostname: str, secrets: dict[str, str]) -> list[str]:
    lines = [
        "version 15.2",
        "no service pad",
        "service timestamps debug datetime msec localtime show-timezone",
        "service timestamps log datetime msec localtime show-timezone",
        "service password-encryption",
        f"hostname {hostname}",
        "!",
        "boot-start-marker",
        "boot-end-marker",
        "!",
        f"enable secret 0 {secrets['LAB_ENABLE_SECRET']}",
        f"username noc privilege 15 secret 0 {ios_local_secret(secrets['LAB_ADMIN_SECRET'])}",
        "aaa new-model",
        "aaa authentication login default local",
        "aaa authentication login CONSOLE none",
        "aaa authorization exec default local",
        "!",
        "no ip domain lookup",
        "ip domain name copilot.local",
        "ip cef",
        "ip ssh version 2",
        "!",
        "ip access-list standard MGMT-SOURCES",
        f" permit host {COLLECTOR_IP}",
        "!",
        "interface FastEthernet0/0",
        " description OOB-MANAGEMENT",
        f" ip address {MGMT[hostname]} 255.255.255.0",
        " no ip redirects",
        " no ip proxy-arp",
        " no shutdown",
        "!",
        "ip flow-export source FastEthernet0/0",
        "ip flow-export version 9",
        "ip flow-export template refresh-rate 1",
        f"ip flow-export destination {COLLECTOR_IP} 2055",
        "ip flow-cache timeout active 1",
        "ip flow-cache timeout inactive 15",
        "!",
        "logging buffered 64000 informational",
        "logging trap informational",
        "logging source-interface FastEthernet0/0",
        f"logging host {COLLECTOR_IP} transport udp port 5514",
        "!",
        "snmp-server group NOC v3 priv",
        (
            "snmp-server user copilot NOC v3 auth sha "
            f"{secrets['LAB_SNMP_AUTH']} priv aes 128 {secrets['LAB_SNMP_PRIV']}"
        ),
        f"snmp-server host {COLLECTOR_IP} version 3 priv copilot",
        "snmp-server ifindex persist",
        "!",
        "line con 0",
        " logging synchronous",
        " exec-timeout 0 0",
        " login authentication CONSOLE",
        "line vty 0 4",
        " transport input ssh",
        " login authentication default",
        " access-class MGMT-SOURCES in",
        "!",
    ]
    if hostname == "HUB":
        lines += ["ntp master 3", "!"]
    else:
        lines += [f"ntp server {MGMT['HUB']} prefer", "!"]
    return lines


def interface(
    name: str,
    description: str,
    address: str,
    mask: str,
    *,
    mpls: bool = False,
    vrf: str | None = None,
    flow: bool = True,
    service_policy: str | None = None,
) -> list[str]:
    lines = [f"interface {name}", f" description {description}"]
    if vrf:
        lines.append(f" ip vrf forwarding {vrf}")
    lines += [
        f" ip address {address} {mask}",
        " no ip redirects",
        " no ip proxy-arp",
    ]
    if flow:
        lines.append(" ip flow ingress")
    if mpls:
        lines.append(" mpls ip")
    if service_policy:
        lines.append(f" service-policy output {service_policy}")
    lines += [" no shutdown", "!"]
    return lines


def core_router(hostname: str, secrets: dict[str, str]) -> str:
    if hostname == "P1":
        links = [
            ("FastEthernet1/0", "TO-PE1", "10.0.0.2", "10.0.0.0", "0.0.0.3"),
            ("FastEthernet2/0", "TO-PE2", "10.0.0.9", "10.0.0.8", "0.0.0.3"),
        ]
    else:
        links = [
            ("FastEthernet1/0", "TO-PE1", "10.0.0.6", "10.0.0.4", "0.0.0.3"),
            ("FastEthernet2/0", "TO-PE2", "10.0.0.13", "10.0.0.12", "0.0.0.3"),
        ]
    lines = common(hostname, secrets)
    lines += [
        "mpls label protocol ldp",
        f"mpls ldp router-id Loopback0 force",
        "!",
        "interface Loopback0",
        f" ip address {LOOPBACK[hostname]} 255.255.255.255",
        "!",
    ]
    for name, desc, addr, _, _ in links:
        lines += interface(name, desc, addr, "255.255.255.252", mpls=True)
    lines += [
        "router ospf 10",
        f" router-id {LOOPBACK[hostname]}",
        " passive-interface default",
        " no passive-interface FastEthernet1/0",
        " no passive-interface FastEthernet2/0",
        f" network {LOOPBACK[hostname]} 0.0.0.0 area 0",
    ]
    for _, _, _, network, wildcard in links:
        lines.append(f" network {network} {wildcard} area 0")
    lines += ["!", "end"]
    return block(lines)


def pe_router(hostname: str, secrets: dict[str, str]) -> str:
    if hostname == "PE1":
        core = [
            ("FastEthernet1/0", "TO-P1", "10.0.0.1", "10.0.0.0"),
            ("FastEthernet2/0", "TO-P2", "10.0.0.5", "10.0.0.4"),
        ]
        access = [
            ("FastEthernet3/0", "TO-HUB-MPLS", "10.100.10.1", "10.100.10.2", 65110),
            ("FastEthernet4/0", "TO-BR1-MPLS", "10.100.11.1", "10.100.11.2", 65101),
        ]
        rd = "65000:1"
        peer = LOOPBACK["PE2"]
    else:
        core = [
            ("FastEthernet1/0", "TO-P1", "10.0.0.10", "10.0.0.8"),
            ("FastEthernet2/0", "TO-P2", "10.0.0.14", "10.0.0.12"),
        ]
        access = [
            ("FastEthernet3/0", "TO-BR2-MPLS", "10.100.12.1", "10.100.12.2", 65102),
            ("FastEthernet4/0", "TO-DC-MPLS", "10.100.20.1", "10.100.20.2", 65120),
        ]
        rd = "65000:2"
        peer = LOOPBACK["PE1"]

    lines = common(hostname, secrets)
    lines += [
        "ip vrf SDWAN-MPLS",
        f" rd {rd}",
        " route-target export 65000:100",
        " route-target import 65000:100",
        "!",
        "mpls label protocol ldp",
        "mpls ldp router-id Loopback0 force",
        "!",
        "interface Loopback0",
        f" ip address {LOOPBACK[hostname]} 255.255.255.255",
        "!",
    ]
    for name, desc, addr, _ in core:
        lines += interface(name, desc, addr, "255.255.255.252", mpls=True)
    for name, desc, addr, _, _ in access:
        lines += interface(name, desc, addr, "255.255.255.252", vrf="SDWAN-MPLS")
    lines += [
        "router ospf 10",
        f" router-id {LOOPBACK[hostname]}",
        " passive-interface default",
        " no passive-interface FastEthernet1/0",
        " no passive-interface FastEthernet2/0",
        f" network {LOOPBACK[hostname]} 0.0.0.0 area 0",
    ]
    for _, _, _, network in core:
        lines.append(f" network {network} 0.0.0.3 area 0")
    lines += [
        "!",
        "router bgp 65000",
        " bgp log-neighbor-changes",
        " no bgp default ipv4-unicast",
        f" neighbor {peer} remote-as 65000",
        f" neighbor {peer} update-source Loopback0",
        " !",
        " address-family vpnv4",
        f"  neighbor {peer} activate",
        f"  neighbor {peer} send-community extended",
        " exit-address-family",
        " !",
        " address-family ipv4 vrf SDWAN-MPLS",
        "  redistribute connected",
    ]
    for _, _, _, neighbor, remote_as in access:
        lines += [
            f"  neighbor {neighbor} remote-as {remote_as}",
            f"  neighbor {neighbor} description {hostname}-CE-UNDERLAY",
        ]
    lines += [" exit-address-family", "!", "end"]
    return block(lines)


def internet_router(secrets: dict[str, str]) -> str:
    links = [
        ("FastEthernet1/0", "TO-HUB-INET", "198.18.10.1", "198.18.10.2", 65110),
        ("FastEthernet2/0", "TO-BR1-INET", "198.18.11.1", "198.18.11.2", 65101),
        ("FastEthernet3/0", "TO-BR2-INET", "198.18.12.1", "198.18.12.2", 65102),
        ("FastEthernet4/0", "TO-DC-INET", "198.18.20.1", "198.18.20.2", 65120),
    ]
    lines = common("INET", secrets)
    lines += [
        "ip prefix-list BLOCK-ALL seq 5 deny 0.0.0.0/0 le 32",
        "!",
        "interface Loopback0",
        f" ip address {LOOPBACK['INET']} 255.255.255.255",
        "!",
    ]
    for name, desc, local, _, _ in links:
        lines += interface(name, desc, local, "255.255.255.252")
    lines += [
        "router bgp 64500",
        " bgp log-neighbor-changes",
    ]
    for _, desc, _, neighbor, remote_as in links:
        lines += [
            f" neighbor {neighbor} remote-as {remote_as}",
            f" neighbor {neighbor} description {desc}",
            f" neighbor {neighbor} default-originate",
            f" neighbor {neighbor} prefix-list BLOCK-ALL in",
        ]
    lines += ["!", "end"]
    return block(lines)


def crypto(hostname: str, site: dict[str, object], secrets: dict[str, str]) -> list[str]:
    return [
        "crypto ikev2 proposal COPILOT-IKEV2",
        " encryption aes-cbc-256",
        " integrity sha256",
        " group 14",
        "!",
        "crypto ikev2 policy COPILOT-IKEV2-POLICY",
        " proposal COPILOT-IKEV2",
        "!",
        "crypto ikev2 keyring KR-MPLS",
        " peer DMVPN-MPLS",
        "  address 0.0.0.0 0.0.0.0",
        f"  pre-shared-key local {secrets['LAB_IKEV2_MPLS_PSK']}",
        f"  pre-shared-key remote {secrets['LAB_IKEV2_MPLS_PSK']}",
        "!",
        "crypto ikev2 keyring KR-INET",
        " peer DMVPN-INET",
        "  address 0.0.0.0 0.0.0.0",
        f"  pre-shared-key local {secrets['LAB_IKEV2_INET_PSK']}",
        f"  pre-shared-key remote {secrets['LAB_IKEV2_INET_PSK']}",
        "!",
        "crypto ikev2 profile IKEV2-MPLS",
        " match identity remote address 10.100.0.0 255.255.0.0",
        f" identity local address {site['mpls_local']}",
        " authentication remote pre-share",
        " authentication local pre-share",
        " keyring local KR-MPLS",
        " dpd 10 3 periodic",
        "!",
        "crypto ikev2 profile IKEV2-INET",
        " match identity remote address 198.18.0.0 255.254.0.0",
        f" identity local address {site['inet_local']}",
        " authentication remote pre-share",
        " authentication local pre-share",
        " keyring local KR-INET",
        " dpd 10 3 periodic",
        "!",
        "crypto ipsec transform-set TS-MPLS esp-aes 256 esp-sha256-hmac",
        " mode transport",
        "crypto ipsec transform-set TS-INET esp-aes 256 esp-sha256-hmac",
        " mode transport",
        "!",
        "crypto ipsec profile IPSEC-MPLS",
        " set transform-set TS-MPLS",
        " set ikev2-profile IKEV2-MPLS",
        "crypto ipsec profile IPSEC-INET",
        " set transform-set TS-INET",
        " set ikev2-profile IKEV2-INET",
        "!",
    ]


def qos() -> list[str]:
    return [
        "ip access-list extended BUSINESS-TRAFFIC",
        " permit tcp any any eq 8443",
        " permit tcp any eq 8443 any",
        "!",
        "class-map match-any VOICE",
        " match dscp ef",
        "class-map match-any BUSINESS",
        " match dscp af31",
        " match access-group name BUSINESS-TRAFFIC",
        "!",
        "policy-map CHILD-QOS",
        " class VOICE",
        "  priority percent 20",
        " class BUSINESS",
        "  bandwidth percent 40",
        " class class-default",
        "  fair-queue",
        "policy-map WAN-SHAPER",
        " class class-default",
        "  shape average 5000000",
        "  service-policy CHILD-QOS",
        "!",
    ]


def tunnel(hostname: str, site: dict[str, object], transport: str) -> list[str]:
    is_mpls = transport == "MPLS"
    number = 100 if is_mpls else 200
    t_ip = str(site["t100"] if is_mpls else site["t200"])
    source = "FastEthernet1/0" if is_mpls else "FastEthernet2/0"
    auth = "MPLS100" if is_mpls else "INET200"
    hub_tunnel = "172.20.100.1" if is_mpls else "172.20.200.1"
    hub_nbma = "10.100.10.2" if is_mpls else "198.18.10.2"
    lines = [
        f"interface Tunnel{number}",
        f" description DMVPN-PHASE3-{transport}",
        f" ip address {t_ip} 255.255.255.0",
        " no ip redirects",
        " no ip proxy-arp",
        " ip mtu 1400",
        " ip tcp adjust-mss 1360",
        f" ip nhrp authentication {auth}",
        f" ip nhrp network-id {number}",
    ]
    if site["hub"]:
        lines += [
            " ip nhrp map multicast dynamic",
            " ip nhrp redirect",
        ]
    else:
        lines += [
            f" ip nhrp map {hub_tunnel} {hub_nbma}",
            f" ip nhrp map multicast {hub_nbma}",
            f" ip nhrp nhs {hub_tunnel}",
            " ip nhrp shortcut",
        ]
    lines += [
        " ip flow ingress",
        " qos pre-classify",
        " bandwidth 100000",
        f" delay {1000 if is_mpls else 5000}",
        f" tunnel source {source}",
        " tunnel mode gre multipoint",
        f" tunnel key {number}",
        f" tunnel protection ipsec profile IPSEC-{transport}",
        " no shutdown",
        "!",
    ]
    return lines


def eigrp(hostname: str, site: dict[str, object]) -> list[str]:
    lines = [
        "router eigrp COPILOT",
        " !",
        " address-family ipv4 unicast autonomous-system 100",
        f"  eigrp router-id {LOOPBACK[hostname]}",
        f"  network {site['lan_network']} 0.0.0.255",
        "  network 172.20.100.0 0.0.0.255",
        "  network 172.20.200.0 0.0.0.255",
        "  af-interface default",
        "   passive-interface",
        "  exit-af-interface",
        "  af-interface Tunnel100",
        "   no passive-interface",
    ]
    if site["hub"]:
        lines += ["   no split-horizon", "   no next-hop-self"]
    lines += [
        "  exit-af-interface",
        "  af-interface Tunnel200",
        "   no passive-interface",
    ]
    if site["hub"]:
        lines += ["   no split-horizon", "   no next-hop-self"]
    lines += ["  exit-af-interface", " exit-address-family", "!"]
    return lines


def ip_sla(hostname: str) -> list[str]:
    if hostname in {"BR1", "BR2"}:
        probes = [
            (101, "172.20.100.1", "Tunnel100"),
            (102, "172.20.200.1", "Tunnel200"),
            (111, "172.20.100.20", "Tunnel100"),
            (112, "172.20.200.20", "Tunnel200"),
        ]
    elif hostname == "DC":
        probes = [
            (101, "172.20.100.1", "Tunnel100"),
            (102, "172.20.200.1", "Tunnel200"),
        ]
    else:
        probes = [
            (111, "172.20.100.20", "Tunnel100"),
            (112, "172.20.200.20", "Tunnel200"),
        ]
    lines: list[str] = []
    for number, target, source in probes:
        lines += [
            f"ip sla {number}",
            f" icmp-echo {target} source-interface {source}",
            " timeout 1000",
            " frequency 5",
            f"ip sla schedule {number} life forever start-time now",
            f"track {number} ip sla {number} reachability",
            "!",
        ]
    return lines


def branch_path_policy(hostname: str, site: dict[str, object]) -> list[str]:
    if hostname not in {"BR1", "BR2"}:
        return []
    source = str(site["lan_network"])
    return [
        "ip access-list extended APP-VOICE-DC",
        f" permit udp {source} 0.0.0.255 10.20.10.0 0.0.0.255 dscp ef",
        "ip access-list extended APP-BUSINESS-DC",
        f" permit tcp {source} 0.0.0.255 10.20.10.0 0.0.0.255 eq 5202",
        "ip access-list extended APP-BULK-DC",
        f" permit tcp {source} 0.0.0.255 10.20.10.0 0.0.0.255 eq 5201",
        "!",
        "route-map APP-STEER-DC permit 10",
        " match ip address APP-VOICE-DC",
        " set ip next-hop verify-availability 172.20.100.20 10 track 111",
        " set ip next-hop verify-availability 172.20.200.20 20 track 112",
        "route-map APP-STEER-DC permit 20",
        " match ip address APP-BUSINESS-DC",
        " set ip next-hop verify-availability 172.20.100.20 10 track 111",
        " set ip next-hop verify-availability 172.20.200.20 20 track 112",
        "route-map APP-STEER-DC permit 30",
        " match ip address APP-BULK-DC",
        " set ip next-hop verify-availability 172.20.200.20 10 track 112",
        " set ip next-hop verify-availability 172.20.100.20 20 track 111",
        "route-map APP-STEER-DC permit 100",
        "!",
    ]


def site_router(hostname: str, secrets: dict[str, str]) -> str:
    site = SITES[hostname]
    lines = common(hostname, secrets)
    lines += [
        "ip prefix-list MPLS-NBMA-IN seq 5 permit 10.100.0.0/16 le 30",
        "ip prefix-list DEFAULT-ONLY seq 5 permit 0.0.0.0/0",
        "!",
        "interface Loopback0",
        f" ip address {LOOPBACK[hostname]} 255.255.255.255",
        "!",
    ]
    lines += qos()
    lines += branch_path_policy(hostname, site)
    lines += crypto(hostname, site, secrets)
    lines += interface(
        "FastEthernet1/0",
        "MPLS-TRANSPORT",
        str(site["mpls_local"]),
        "255.255.255.252",
        service_policy="WAN-SHAPER",
    )
    lines += interface(
        "FastEthernet2/0",
        "INTERNET-TRANSPORT",
        str(site["inet_local"]),
        "255.255.255.252",
        service_policy="WAN-SHAPER",
    )
    lines += interface(
        "FastEthernet3/0",
        f"{hostname}-SERVICE-LAN",
        str(site["lan"]),
        "255.255.255.0",
    )
    if hostname in {"BR1", "BR2"}:
        # Insert PBR under the already-rendered LAN interface before the next block.
        insert_at = len(lines) - 2
        lines.insert(insert_at, " ip policy route-map APP-STEER-DC")
    lines += tunnel(hostname, site, "MPLS")
    lines += tunnel(hostname, site, "INET")
    lines += eigrp(hostname, site)
    lines += [
        f"router bgp {site['asn']}",
        " bgp log-neighbor-changes",
        f" neighbor {site['mpls_peer']} remote-as 65000",
        f" neighbor {site['mpls_peer']} description MPLS-PE",
        f" neighbor {site['mpls_peer']} prefix-list MPLS-NBMA-IN in",
        f" neighbor {site['inet_peer']} remote-as 64500",
        f" neighbor {site['inet_peer']} description INTERNET-TRANSIT",
        f" neighbor {site['inet_peer']} prefix-list DEFAULT-ONLY in",
        "!",
    ]
    lines += ip_sla(hostname)
    lines += ["end"]
    return block(lines)


def render_all(secrets: dict[str, str]) -> dict[str, str]:
    return {
        "P1": core_router("P1", secrets),
        "P2": core_router("P2", secrets),
        "PE1": pe_router("PE1", secrets),
        "PE2": pe_router("PE2", secrets),
        "INET": internet_router(secrets),
        "HUB": site_router("HUB", secrets),
        "BR1": site_router("BR1", secrets),
        "BR2": site_router("BR2", secrets),
        "DC": site_router("DC", secrets),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, default=ROOT / ".env")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--allow-placeholders",
        action="store_true",
        help="Render even if CHANGEME secrets remain.",
    )
    args = parser.parse_args()

    secrets = load_env(args.env_file)
    unresolved = [key for key, value in secrets.items() if "CHANGEME" in value]
    if unresolved and not args.allow_placeholders:
        parser.error(
            "replace placeholders in .env or pass --allow-placeholders for a non-deployable preview: "
            + ", ".join(unresolved)
        )

    args.output.mkdir(parents=True, exist_ok=True)
    rendered = render_all(secrets)
    for hostname, config in rendered.items():
        (args.output / f"{hostname}.cfg").write_text(config, encoding="utf-8", newline="\n")
    print(f"Rendered {len(rendered)} router configurations in {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
