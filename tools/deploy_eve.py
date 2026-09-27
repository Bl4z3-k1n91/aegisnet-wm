#!/usr/bin/env python3
"""Create the complete topology through the EVE-NG REST API.

The script intentionally does not upload proprietary device images. It discovers
images already installed on the user's EVE-NG instance and uses explicit
overrides when more than one suitable image exists.
"""

from __future__ import annotations

import argparse
import getpass
import http.cookiejar
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TOPOLOGY_PATH = ROOT / "lab" / "topology.json"


class EveError(RuntimeError):
    pass


class EveClient:
    def __init__(self, base_url: str, *, insecure: bool = False) -> None:
        self.base_url = base_url.rstrip("/")
        cookies = http.cookiejar.CookieJar()
        context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cookies),
            urllib.request.HTTPSHandler(context=context),
        )

    def request(
        self,
        method: str,
        endpoint: str,
        payload: dict[str, Any] | None = None,
        *,
        allow_404: bool = False,
    ) -> dict[str, Any] | None:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/api{endpoint}",
            data=data,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        try:
            with self.opener.open(request, timeout=30) as response:
                raw = response.read().decode("utf-8")
                body = json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            if allow_404 and exc.code == 404:
                return None
            raise EveError(f"{method} {endpoint} failed ({exc.code}): {raw}") from exc
        except urllib.error.URLError as exc:
            raise EveError(f"cannot reach EVE-NG at {self.base_url}: {exc.reason}") from exc

        if allow_404 and body.get("status") == "fail" and int(body.get("code", 0)) == 404:
            return None
        if body.get("status") not in {None, "success"}:
            raise EveError(f"{method} {endpoint}: {body.get('message', body)}")
        return body

    def login(
        self,
        username: str,
        password: str,
        *,
        pro: bool = False,
        native_console: bool = False,
    ) -> None:
        payload: dict[str, Any] = {"username": username, "password": password}
        if pro or native_console:
            payload["html5"] = "0"
        self.request("POST", "/auth/login", payload)


def load_topology() -> dict[str, Any]:
    return json.loads(TOPOLOGY_PATH.read_text(encoding="utf-8"))


def api_lab_path(eve_path: str, lab_name: str) -> str:
    segments = [part for part in eve_path.strip("/").split("/") if part]
    segments.append(f"{lab_name}.unl")
    return "/" + "/".join(urllib.parse.quote(part, safe="") for part in segments)


def available_images(client: EveClient, template: str) -> list[str]:
    response = client.request("GET", f"/list/templates/{urllib.parse.quote(template)}")
    try:
        images = response["data"]["options"]["image"]["list"]  # type: ignore[index]
    except (KeyError, TypeError) as exc:
        raise EveError(f"EVE template {template!r} did not return an image list") from exc
    return list(images.keys())


def select_router_image(
    topology: dict[str, Any],
    installed: list[str],
    explicit: str | None,
) -> str:
    if explicit:
        if explicit not in installed:
            raise EveError(
                f"router image {explicit!r} is not installed; available: {', '.join(installed)}"
            )
        return explicit
    for preferred in topology["defaults"]["router_image_preference"]:
        if preferred in installed:
            return preferred
    matching = [
        image
        for image in installed
        if image.startswith("c7200-adventerprisek9-mz.152-4.")
    ]
    if matching:
        return sorted(matching)[-1]
    raise EveError(
        "no compatible c7200 15.2(4)S image found; pass --router-image after installing one"
    )


def select_linux_image(installed: list[str], explicit: str | None) -> str:
    if explicit:
        if explicit not in installed:
            raise EveError(
                f"Linux image {explicit!r} is not installed; available: {', '.join(installed)}"
            )
        return explicit
    preferred_tokens = ("alpine", "tinycore", "linux")
    for token in preferred_tokens:
        matches = [image for image in installed if token in image.lower()]
        if matches:
            return sorted(matches)[-1]
    raise EveError(
        "no lightweight Linux image was detected; pass --linux-image with an installed image"
    )


def node_payload(
    node: dict[str, Any],
    topology: dict[str, Any],
    router_image: str,
    netem_image: str,
    endpoint_image: str,
) -> dict[str, Any]:
    defaults = topology["defaults"]
    if node["kind"] == "router":
        idlepc = defaults["idlepc_by_image"].get(router_image)
        if not idlepc and ".S6" in router_image:
            idlepc = "0x62f224ac"
        elif not idlepc and ".S2" in router_image:
            idlepc = "0x60630d5c"
        idlepc = idlepc or "0x0"
        payload: dict[str, Any] = {
            "type": defaults["router_type"],
            "template": defaults["router_template"],
            "config": "0",
            "delay": 0,
            "icon": "Router.png",
            "image": router_image,
            "name": node["name"],
            "left": node["left"],
            "top": node["top"],
            "ram": str(defaults["router_ram"]),
            "nvram": str(defaults["router_nvram"]),
            "idlepc": idlepc,
        }
        payload.update(defaults["router_slots"])
        return payload
    is_netem = node["name"].startswith("NETEM-")
    linux_image = netem_image if is_netem else endpoint_image
    linux_ram = defaults["netem_ram"] if is_netem else defaults["endpoint_ram"]
    return {
        "type": defaults["linux_type"],
        "template": defaults["linux_template"],
        "config": "0",
        "delay": 0,
        "icon": "Server.png",
        "image": linux_image,
        "name": node["name"],
        "left": node["left"],
        "top": node["top"],
        "ram": str(linux_ram),
        "console": "telnet",
        "cpu": 1,
        "ethernet": int(node.get("ethernet", 1)),
        "uuid": str(uuid.uuid4()),
    }


def deploy(args: argparse.Namespace) -> int:
    topology = load_topology()
    lab = topology["lab"]
    lab_name = args.lab_name or lab["name"]

    if args.dry_run:
        router_image = args.router_image or topology["defaults"]["router_image_preference"][0]
        netem_image = args.netem_image or args.linux_image or "linux-netem"
        endpoint_image = args.endpoint_image or args.linux_image or "linux-tinycore-6.4"
        print(f"DRY RUN: lab={lab_name!r}")
        print(
            f"DRY RUN: router_image={router_image!r}, "
            f"netem_image={netem_image!r}, endpoint_image={endpoint_image!r}"
        )
        print(
            f"DRY RUN: {len(topology['nodes'])} nodes, "
            f"{len(topology['networks'])} networks, "
            f"{len(topology['connections'])} interface attachments"
        )
        for node in topology["nodes"]:
            payload = node_payload(
                node, topology, router_image, netem_image, endpoint_image
            )
            print(f"NODE {node['name']}: {json.dumps(payload, sort_keys=True)}")
        return 0

    password = args.password or os.environ.get("EVE_PASSWORD")
    if not password:
        password = getpass.getpass("EVE-NG password: ")
    client = EveClient(args.eve_url, insecure=args.insecure)
    client.login(args.username, password, pro=args.pro)

    router_images = available_images(client, topology["defaults"]["router_template"])
    linux_images = available_images(client, topology["defaults"]["linux_template"])
    router_image = select_router_image(topology, router_images, args.router_image)
    netem_image = select_linux_image(
        linux_images, args.netem_image or args.linux_image or "linux-netem"
    )
    endpoint_image = select_linux_image(
        linux_images,
        args.endpoint_image or args.linux_image or "linux-tinycore-6.4",
    )
    print(f"Using router image: {router_image}")
    print(f"Using netem image: {netem_image}")
    print(f"Using endpoint image: {endpoint_image}")

    lab_endpoint = api_lab_path(args.eve_path, lab_name)
    existing = client.request("GET", f"/labs{lab_endpoint}", allow_404=True)
    if existing:
        if not args.replace:
            raise EveError(
                f"lab {lab_name!r} already exists; use --replace to delete and rebuild it"
            )
        client.request("DELETE", f"/labs{lab_endpoint}")

    client.request(
        "POST",
        "/labs",
        {
            "path": args.eve_path,
            "name": lab_name,
            "version": lab["version"],
            "author": lab["author"],
            "description": lab["description"],
            "body": (
                "Dual DMVPN Phase 3 clouds over MPLS L3VPN and simulated Internet. "
                "Generated from the Air-Gapped Predictive Copilot workspace."
            ),
        },
    )

    for network in topology["networks"]:
        client.request(
            "POST",
            f"/labs{lab_endpoint}/networks",
            {
                "type": network["type"],
                "name": network["name"],
                "left": network["left"],
                "top": network["top"],
            },
        )
    network_response = client.request("GET", f"/labs{lab_endpoint}/networks")
    network_ids = {
        value["name"]: int(key)
        for key, value in network_response["data"].items()  # type: ignore[index,union-attr]
    }

    for node in topology["nodes"]:
        client.request(
            "POST",
            f"/labs{lab_endpoint}/nodes",
            node_payload(node, topology, router_image, netem_image, endpoint_image),
        )
    node_response = client.request("GET", f"/labs{lab_endpoint}/nodes")
    node_ids = {
        value["name"]: int(key)
        for key, value in node_response["data"].items()  # type: ignore[index,union-attr]
    }
    node_kinds = {node["name"]: node["kind"] for node in topology["nodes"]}

    for connection in topology["connections"]:
        node_id = node_ids[connection["node"]]
        network_id = network_ids[connection["network"]]
        interface_id = int(connection["interface"])
        if node_kinds[connection["node"]] == "router":
            interface_id *= 16
        client.request(
            "PUT",
            f"/labs{lab_endpoint}/nodes/{node_id}/interfaces",
            {str(interface_id): network_id},
        )

    print(
        f"Created {lab_name!r}: {len(node_ids)} nodes, "
        f"{len(network_ids)} networks, {len(topology['connections'])} attachments"
    )
    print("Start the routers, then run tools/push_configs.py after IOS finishes booting.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eve-url", default=os.environ.get("EVE_URL", "http://192.168.58.128"))
    parser.add_argument("--username", default=os.environ.get("EVE_USERNAME", "admin"))
    parser.add_argument("--password", help="Prefer EVE_PASSWORD instead of shell history.")
    parser.add_argument("--eve-path", default="/", help="EVE lab folder, for example /User1")
    parser.add_argument("--lab-name")
    parser.add_argument("--router-image")
    parser.add_argument("--linux-image")
    parser.add_argument("--netem-image")
    parser.add_argument("--endpoint-image")
    parser.add_argument("--pro", action="store_true", help="Use EVE Pro login semantics.")
    parser.add_argument("--insecure", action="store_true", help="Accept a self-signed HTTPS certificate.")
    parser.add_argument(
        "--replace",
        action="store_true",
        help="Delete an existing lab with the same name before deploying.",
    )
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main() -> int:
    try:
        return deploy(build_parser().parse_args())
    except (EveError, KeyError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
