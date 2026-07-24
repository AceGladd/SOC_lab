#!/usr/bin/env python3
"""Minimal RADIUS/PAP client used by OpenVPN auth-user-pass-verify."""

import hashlib
import ipaddress
import json
import os
import random
import socket
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path


ACCESS_REQUEST = 1
ACCESS_ACCEPT = 2
ACCESS_REJECT = 3
ATTR_USER_NAME = 1
ATTR_USER_PASSWORD = 2
ATTR_NAS_IP_ADDRESS = 4
ATTR_SERVICE_TYPE = 6
ATTR_CALLING_STATION_ID = 31
ATTR_NAS_IDENTIFIER = 32
ATTR_TUNNEL_PRIVATE_GROUP_ID = 81


def attribute(attr_type: int, value: bytes) -> bytes:
    if len(value) > 253:
        raise ValueError("RADIUS attribute is too long")
    return bytes((attr_type, len(value) + 2)) + value


def encrypt_user_password(password: str, secret: bytes, authenticator: bytes) -> bytes:
    raw = password.encode("utf-8")
    padded_length = max(16, ((len(raw) + 15) // 16) * 16)
    raw = raw.ljust(padded_length, b"\x00")
    encrypted = bytearray()
    previous = authenticator
    for offset in range(0, len(raw), 16):
        digest = hashlib.md5(secret + previous).digest()
        block = bytes(a ^ b for a, b in zip(raw[offset : offset + 16], digest))
        encrypted.extend(block)
        previous = block
    return bytes(encrypted)


def parse_attributes(raw):
    result = {}
    offset = 0
    while offset < len(raw):
        if offset + 2 > len(raw):
            raise ValueError("Truncated RADIUS attribute")
        attr_type, attr_length = raw[offset], raw[offset + 1]
        if attr_length < 2 or offset + attr_length > len(raw):
            raise ValueError("Invalid RADIUS attribute length")
        result.setdefault(attr_type, []).append(raw[offset + 2 : offset + attr_length])
        offset += attr_length
    return result


def safe_identity(value: str) -> str:
    cleaned = "".join(ch for ch in value if ch.isalnum() or ch in "._-")
    return cleaned or "unknown"


def write_event(decision, username, common_name, vlan, detail):
    log_path = Path(os.getenv("OPENVPN_RADIUS_LOG", "/var/log/shared/openvpn-radius.log"))
    log_path.parent.mkdir(parents=True, exist_ok=True)
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "app": "openvpn",
        "event": "radius_authentication",
        "decision": decision,
        "username": username,
        "common_name": common_name,
        "srcip": os.getenv("untrusted_ip", ""),
        "vlan": vlan,
        "detail": detail,
    }
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, separators=(",", ":")) + "\n")


def main() -> int:
    if len(sys.argv) != 2:
        return 1

    credentials = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
    if len(credentials) < 2:
        return 1
    username, password = credentials[0], credentials[1]
    common_name = safe_identity(os.getenv("common_name", "unknown"))

    server = os.getenv("RADIUS_SERVER", "radius_server")
    port = int(os.getenv("RADIUS_AUTH_PORT", "1812"))
    timeout = float(os.getenv("RADIUS_TIMEOUT", "3"))
    secret_text = os.getenv("RADIUS_SHARED_SECRET", "")
    if not secret_text:
        write_event("REJECT", username, common_name, None, "RADIUS shared secret is missing")
        return 1
    secret = secret_text.encode("utf-8")

    request_id = random.SystemRandom().randrange(256)
    request_authenticator = os.urandom(16)
    attrs = b"".join(
        (
            attribute(ATTR_USER_NAME, username.encode("utf-8")),
            attribute(
                ATTR_USER_PASSWORD,
                encrypt_user_password(password, secret, request_authenticator),
            ),
            attribute(
                ATTR_NAS_IP_ADDRESS,
                ipaddress.ip_address(os.getenv("RADIUS_NAS_IP", "10.10.20.250")).packed,
            ),
            attribute(ATTR_NAS_IDENTIFIER, b"vpn_gateway"),
            attribute(ATTR_SERVICE_TYPE, struct.pack("!I", 2)),
            attribute(
                ATTR_CALLING_STATION_ID,
                os.getenv("untrusted_ip", "unknown").encode("utf-8"),
            ),
        )
    )
    packet_length = 20 + len(attrs)
    request = struct.pack("!BBH", ACCESS_REQUEST, request_id, packet_length)
    request += request_authenticator + attrs

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(timeout)
            client.sendto(request, (server, port))
            response, _ = client.recvfrom(4096)
    except (OSError, socket.timeout) as exc:
        write_event("REJECT", username, common_name, None, f"RADIUS unavailable: {exc}")
        return 1

    if len(response) < 20:
        write_event("REJECT", username, common_name, None, "Short RADIUS response")
        return 1
    code, response_id, response_length = struct.unpack("!BBH", response[:4])
    if response_id != request_id or response_length != len(response):
        write_event("REJECT", username, common_name, None, "Invalid RADIUS response header")
        return 1

    response_attributes = response[20:]
    expected_authenticator = hashlib.md5(
        response[:4] + request_authenticator + response_attributes + secret
    ).digest()
    if expected_authenticator != response[4:20]:
        write_event("REJECT", username, common_name, None, "Invalid RADIUS authenticator")
        return 1

    parsed = parse_attributes(response_attributes)
    vlan = None
    if ATTR_TUNNEL_PRIVATE_GROUP_ID in parsed:
        vlan_raw = parsed[ATTR_TUNNEL_PRIVATE_GROUP_ID][0]
        if vlan_raw and vlan_raw[0] <= 31:
            vlan_raw = vlan_raw[1:]
        vlan = vlan_raw.decode("utf-8", errors="replace")

    role_dir = Path("/run/openvpn-roles")
    role_dir.mkdir(parents=True, exist_ok=True)
    role_path = role_dir / f"{common_name}.json"
    if code == ACCESS_ACCEPT and vlan in {"10", "20", "30"}:
        role_path.write_text(
            json.dumps({"username": username, "vlan": vlan}),
            encoding="utf-8",
        )
        write_event("ACCEPT", username, common_name, vlan, "RADIUS Access-Accept")
        return 0

    role_path.unlink(missing_ok=True)
    detail = "RADIUS Access-Reject" if code == ACCESS_REJECT else f"Unexpected RADIUS code {code}"
    write_event("REJECT", username, common_name, vlan, detail)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
