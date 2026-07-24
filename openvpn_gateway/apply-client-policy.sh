#!/bin/sh
set -eu

COMMON_NAME=$(printf '%s' "${common_name:-unknown}" | tr -cd 'A-Za-z0-9._-')
CLIENT_IP="${ifconfig_pool_remote_ip:-}"
ROLE_FILE="/run/openvpn-roles/${COMMON_NAME}.json"
DMZ_SUBNET="${DMZ_SUBNET:-10.10.10.0/24}"
INTERNAL_SUBNET="${INTERNAL_SUBNET:-10.10.20.0/24}"

[ -n "$CLIENT_IP" ] || exit 1
[ -f "$ROLE_FILE" ] || exit 1

VLAN=$(sed -n 's/.*"vlan"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$ROLE_FILE")

case "$VLAN" in
    10)
        iptables -I VPN_ROLE_POLICY -s "$CLIENT_IP" -d "$INTERNAL_SUBNET" -j ACCEPT
        iptables -I VPN_ROLE_POLICY -s "$CLIENT_IP" -d "$DMZ_SUBNET" -j ACCEPT
        ;;
    20)
        iptables -I VPN_ROLE_POLICY -s "$CLIENT_IP" -d "$DMZ_SUBNET" \
            -p tcp --dport 8080 -j ACCEPT
        ;;
    30)
        # Guest has no direct DMZ/internal access in the routed lab.
        ;;
    *)
        exit 1
        ;;
esac

printf '%s\n' "$VLAN" > "/run/openvpn-roles/${CLIENT_IP}.vlan"
exit 0
