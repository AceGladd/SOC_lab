#!/bin/sh
set -eu

COMMON_NAME=$(printf '%s' "${common_name:-unknown}" | tr -cd 'A-Za-z0-9._-')
CLIENT_IP="${ifconfig_pool_remote_ip:-}"
DMZ_SUBNET="${DMZ_SUBNET:-10.10.10.0/24}"
INTERNAL_SUBNET="${INTERNAL_SUBNET:-10.10.20.0/24}"
VLAN_FILE="/run/openvpn-roles/${CLIENT_IP}.vlan"

[ -n "$CLIENT_IP" ] || exit 0
VLAN=$(cat "$VLAN_FILE" 2>/dev/null || true)

case "$VLAN" in
    10)
        while iptables -D VPN_ROLE_POLICY -s "$CLIENT_IP" -d "$INTERNAL_SUBNET" -j ACCEPT 2>/dev/null; do :; done
        while iptables -D VPN_ROLE_POLICY -s "$CLIENT_IP" -d "$DMZ_SUBNET" -j ACCEPT 2>/dev/null; do :; done
        ;;
    20)
        while iptables -D VPN_ROLE_POLICY -s "$CLIENT_IP" -d "$DMZ_SUBNET" \
            -p tcp --dport 8080 -j ACCEPT 2>/dev/null; do :; done
        ;;
esac

rm -f "$VLAN_FILE" "/run/openvpn-roles/${COMMON_NAME}.json"
exit 0
