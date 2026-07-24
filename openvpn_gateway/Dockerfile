FROM kylemanna/openvpn:latest

LABEL org.opencontainers.image.title="SOC Lab OpenVPN Gateway"
LABEL org.opencontainers.image.description="OpenVPN gateway for the segmented NAC/SOC laboratory"

EXPOSE 1194/udp

RUN apk add --no-cache python3

COPY initialize-openvpn.sh /usr/local/bin/initialize-openvpn.sh
COPY create-secure-client.sh /usr/local/bin/create-secure-client.sh
COPY revoke-client.sh /usr/local/bin/revoke-client.sh
COPY start-gateway.sh /usr/local/bin/start-gateway.sh
COPY radius-auth.py /usr/local/bin/radius-auth.py
COPY apply-client-policy.sh /usr/local/bin/apply-client-policy.sh
COPY remove-client-policy.sh /usr/local/bin/remove-client-policy.sh
COPY export-client-profile.sh /usr/local/bin/export-client-profile.sh
RUN sed -i 's/\r$//' /usr/local/bin/initialize-openvpn.sh \
    && sed -i 's/\r$//' /usr/local/bin/create-secure-client.sh \
    && sed -i 's/\r$//' /usr/local/bin/revoke-client.sh \
    && sed -i 's/\r$//' /usr/local/bin/start-gateway.sh \
    && sed -i 's/\r$//' /usr/local/bin/radius-auth.py \
    && sed -i 's/\r$//' /usr/local/bin/apply-client-policy.sh \
    && sed -i 's/\r$//' /usr/local/bin/remove-client-policy.sh \
    && sed -i 's/\r$//' /usr/local/bin/export-client-profile.sh \
    && chmod 755 /usr/local/bin/initialize-openvpn.sh \
    && chmod 755 /usr/local/bin/create-secure-client.sh \
    && chmod 755 /usr/local/bin/revoke-client.sh \
    && chmod 755 /usr/local/bin/start-gateway.sh \
    && chmod 755 /usr/local/bin/radius-auth.py \
    && chmod 755 /usr/local/bin/apply-client-policy.sh \
    && chmod 755 /usr/local/bin/remove-client-policy.sh \
    && chmod 755 /usr/local/bin/export-client-profile.sh

# The base image supplies ovpn_run as its default command. Runtime
# configuration and private keys live in the vpn_data Docker volume.
