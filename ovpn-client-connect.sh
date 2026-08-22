#!/bin/bash
# OpenVPN client-connect: push a static tunnel IP from /etc/ppp/chap-secrets.
# Mapping (same last octet as L2TP so SAS NAS is predictable):
#   chap 10.10.30.x  -> 10.10.30.x
#   chap 10.255.10.x -> 10.10.30.x
#   any other a.b.c.x -> 10.10.30.x
# Skips .0/.1/.255 (server / network / broadcast).
# $1 = temp client-config path written by OpenVPN.
# username / common_name come from the OpenVPN environment.

CONF="${1:-}"
u="${username:-${common_name:-}}"
[ -z "$CONF" ] || [ -z "$u" ] && exit 0
CHAP="/etc/ppp/chap-secrets"
ip=$(awk -v u="$u" '$1==u {print $4; exit}' "$CHAP")
[ -z "$ip" ] && exit 0
last="${ip##*.}"
case "$last" in
  ''|*[!0-9]*) exit 0 ;;
esac
if [ "$last" -le 1 ] || [ "$last" -ge 255 ]; then
  exit 0
fi
echo "ifconfig-push 10.10.30.${last} 255.255.255.0" > "$CONF"
exit 0
