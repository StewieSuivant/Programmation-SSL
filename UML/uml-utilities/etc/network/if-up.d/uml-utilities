#!/bin/sh

test -n "${IF_UML_PROXY_ARP}" || exit 0
test -n "${IF_UML_PROXY_ETHER}" || exit 0

sysctl -w net/ipv4/conf/"${IFACE}"/proxy_arp=1

for i in ${IF_UML_PROXY_ARP};
do
  route add -host "$i" dev "${IFACE}"
  arp -Ds "$i" "${IF_UML_PROXY_ETHER}" pub
done
