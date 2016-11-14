#!/bin/bash

# return the external interface
_get_external_interface() {
	ip route get 1.1.1.1 | head -1 | cut -d' ' -f5
}

# install ifconfig
install_ifconfig() {
	yum install -y net-tools
}

# permit tunnel on server
permit_tunnel() {
	echo 'PermitTunnel=yes' >> /etc/ssh/sshd_config
	service sshd reload
}

# enable ip_forward
kernel_forwarding() {
	echo 1 > /proc/sys/net/ipv4/ip_forward
}

# firewall rules
firewall_rules() {
	local device
	for device in tun tap; do
		iptables -I FORWARD -i $device+ -j ACCEPT
		iptables -I FORWARD -o $device+ -j ACCEPT
		iptables -I INPUT   -i $device+ -j ACCEPT
	done
	local external_interface=`_get_external_interface`
	iptables -t nat -I POSTROUTING -o $external_interface -j MASQUERADE
}

# main
main() {
	install_ifconfig && \
	permit_tunnel && \
	kernel_forwarding && \
	firewall_rules
}

main "$@"
