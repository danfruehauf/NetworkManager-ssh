# NetworkManager-ssh
Happy to introduce SSH VPN integration for NetworkManager.

It is still very much work in progress, so please do open me issues with bugs or future requests.
If there will be enough interest, I'll definitely continue developing it.
I still have enough cleanups I need to perform code wise.

I've forked the work of NetworkManager-ssh from NetworkManager-openvpn.

## Why?
Because we can!

SSH VPN can be used just anywhere!

## So what does it do?
Basically NetworkManager-ssh integrates OpenSSH tunnel capabilities with NetworkManager and provides you with the easiest of all VPNs, as OpenSSH lives on almost any *nix machine today.

## Compiling
### Fedora/CentOS
On Fedora things should be simple, after you clone the repository:

	autoreconf -fvi && ./configure && make rpm

Enjoy your new RPM.

### Ubuntu/Debian
Building a .deb should be straight forward with (Tested on Ubuntu 12.10):

	autoreconf -fvi && ./configure && make deb

Enjoy your new .deb.

## Running
Please edit <i>/etc/dbus-1/system.d/org.freedesktop.NetworkManager.conf</i> and add the line:

	<allow send_destination="org.freedesktop.NetworkManager.ssh"/>

Make sure your target host is known in <i>/root/.ssh/known_hosts</i>

If all went right, you should have a new VPN of type <i>SSH</i> when creating a new VPN.

### Debugging
When things go wrong and you can't really figure out what's happening, you can run the SSH VPN plugin in debug mode.

As <b>root</b> run (on Fedora/RHEL/CentOS):

	/usr/libexec/nm-ssh-service --debug

On Debian/Ubuntu:

	/usr/lib/NetworkManager/nm-ssh-service --debug

Invoke the connection via the NetworkManager icon in your taskbar and you should see the full output of what's going on...

## Server side configuration
Even though this is a bit off-topic, I've decided to cover it anyway.

On the server, you'll need to enable in <i>/etc/ssh/sshd_config</i>:

	PermitTunnel=yes

Enable kernel packet forwarding:

	echo 1 > /proc/sys/net/ipv4/ip_forward

In terms of firewall configuration, I recommend looking at the "standard" way of editing firewall rules on your distribution.
These however, should work on most GNU/Linux distributions.

Tun devices:

	iptables -I FORWARD -i tun+ -j ACCEPT
	iptables -I FORWARD -o tun+ -j ACCEPT
	iptables -I INPUT -i tun+ -j ACCEPT
	iptables -t nat -I POSTROUTING -o EXTERNAL_INTERFACE -j MASQUERADE

Tap devices:

	iptables -I FORWARD -i tap+ -j ACCEPT
	iptables -I FORWARD -o tap+ -j ACCEPT
	iptables -I INPUT -i tap+ -j ACCEPT
	iptables -t nat -I POSTROUTING -o EXTERNAL_INTERFACE -j MASQUERADE

Please use these firewall rules as a reference only.

Don't forget to replace <b>EXTERNAL_INTERFACE</b> with your WAN interface (eth0, ppp0, etc).

## Limitations

### Authentication Types
Right now only <i>ssh-agent</i> authentication is supported, so you need to:

You will need <i>ssh-agent</i> running before you start NetworkManager-ssh.

How do you know if you have <i>ssh-agent</i> running? Simply run:

	$ env | grep SSH
	SSH_AGENT_PID=16152
	SSH_AUTH_SOCK=/tmp/ssh-mGTf3Q1L2oPf/agent.16151
	SSH_ASKPASS=/usr/libexec/openssh/gnome-ssh-askpass

You should see something similar to that.

NetworkManager-ssh probes for the <i>ssh-agent</i> that is attached to your session and authenticates with its socket.

### Known Hosts
If the destination host is not in your <i>known_hosts</i> file, things will not work, unless you add in the extra options box:

	-o StrictHostKeyChecking=no

## Behind the scenes - how does it actually work??
In order to open a tunnel OpenSSH VPN, all that you have to do is run:

	#!/bin/bash
	# This is the WAN IP/hostname of the remote machine
	REMOTE=EDIT_ME

	# Remote username will usually be root, or any other privileged user
	# who can open tun/tap devices on the remote host
	REMOTE_USERNAME=root

	# Remote IP in the tunnel
	REMOTE_IP=192.168.0.1

	# Local IP in the tunnel
	LOCAL_IP=192.168.0.2

	# Netmask to set (on both sides)
	NETMASK=255.255.255.252

	# SSH port to use
	PORT=22

	# MTU for tunnel
	MTU=1500

	# Extra SSH options, these would give us some nice keep alive
	EXTRA_OPTS='-o ServerAliveInterval=10 -o TCPKeepAlive=yes'

	# Remote tunnel device (tun100/tap100)
	REMOTE_DEV=100
	DEV_TYPE=tun
	# TUNNEL_TYPE is 'point-to-point' for tun and 'ethernet' for tap
	TUNNEL_TYPE=point-to-point

	# Local tunnel is calculated depending on what devices are free
	# The following loop iterates from 0 to 255 and finds a free
	# tun/tap device
	for i in `seq 0 255`; do ! ifconfig $DEV_TYPE$i >& /dev/null && LOCAL_DEV=$i && break; done

	ssh -f -v -o Tunnel=$TUNNEL_TYPE -o NumberOfPasswordPrompts=0 $EXTRA_OPTS \
		-w $LOCAL_DEV:$REMOTE_DEV \
		-l $REMOTE_USERNAME -p $PORT $REMOTE \
		"/sbin/ifconfig $DEV_TYPE$REMOTE_DEV $REMOTE_IP netmask $NETMASK pointopoint $LOCAL_IP up" && \
	/sbin/ifconfig $DEV_TYPE$LOCAL_DEV $LOCAL_IP netmask $NETMASK pointopoint $REMOTE_IP up

That's actually an edited export file of a working SSH VPN configuration I have from NetworkManager.

This will create a tunnel of 192.168.0.1<->192.168.0.2 on tun100 on both machines. If forwarding is enabled on that SSH server, you'll get pass-through internet easy.

## People I'd like to thank

 * Thomas Young - First user!
 * Whoopie - For nice debian support and testing
 * Oren Held - Invaluable feedback and testing

## Screenshots

Choosing a connection type:

<img src="https://raw.github.com/danfruehauf/NetworkManager-ssh/master/images/ConnectionType.png">

Main dialog:

<img src="https://raw.github.com/danfruehauf/NetworkManager-ssh/master/images/MainDialog.png">

Advanced dialog:

<img src="https://raw.github.com/danfruehauf/NetworkManager-ssh/master/images/AdvancedDialog.png">

