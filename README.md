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

If you're using Fedora 22 or later, you can simply run:
```
# dnf install NetworkManager-ssh-gnome
```
If you're using Fedora 22 or later, with KDE Plasma 5 run:
```
# dnf install NetworkManager-ssh plasma-nm-ssh
```

That will set you up with NetworkManager and the traditional GNOME interface. I am the current maintainer of the package for Fedora.

On older versions of Fedora or CentOS, you can run the following after cloning the repository:
```
$ autoreconf -fvi && ./configure && make rpm
```

Enjoy your new RPM.

### Ubuntu/Debian

On recent Debian/Ubuntu distributions you should be able to install with:
```
# apt-get install network-manager-ssh
```

In case you want to build the package for Debian/Ubuntu, you can use the complimentary packaging this repository provides, but **please do not open bugs about it on this GitHub issue tracker.** The correct thing to do is to use the upstream packages provided with the distribution and open bugs on the distribution issue tracker.

Building a .deb *should* be straight forward with:
```
# apt-get install libnm-glib-dev libnm-glib-vpn-dev libnm-util-dev libnm-dev libnma-dev libgnome-keyring-dev dh-autoreconf libgtk-3-dev sshpass
$ autoreconf -fvi && ./configure && make deb
```

Enjoy your new .deb. (It should show up in the directory you `git clone`d from.)

### Older Distributions

On old distributions with NetworkManager < 0.9.10, such as Ubuntu 14.04, use the 0.9.3 tag:
```
$ git checkout 0.9.3
$ autoreconf -fvi && ./configure && make deb
```
### Arch Linux

A package for Arch is available in the AUR - https://aur.archlinux.org/packages/networkmanager-ssh

## Running

Please edit <i>/etc/dbus-1/system.d/org.freedesktop.NetworkManager.conf</i> and add the line:
```
<allow send_destination="org.freedesktop.NetworkManager.ssh"/>
```

Make sure your target host is known in `~/.ssh/known_hosts`. If it's not there, you should add it manually or by SSHing to it:
```
$ ssh root@TARGET_HOST
The authenticity of host 'TARGET_HOST' can't be established.
ECDSA key fingerprint is SHA256:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.
ECDSA key fingerprint is MD5:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added 'TARGET_HOST' (ECDSA) to the list of known hosts.
```

If all went right, you should have a new VPN of type <i>SSH</i> when creating a new VPN.

### Debugging

When things go wrong and you can't really figure out what's happening, have a look at `/var/log/messages` as you spin up the connection. You should
be able to tell what is going wrong.

## Server side configuration

Even though this is a bit off-topic, I've decided to cover it anyway.

On the server, you'll need to enable in `/etc/ssh/sshd_config`:
```
PermitTunnel=yes
```

Enable kernel packet forwarding:
```
echo 1 > /proc/sys/net/ipv4/ip_forward
```

In terms of firewall configuration, I recommend looking at the "standard" way of editing firewall rules on your distribution.
These however, should work on most GNU/Linux distributions.

Tun devices:
```
iptables -I FORWARD -i tun+ -j ACCEPT
iptables -I FORWARD -o tun+ -j ACCEPT
iptables -I INPUT -i tun+ -j ACCEPT
iptables -t nat -I POSTROUTING -o EXTERNAL_INTERFACE -j MASQUERADE
```

Tap devices:
```
iptables -I FORWARD -i tap+ -j ACCEPT
iptables -I FORWARD -o tap+ -j ACCEPT
iptables -I INPUT -i tap+ -j ACCEPT
iptables -t nat -I POSTROUTING -o EXTERNAL_INTERFACE -j MASQUERADE
```

Please use these firewall rules as a reference only.

Don't forget to replace <b>EXTERNAL_INTERFACE</b> with your WAN interface (eth0, ppp0, etc).

## Port Binding

If you're only after port binding (-L or -R with SSH), you can still use NetworkManager-ssh to perform that, although two limitations still exist:

 * You will still have a full open tunnel to the destination machine
 * NetworkManager allows to open only one VPN connection at a time, so it means one port bind at any given time

So this is how it's done, in the <i>Advanced Dialog</i> tick <b>Extra SSH options</b> and add your line, something in the form of:
```
-L 3306:localhost:3306
```

And to prevent networking from being routed through the VPN, tick <b>Do not replace default route</b>.

That's it, you're done.

## Authenticating with SSH Agent

You will need <i>ssh-agent</i> running before you start NetworkManager-ssh.

How do you know if you have <i>ssh-agent</i> running? Simply run:
```
$ env | grep SSH
SSH_AGENT_PID=16152
SSH_AUTH_SOCK=/tmp/ssh-mGTf3Q1L2oPf/agent.16151
SSH_ASKPASS=/usr/libexec/openssh/gnome-ssh-askpass
```

You should see something similar to that.

NetworkManager-ssh probes for the <i>ssh-agent</i> that is attached to your session and authenticates with its socket.

## Limitations

### Known Hosts

If the destination host is not in your <i>known_hosts</i> file, things will not work, unless you add in the extra options box:
```
-o StrictHostKeyChecking=no
```

## Behind the scenes - how does it actually work??

In order to open a tunnel OpenSSH VPN, all that you have to do is run:
```
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
```

That's actually an edited export file of a working SSH VPN configuration I have from NetworkManager.

This will create a tunnel of 192.168.0.1<->192.168.0.2 on tun100 on both machines. If forwarding is enabled on that SSH server, you'll get pass-through internet easy.

## People I'd like to thank

 * Thomas Young - First user!
 * Whoopie - For nice debian support and testing
 * Oren Held - Invaluable feedback and testing
 * Lubomir Rintel (@lkundrak)- Keeping this repository up to date with upstream NetworkManager, assisting with Fedora packaging
 * Lennart Weller (@lhw) - Debian packaging

## Screenshots

Choosing a connection type:

<img src="https://raw.github.com/danfruehauf/NetworkManager-ssh/master/images/ConnectionType.png">

Main dialog:

<img src="https://raw.github.com/danfruehauf/NetworkManager-ssh/master/images/MainDialog.png">

Advanced dialog:

<img src="https://raw.github.com/danfruehauf/NetworkManager-ssh/master/images/AdvancedDialog.png">

