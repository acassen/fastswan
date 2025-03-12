---
title: Routed Network
---

Consider the following topology where 16.0.0.1 wants to reach 48.0.0.1:
<p style="text-align: center"><img src="../../assets/RoutedNetwork.png"></p>
IPsecGW connects multiple network segments. This is a realistic network architecture as
found on large scale telco operators networks. IPsecGW are in charge of interconnecting
trusted networks segments using and relying on a large network infrastructure referred
as "Wild Telco Network" on the picture. This Wild network infrastructure is mostly
built using heterogeneous routing equipements and can run multiple transports and
routings protocols. In the proposed topology, IPsecGW are routing ciphered traffic via
their P0 ports. Lets define 3 types of network segments:

* **Connected Network** : *Net Segment 0* is the connected network between IPSEC-GW-0 and router R1. *Net Segment 1* is the connected network between IPSEC-GW-1 and router R2.

* **Routed Network** : *Net Segment 2* is routed by R1 and advertised to IPSEC-GW-0. *Net Segment 3* is routed by R4 and advertised to IPSEC-GW-1. Most of the time routed networks are advertised using a routing protocol such as BGP. To simplify, we will use simple statics routes in our test scenario here.

* **Quarantine Network** : This segment is used as default captive network, where all
  traffic that doesn't match any IPsec XFRM policies is redirected to. Mainly it is
  a default route on both IPsecGW to this quarantine network.

When NE-0 wants to reach NE-1, its traffic is routed by router R1 to IPSEC-GW-0, then IPSEC-GW-0 XFRM polices will match the traffic and tunnels it to IPSEC-GW-1, which, after tunnel decap, routes the traffic to router R4 to eventually reach NE-1. Symetric traffic routing applies when NE-1 wants to reach NE-0.

This is where IPsec Tunnel mode is critical for ISPs or any network operator running a large network. Simply because *Wild Telco Network* is a collection of routers and other network segments. This network architecture simply relies on pure and simple Layer3 routing.

Both IPsecGW are running Nvidia ConnectX-7 NICs.

---

## Quarantine Network discussion

Default route should be avoided as much as possible for security reasons. A way to
avoid miss-use of it is to rely on it to steer traffic to a specific network segment.
This is typically usefull to redirect untrusted/unauthorized traffic to a captive
portal. When a packet doesnt match any IPsec XFRM policies it will simply be routed to
dedicated segment hosting infrastructure to handle it.

This is also a good way to not expose IPsec secured network segments. If we are not
using a default route and incoming packets are not matching any IPsec XFRM policies,
then an ICMP 'destination unreachable' will be generated. This built-in IP stack
feature can be used and abused as a way to probe secured network segments. Using
a default route all traffic will be handled and operations on Quanratine network can
be both passive by simply logging activities or active by handling traffic. Using
passive approach can provide a good way to detect miss-configuration.


## IPsecGW: network configuration

On both IPsecGW P0 port is used for ciphered traffic and a VLAN is used on P0 for
unciphered traffic. VLAN 502 on port P0 for IPSEC-GW-0 and VLAN 503 on port P0 for
IPSEC-GW-1.

=== "IPSEC-GW-0 configuration"
	```
	sysctl -w net.ipv4.ip_forward=1
	sysctl -w net.ipv6.conf.all.forwarding=1

	ip link set p0 up
	ip address add 123.0.0.1/16 dev p0

	ip link add link p0 name p0.502 type vlan id 502
	ip link set dev p0.502 up
	ip address add 10.0.0.254/24 dev p0.502

	# Connected network
	ip route add 123.2.0.0/16 via 123.0.0.254

	# Routed Networks
	ip route add 16.0.0.0/8 via 10.0.0.1
	ip route add 48.0.0.0/8 via 123.0.0.254

	# Quarantine Network
	ip link set dev dummy0 up
	ip address add 10.10.10.10/32 dev dummy0
	ip route add default via 10.10.10.10
	```

=== "IPSEC-GW-1 configuration"
	```
	sysctl -w net.ipv4.ip_forward=1
	sysctl -w net.ipv6.conf.all.forwarding=1

	ip link set p0 up
	ip address add 123.2.0.1/16 dev p0
	ip address add 123.2.1.2/16 dev p0

	ip link add link p0 name p0.503 type vlan id 503
	ip link set dev p0.503 up
	ip address add 11.0.0.254/24 dev p0.503

	# Connected Network
	ip route add 123.0.0.0/16 via 123.2.0.254

	# Routed Network
	ip route add 48.0.0.0/8 via 11.0.0.1
	ip route add 16.0.0.0/8 via 123.0.0.254

	# Quarantine Network
	ip link set dev dummy0 up
	ip address add 10.10.10.10/32 dev dummy0
	ip route add default via 10.10.10.10
	```

## IPsecGW: strongSwan configuration

IPSEC-GW-0 will use 123.0.0.1 IP Address for its IPsec tunnel endpoint
and IPSEC-GW-1 will use 123.2.1.2 IP Address for its IPsec tunnel endpoint.

For all strongSwan operations, please refer to the strongSwan documentation, but to start SA, simply run :
```
IPSEC-GW-0$ sudo swanctl --load-all
IPSEC-GW-0$ sudo swanctl -i --child tnl-0-1
```

=== "IPSEC-GW-0 swanctl.conf"
	```
	connections {
	  tunnel-0-1 {
		local_addrs  = 123.0.0.1
		remote_addrs = 123.2.1.2
 
		local {
			auth = psk
			id = ipsecgw-0
		}
		remote {
			auth = psk
			id = ipsecgw-1
		}
 
		children {
		  tnl-0-1 {
			local_ts = 16.0.0.0/8
			remote_ts = 48.0.0.0/24
			esp_proposals = aes256gcm128-esn
			mode = tunnel
			policies_fwd_out = yes
			hw_offload = packet
		  }
		}
		version = 2
		mobike = no
		reauth_time = 0
		proposals = aes256-sha256-modp2048
	  }
	}

	secrets {
	  ike-tnl-0-1 {
		id-1 = ipsecgw-0
		id-2 = ipsecgw-1
		secret = 'TopSecret'
	  }
	}
	```

=== "IPSEC-GW-1 swanctl.conf"
	```
	connections {
	  tunnel-0-1 {
		remote_addrs  = 123.0.0.1
		local_addrs = 123.2.1.2

		local {
			auth = psk
			id = ipsecgw-1
		}
		remote {
			auth = psk
			id = ipsecgw-0
		}
 
		children {
		  tnl-0-1 {
			local_ts = 48.0.0.0/24
			remote_ts = 16.0.0.0/8
			esp_proposals = aes256gcm128-esn
			mode = tunnel
			policies_fwd_out = yes
			hw_offload = packet
		  }
		}
		version = 2
		mobike = no
		reauth_time = 0
		proposals = aes256-sha256-modp2048
	  }
	}

	secrets {
	  ike-tnl-0-1 {
		id-1 = ipsecgw-1
		id-2 = ipsecgw-0
		secret = 'TopSecret'
	  }
	}
	```

## Wild Telco Network: Emulating using VRF

In order to emulate **Wild Telco Network**, we can use the following configuration
on a Cisco equipment. This configuration will define a VRF to introduce Layer3
routing :


``` title="Cisco Nexus9000 configuration"
vlan 502-513

vlan 502
  name ipsecgw_trusted_0
vlan 503
  name ipsecgw_trusted_1

vrf context ipsecgw_unciphered
  ip route 16.0.0.0/8 123.0.0.1
  ip route 48.0.0.0/8 123.2.0.1

interface Vlan510
  no shutdown
  vrf member ipsecgw_unciphered
  no ip redirects
  ip address 123.0.0.254/16

interface Vlan512
  no shutdown
  vrf member ipsecgw_unciphered
  no ip redirects
  ip address 123.2.0.254/16

interface Ethernet1/26
  description IPSEC-GW-0-p0
  switchport
  switchport mode trunk
  switchport trunk native vlan 510
  switchport trunk allowed vlan 502,510
  no shutdown

interface Ethernet1/28
  description IPSEC-GW-1-p0
  switchport
  switchport mode trunk
  switchport trunk native vlan 512
  switchport trunk allowed vlan 503,512
  no shutdown
```
