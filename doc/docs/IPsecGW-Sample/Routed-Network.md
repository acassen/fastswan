---
title: Routed Network
---

Consider the following topology where 16.0.0.1 wants to reach 48.0.0.1:
<p style="text-align: center"><img src="../../assets/RoutedNetwork.png"></p>
IPsecGW connects multiple network segments. We are using 2 IPsecGW Back-to-Back.
*Net Segment 1* is for ciphered IPsec traffic where others Segments are for clear traffic.
The proposed topology illustrates the most common use-case of IPsec on large carrier networks where multiple
network segments are interconnected by routers. This network architecture is
flexible and can be implemented on any routing equipment. Lets define 2 types of network segments:

* **Connected Network** : *Net Segment 0* is the connected network between IPSEC-GW-0 and router R1. *Net Segment 2* is the connected network between IPSEC-GW-1 and router R2.

* **Routed Network** : *Net Segment 3* is the routed by R1 and advertised to IPSEC-GW-0. *Net Segment 4* is the routed by R2 and advertised to IPSEC-GW-1. Most of the time routed networks are advertised using a routing protocol such as BGP. To simplify, we will use simple statics routes in our test scenario here.

When NE-0 wants to reach NE-1, its traffic is routed by router R1 to IPSEC-GW-0. IPSEC-GW-0 XFRM polices will match the traffic and tunnels it to IPSEC-GW-1, which, after tunnel decap, routes the traffic to router R2 to eventually reach NE-1. Symetric traffic routing applies when NE-1 wants to reach NE-0.

This is where IPsec Tunnel mode is critical for ISPs or any network operator running a large network. Simply because *Net Segment 1* is most of the time a collection of routers and other network segments. This network architecture simply relies on pure and simple Layer3 routing.

On the left, we see a production topology as run in live operator networks. On the right is a LAB topology used to emulate production topology and validate IPSEC-GW operations in '*Routed Network*' scenario. In the LAB topology, the IPSEC-GW configuration and operations are the same as in the production topology but simply run on 2 hosts or VM. The LAB topology can be used as part of a non-regression & validation process and run on a single server hosting multiple NICs (ConnectX-7 here in our example) where each NIC is a VFIO in a dedicated VM.

IPSEC-GW configuration is as simple as possible reflecting exact production configuration. Simulated-NE configuration and complexity are just here to emulate network topology of tested scenario : '*Routed Network*'

---

## LAB Topology: network configuration

To simulate a full routing path within Simulated-NE, we will create 2 network namespaces:

* **network namespace ns1** will emulate *Net Segment 4* and *Net Segment 2*.
* **network namespace ns0** will emulate *Net Segment 3* and *Net Segment 0*.

Since we just have 2 physicals network devices per host (or VM), **network namepace ns1** will be local to the host and will act as a *Routed Network*.

**network namespace ns0** will be connected to CX interface using a bridge interface.

*VETH* interfaces will be used to connect logically network namespaces.

=== "Simulated-NE configuration"
	```
	sysctl -w net.ipv4.ip_forward=1
	sysctl -w net.ipv6.conf.all.forwarding=1

	# network namespace ns1
	ip link set dev p0 up
	ip address add 192.168.101.11/24 dev p0
	ip link add dev veth0 type veth peer name veth1
	ip link set veth0 up
	ip address add 11.0.0.254/24 dev veth0
	ip netns add ns1
	ip link set veth1 netns ns1
	ip netns exec ns1 ip link set dev lo up
	ip -n ns1 a a 11.0.0.1/24 dev veth1
	ip -n ns1 a a 48.0.0.1/8 dev veth1
	ip -n ns1 link set veth1 up
	ip netns exec ns1 ip route add 16.0.0.0/8 via 11.0.0.254
	ip route add 48.0.0.0/8 via 11.0.0.1

	# network namespace ns0
	ip link add br-network type bridge
	ip link add dev veth2 type veth peer name veth3
	ip link set veth2 up
	ip link set p1 master br-network
	ip link set veth2 master br-network
	ip netns add ns0
	ip link set veth3 netns ns0
	ip netns exec ns0 ip link set dev lo up
	ip -n ns0 a a 10.0.0.1/8 dev veth3
	ip -n ns0 a a 16.0.0.1/8 dev veth3
	ip -n ns0 link set veth3 up
	ip netns exec ns0 ip route add 48.0.0.0/8 via 10.0.0.254
	ip link set dev br-network up
	ip link set dev p1 up
	```

=== "IPSEC-GW configuration"
	```
	sysctl -w net.ipv4.ip_forward=1
	sysctl -w net.ipv6.conf.all.forwarding=1
	ip link set dev p0 up
	ip link set dev p1 up
	ip address add 192.168.101.10/24 dev p0
	ip address add 10.0.0.254/24 dev p1
	ip route add 16.0.0.0/8 via 10.0.0.1
	```

## LAB Topology: strongSwan configuration

The IPSEC-GW node is the only node configured in hw_offload mode. Simulated-NE is configured without offload enabled to inspect ingress and egress ESP traffic.  For all strongSwan operations, please refer to the strongSwan documentation, but to start SA, simply run :
```
$ sudo swanctl --load-all
$ sudo swanctl -i --child gw
```

=== "IPSEC-GW swanctl.conf"
	```
	connections {
	  B-TO-B {
		local_addrs  = 192.168.101.10
		remote_addrs = 192.168.101.11
 
		local {
			auth = psk
			id = ipsec-gw
		}
		remote {
			auth = psk
			id = ipsec-enodeb
		}
 
		children {
		  gw {
			local_ts = 16.0.0.0/8
			remote_ts = 48.0.0.0/8
			esp_proposals = aes128gcm128-x25519-esn
			mode = tunnel
			policies_fwd_out = yes
			hw_offload = packet
		  }
		}
		version = 2
		mobike = no
		reauth_time = 0 
		proposals = aes128-sha256-x25519
	  }
	}
 
	secrets {
	  ike-GW {
		id-1 = ipsec-gw
		id-2 = ipsec-enodeb
		secret = 'TopSecret'
	  }
	}
	```

=== "Simulated-NE swanctl.conf"
	```
	connections {
	  B-TO-B {
		local_addrs  = 192.168.101.11
		remote_addrs = 192.168.101.10
 
		local {
			auth = psk
			id = ipsec-enodeb
		}
		remote {
			auth = psk
			id = ipsec-gw
		}
 
		children {
		  gw {
			local_ts = 48.0.0.0/8
			remote_ts = 16.0.0.0/8
			esp_proposals = aes128gcm128-x25519-esn
			mode = tunnel
			policies_fwd_out = yes
		  }
		}
		version = 2
		mobike = no
		reauth_time = 0 
		proposals = aes128-sha256-x25519
	  }
	}
 
	secrets {
	  ike-GW {
		id-1 = ipsec-enodeb
		id-2 = ipsec-gw
		secret = 'TopSecret'
	  }
	}
	```

## Current Linux Kernel routing issue

To validate IPSEC tunnel Packet Offload operations, we send icmp-request from Simulated-NE.
Packet Offload **MUST** be configured on IPSEC-GW node **ONLY**, since IPSEC-GW is the node under test and Simulated-NE is just used for network emulation.
We are generating icmp-request from *network namespace ns0*. Following result is observed:

``` title="ICMP-Request from Simulated-NE 'network namespace ns0'"
simulated-ne:$ ip netns exec ns0 ping -I 16.0.0.1 48.0.0.1
PING 48.0.0.1 (48.0.0.1) from 16.0.0.1 : 56(84) bytes of data.
From 10.0.0.254 icmp_seq=1 Destination Host Unreachable
From 10.0.0.254 icmp_seq=2 Destination Host Unreachable
From 10.0.0.254 icmp_seq=3 Destination Host Unreachable
^C
--- 48.0.0.1 ping statistics ---
5 packets transmitted, 0 received, +3 errors, 100% packet loss, time 4124ms
```

``` title="Neighbour table on IPSEC-GW"
ipsec-gw:$ ip neig
48.0.0.1 dev p0  FAILED
10.0.0.1 dev p1 lladdr 4a:b1:3b:82:17:19 STALE
16.0.0.1 dev p1 lladdr 4a:b1:3b:82:17:19 STALE
192.168.101.11 dev p0 lladdr 94:6d:ae:87:a1:58 STALE
```

## Discussion

IPSEC-GW **MUST** not try to resolv 48.0.0.1 since we are in Tunnel mode and 48.0.0.0/8 is a **Routed Network**.
If we remove Packet Offload from the configuration or use Crypto Offload instead then 48.0.0.1 is not resolved and
forwarding works as expected. So why does Packet Offload cause the Linux kernel's routing operations to end in a Layer2 resolution? The reason is :

Packets that match the output xfrm policy are delivered to the netstack.
In IPsec packet mode for tunnel mode, the HW is responsible for building the
hard header and outer IP header. In such a situation, the inner header may
refer to a network that is not directly reachable by the host, resulting in
a failed neighbor resolution. The packet is then dropped.

There is no such an issue for crypto-offload and no-offload modes since the kernel netstack
is responsible for IP outer header encapsulation at the XFRM output. So skb will travel through
the netsatck with the outer header properly set til xmit netdevice.

## Proposed Linux Kernel patch

Proposed solution is simple : in Packet Offload mode, the HW is responsible for building the
hard header and outer IP header. Additionnaly, xfrm policy defines the netdevice to use for xmit
so we can send packets directly to it.

This solution also provides a performance improvement for transport mode, since
there is no need to perform neighbour resolution if the HW is already configured
with it.

There is an on-going discussion on netdev with proposed solution and current page is proposed as
ref material in order to reproduce the issue by anyone.

As a side note and if you want to test this fix, here is a copy : [xfrm: fix tunnel mode TX datapath in packet offload mode]
  [xfrm: fix tunnel mode TX datapath in packet offload mode]: https://fastswan.org/kernel-patches/0010-xfrm-fix-tunnel-mode-TX-datapath-in-packet-offload-m.patch

