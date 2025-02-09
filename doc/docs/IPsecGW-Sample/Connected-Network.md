---
title: Connected Network
---

Consider the following topology where 192.168.201.1 wants to reach 192.168.102.1:
<p style="text-align: center"><img src="../../assets/ConnectedNetwork.png"></p>
IPsecGW connects multiple network segments. We are using 2 IPsecGW Back-to-Back. Net Segment 1 is for ciphered IPsec traffic where two others Segments are for clear traffic. {IPSEC-GW-0, NE-0} and {IPSEC-GW-1, NE-1} are connected to the same network segment, respectively *Net Segment 0* and *Net Segment 1*. This scenario is then refered as '*Connected Network*' since network elements are directly attached.

On the left, we see a production topology as run in live operator networks. On the right is a LAB topology used to emulate production topology and validate IPSEC-GW operations in '*Connected Network*' scenario. In the LAB topology, the IPSEC-GW configuration and operations are the same as in the production topology but simply run on 2 hosts or VM. The LAB topology can be used as part of a non-regression & validation process and run on a single server hosting multiple NICs (ConnectX-7 here in our example) where each NIC is a VFIO in a dedicated VM.

IPSEC-GW configuration is as simple as possible reflecting exact production configuration. Simulated-NE configuration and complexity are just here to emulate network topology of tested scenario : '*Connected Network*'

---

## LAB Topology: network configuration

To simulate a full routing path within Simulated-NE, we create a bridge interface, make the CX interface part of the bridge and create a VETH interface where the first peer (veth0) is part of the same bridge and the second peer (veth1) is linked to a network namespace that is part of the same network as the remote IPSEC-GW.

=== "Simulated-NE configuration"
	```
	ip link set dev p0 up
	ip address add 192.168.101.11/24 dev p0
	ip link add dummy0 type dummy
	ip address add 192.168.201.1/24 dev dummy0
	ip link set dummy0 up
	ip link add br-network type bridge
	ip link add dev veth0 type veth peer name veth1
	ip link set veth0 up
	ip link set p1 master br-network
	ip link set veth0 master br-network
	ip netns add nns
	ip link set veth1 netns nns
	ip netns exec nns ip link set dev lo up
	ip -n nns address add 192.168.102.1/24 dev veth1
	ip -n nns link set veth1 up
	ip address add 192.168.102.100/24 dev br-network
	ip netns exec nns ip route add default via 192.168.102.100
	ip netns exec nns ip route add 192.168.201.0/24 via 192.168.102.10
	ip link set dev br-network up
	ip link set dev p1 up
	```

=== "IPSEC-GW configuration"
	```
	sysctl -w net.ipv4.ip_forward=1
	sysctl -w net.ipv6.conf.all.forwarding=1
	ip link set dev p0 up
	ip address add 192.168.101.10/24 dev p0
	ip link set dev p1 up
	ip address add 192.168.102.10/24 dev p1
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
			local_ts = 192.168.102.0/24
			remote_ts = 192.168.201.0/24
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
			local_ts = 192.168.201.0/24
			remote_ts = 192.168.102.0/24
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


## IPSEC-GW: fastSwan configuration

```
$ cat /etc/fastswan/fastswan.conf
!
! fastSwan configuration saved from vty
!   2025/01/08 12:10:50
!
hostname fastSwan
!
bpf
 xdp-xfrm p0-ingress object-file /etc/fastswan/xfrm_offload.bpf interface p0
 xdp-xfrm p1-ingress object-file /etc/fastswan/xfrm_offload.bpf interface p1
!
load-existing-xfrm-policy
!
line vty
 no login
 listen 127.0.0.1 1664
!
```

## Testing

To validate IPSEC tunnel Packet Offload operations, we send icmp-request from Simulated-NE to local the namespace IP Address. This simulates a global routing path via remote IPSEC-GW. To ensure that the traffic is properly encrypted in an ESP envelope on the Simulated-NE side, we run xdpdump at p0 ingress of Simulated-NE.
The following results **MUST** be observed:

``` title="ICMP-Request from Simulated-NE"
simulated-ne:$ ping -I 192.168.201.1 192.168.102.1
PING 192.168.102.1 (192.168.102.1) from 192.168.201.1 : 56(84) bytes of data.
64 bytes from 192.168.102.1: icmp_seq=1 ttl=63 time=0.819 ms
64 bytes from 192.168.102.1: icmp_seq=2 ttl=63 time=0.715 ms
64 bytes from 192.168.102.1: icmp_seq=3 ttl=63 time=0.612 ms
^C
--- 192.168.102.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2070ms
rtt min/avg/max/mdev = 0.612/0.715/0.819/0.084 ms
```

=== "fastSwan VTY output on IPSEC-GW"
	```
	ipsec-gw:$ telnet localhost 1664
	Trying 127.0.0.1...
	Connected to localhost.
	Escape character is '^]'.

	Welcome to fastSwan VTY

	fastSwan> show xdp xfrm offload policy
	  src 192.168.201.0/24 dst 192.168.102.0/24 dir in dev p0
	  src 192.168.102.0/24 dst 192.168.201.0/24 dir out dev p0
	fastSwan> show xdp xfrm offload statistics
	 p0:
	   rx_pkts:3 rx_bytes:294
	   tx_pkts:3 tx_bytes:294
	 p1:
	   rx_pkts:3 rx_bytes:294
	   tx_pkts:3 tx_bytes:294
	fastSwan> 
	```
=== "XFRM policy output on IPSEC-GW"
	```
	ipsec-gw:$ sudo ip xfrm policy
	src 192.168.102.0/24 dst 192.168.201.0/24 
		dir fwd priority 375424 ptype main 
	src 192.168.102.0/24 dst 192.168.201.0/24 
		dir out priority 375423 ptype main 
		tmpl src 192.168.101.10 dst 192.168.101.11
			proto esp spi 0xc2a00805 reqid 1 mode tunnel
		crypto offload parameters: dev p0 mode packet
	src 192.168.201.0/24 dst 192.168.102.0/24 
		dir fwd priority 375423 ptype main 
		tmpl src 192.168.101.11 dst 192.168.101.10
			proto esp reqid 1 mode tunnel
	src 192.168.201.0/24 dst 192.168.102.0/24 
		dir in priority 375423 ptype main 
		tmpl src 192.168.101.11 dst 192.168.101.10
			proto esp reqid 1 mode tunnel
		crypto offload parameters: dev p0 mode packet
	```



``` title="tcpdump on Simulated-NE"
simulated-ne:$ sudo tcpdump -ni p0 esp or icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on p0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
15:27:00.332414 IP 192.168.101.11 > 192.168.101.10: ESP(spi=0xcf6ed559,seq=0xa), length 120
15:27:00.333186 IP 192.168.101.10 > 192.168.101.11: ESP(spi=0xc7b7b547,seq=0xa), length 120
15:27:00.333186 IP 192.168.102.1 > 192.168.201.1: ICMP echo reply, id 4, seq 1, length 64
15:27:01.378227 IP 192.168.101.11 > 192.168.101.10: ESP(spi=0xcf6ed559,seq=0xb), length 120
15:27:01.378910 IP 192.168.101.10 > 192.168.101.11: ESP(spi=0xc7b7b547,seq=0xb), length 120
15:27:01.378910 IP 192.168.102.1 > 192.168.201.1: ICMP echo reply, id 4, seq 2, length 64
15:27:02.402236 IP 192.168.101.11 > 192.168.101.10: ESP(spi=0xcf6ed559,seq=0xc), length 120
15:27:02.402804 IP 192.168.101.10 > 192.168.101.11: ESP(spi=0xc7b7b547,seq=0xc), length 120
15:27:02.402804 IP 192.168.102.1 > 192.168.201.1: ICMP echo reply, id 4, seq 3, length 64
```

=== "xdpdump on Simulated-NE"
	```
	simulated-ne:$ sudo xdpdump -i p0 --rx-capture=entry,exit -w - | tcpdump -n -r - esp or icmp
	listening on p0, ingress XDP program ID 24 func xdp_dummy, capture mode entry/exit, capture
	size 262144 bytes
	reading from file -, link-type EN10MB (Ethernet), snapshot length 262144
	15:26:59.978424 IP 192.168.101.10 > 192.168.101.11: ESP(spi=0xc7b7b547,seq=0xa), length 120
	15:26:59.978445 IP 192.168.101.10 > 192.168.101.11: ESP(spi=0xc7b7b547,seq=0xa), length 120
	15:27:01.024170 IP 192.168.101.10 > 192.168.101.11: ESP(spi=0xc7b7b547,seq=0xb), length 120
	15:27:01.024191 IP 192.168.101.10 > 192.168.101.11: ESP(spi=0xc7b7b547,seq=0xb), length 120
	15:27:02.048090 IP 192.168.101.10 > 192.168.101.11: ESP(spi=0xc7b7b547,seq=0xc), length 120
	15:27:02.048108 IP 192.168.101.10 > 192.168.101.11: ESP(spi=0xc7b7b547,seq=0xc), length 120
	```

=== "xdp_dummy prog on Simulated-NE"
	xdp_dummy.c source code :
	```
	/*
	 *	ip link set dev p0 xdp obj xdp_dummy.bpf sec xdp
	 */
	#define KBUILD_MODNAME "xdp_dummy"
	#include <uapi/linux/bpf.h>
	#include <bpf_helpers.h>

	SEC("xdp")
	int xdp_dummy(struct xdp_md *ctx)
	{
		return XDP_PASS;
	}

	char _license[] SEC("license") = "GPL";

	```


