#!/bin/bash

TNLCOUNT=<TNLCNT>

#
#	Networking setup
#
ip link set p0 up
ip link add link p0 name p0.502 type vlan id 502
ip link set dev p0.502 up
ip a a 123.0.0.1/16 dev p0
ip a a 10.0.0.254/24 dev p0.502

ip link set p1 up
ip link add link p1 name p1.504 type vlan id 504
ip link set dev p1.504 up
ip a a 123.1.0.1/16 dev p1
ip a a 10.1.0.254/24 dev p1.504

ip r a 123.2.0.0/16 via 123.0.0.254
ip r a 123.3.0.0/16 via 123.1.0.254

ip r a 16.0.0.0/8 via 10.0.0.1
ip r a 17.0.0.0/8 via 10.1.0.1
ip r a 48.0.0.0/8 via 123.0.0.254
ip r a 49.0.0.0/8 via 123.1.0.254

ip nei add 10.0.0.1 dev p0.502 lladdr 94:6d:ae:87:a1:58
ip nei add 10.1.0.1 dev p1.504 lladdr 94:6d:ae:87:84:00

ip link set dev dummy0 up
ip a a 10.10.10.10/32 dev dummy0
ip r a default via 10.10.10.10


#
#	strongSwan initiate
#
ipsec start
sleep 1
swanctl --load-all

#for i in `seq 1 $TNLCOUNT`; do echo $i; swanctl -i --child tnl-0-$i > /dev/null; swanctl -i --child tnl-1-$i > /dev/null; done

#fastswan
