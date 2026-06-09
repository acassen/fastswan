#!/bin/bash

TNLCOUNT=<TNLCNT>

#
#       Networking setup
#
ip link set p0 up
ip link add link p0 name p0.503 type vlan id 503
ip link set dev p0.503 up
ip a a 123.2.0.1/16 dev p0
ip a a 11.0.0.254/24 dev p0.503

ip link set p1 up
ip link add link p1 name p1.505 type vlan id 505
ip link set dev p1.505 up
ip a a 123.3.0.1/16 dev p1
ip a a 11.1.0.254/24 dev p1.505

ip r a 123.0.0.0/16 via 123.2.0.254
ip r a 123.1.0.0/16 via 123.3.0.254

ip r a 16.0.0.0/8 via 123.2.0.254
ip r a 17.0.0.0/8 via 123.3.0.254
ip r a 48.0.0.0/8 via 11.0.0.1
ip r a 49.0.0.0/8 via 11.1.0.1

for i in `seq 1 $TNLCOUNT`;
do
	ip a a 123.2.$((i / 255 + 1)).$((i % 255 + 1))/16 dev p0
	ping -q -w 1 -I 123.2.$((i / 255 + 1)).$((i % 255 + 1)) 123.2.0.254 > /dev/null &
done

for i in `seq 1 $TNLCOUNT`;
do
	ip a a 123.3.$((i / 255 + 1)).$((i % 255 + 1))/16 dev p1
	ping -q -w 1 -I 123.3.$((i / 255 + 1)).$((i % 255 + 1)) 123.3.0.254 > /dev/null &
done

ip neig add 11.0.0.1 dev p0.503 lladdr 94:6d:ae:87:a1:59
ip neig add 11.1.0.1 dev p1.505 lladdr 94:6d:ae:87:84:01

ip link set dev dummy0 up
ip a a 10.10.10.10/32 dev dummy0
ip r a default via 10.10.10.10

#
#       strongSwan initiate
#
ipsec start
sleep 1
swanctl --load-all

#fastswan
