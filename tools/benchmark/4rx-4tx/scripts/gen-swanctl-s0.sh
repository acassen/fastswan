#!/bin/bash

if [ "$#" -ne 1 ]; then
        echo "  "$(basename $0)" <tnlcount>"
        echo "     tnlcount: NUMBER "
        echo "                                "
        echo " Generate strongSwan configuration files."
        exit
fi

TNLCOUNT=$1
SUBNET_CONNECTED="123"
SUBNET_ROUTED_LOCAL="16"
SUBNET_ROUTED_REMOTE="48"
BITS="32"
OUTPUT="s0-0-$TNLCOUNT.conf"

if [ $TNLCOUNT -gt $((255 * 255)) ]; then
        echo "Maximum tunnel supported : $((255 * 255))"
        exit
fi

cat << HEADER > "$OUTPUT"
connections {
HEADER

for i in `seq 1 $TNLCOUNT`
do
        cat << TNL >> "$OUTPUT"
  tunnel-0-$i {
	local_addrs  = ${SUBNET_CONNECTED}.0.0.1
	remote_addrs = ${SUBNET_CONNECTED}.2.$((i / 255 + 1)).$((i % 255 + 1))
 
	local {
		auth = psk
		id = ipsecgw-0
	}
	remote {
		auth = psk
		id = ipsecgw-$i
	}
 
	children {
	  tnl-0-$i {
		local_ts = ${SUBNET_ROUTED_LOCAL}.0.0.0/8
		remote_ts = ${SUBNET_ROUTED_REMOTE}.$((i / 65536)).$((i / 256 % 256)).$((i % 256))/${BITS}
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
TNL
done

cat << FOOTER >> "$OUTPUT"
}

secrets {
FOOTER

for i in `seq 1 $TNLCOUNT`
do
        cat << SECRET >> "$OUTPUT"
  ike-tnl-0-$i {
	id-1 = ipsecgw-0
	id-2 = ipsecgw-$i
	secret = 'TopSecret'
  }
SECRET
done

echo "}" >> "$OUTPUT"


