#!/bin/bash

IPSEC_GW_0="root@ipsec-gw-0"
IPSEC_GW_1="root@ipsec-gw-1"

if [ "$#" -ne 1 ]; then
        echo "  "$(basename $0)" <tnlcount>"
        echo "     tnlcount: NUMBER "
        echo "                                "
        echo " Setup scenario env."
        exit
fi

TNLCOUNT=$1

if [ $TNLCOUNT -gt $((255 * 255)) ]; then
        echo "Maximum tunnel supported : $((255 * 255)) !!!"
        exit
fi

./scripts/gen-swanctl-s0.sh $TNLCOUNT
./scripts/gen-swanctl-s0-1.sh $TNLCOUNT
./scripts/gen-swanctl-s1.sh $TNLCOUNT
./scripts/gen-swanctl-s1-1.sh $TNLCOUNT

cp ./scripts/ipsecgw0.sh .
cp ./scripts/ipsecgw1.sh .
cp ./scripts/neig.sh .
sed -e "s/<TNLCNT>/$TNLCOUNT/" -i ipsecgw0.sh
sed -e "s/<TNLCNT>/$TNLCOUNT/" -i ipsecgw1.sh
sed -e "s/<TNLCNT>/$TNLCOUNT/" -i neig.sh

scp s0* $IPSEC_GW_0:/usr/local/etc/swanctl/conf.d/ &
scp ipsecgw0.sh $IPSEC_GW_0: &
scp scripts/setup-host.sh $IPSEC_GW_0: &

scp s1* $IPSEC_GW_1:/usr/local/etc/swanctl/conf.d/ &
scp ipsecgw1.sh $IPSEC_GW_1: &
scp scripts/setup-host.sh $IPSEC_GW_1: &
scp neig.sh $IPSEC_GW_1: &

wait

rm ipsecgw0.sh ipsecgw1.sh neig.sh s0-*.conf s1-*.conf

#ssh $IPSEC_GW_1 "sh ipsecgw1.sh"
#ssh $IPSEC_GW_1 "sh neig.sh"
#ssh $IPSEC_GW_0 "sh ipsecgw0.sh"

