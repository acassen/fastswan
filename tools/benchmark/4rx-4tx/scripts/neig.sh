#!/bin/bash

TNLCOUNT=<TNLCNT>

for i in `seq 1 $TNLCOUNT`;
do
	echo $i
	ping -q -w 1 -I 123.2.$((i / 255 + 1)).$((i % 255 + 1)) 123.2.0.254 > /dev/null &
	sleep .1
	ping -q -w 1 -I 123.3.$((i / 255 + 1)).$((i % 255 + 1)) 123.3.0.254 > /dev/null &
done
