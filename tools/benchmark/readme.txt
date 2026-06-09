# Launch TRex
TRex:~$ ./t-rex-64 -i --stl

# Launch test
TRex:~$ ./trex-run run --output-directory output --name "Flower Hairpin" --multiplier 50gbps --steps 20 --tx-ports=0,1,2,3 --rx-ports=0,1,2,3 profiles/ipsec-cx-multi.py --host 192.168.122.1  

# Generate output graph
TRex:~$ ./trex-run --debug plot --title "fastSwan: 2000 tunnels (Bi-Direction)" --input-directory=output-scn2/ --format png --max-latency=0.001 --max-drop-latency=8 --max-drop-rx=5
