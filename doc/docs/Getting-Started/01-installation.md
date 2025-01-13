---
title: Installation
---

# Installation

## Dependencies
First step is to install dependencies, as follow on ubuntu systems :

```
$ sudo apt install libelf-dev zlib1g-dev
$ sudo apt install llvm clang
```

## Build

To build fastSwan, you simply need to clone last version from github repo and build:

```
git clone --recursive git@github.com:acassen/fastswan.git
cd fastswan
make -j $(nproc)
```

It will build fastSwan and companion eBPF prog in bin/ directory :
```
$ ls bin/
fastswan  xfrm_offload.bpf
```

## Configuration file

fastSwan is configured via a simple configuration file as follow :

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

## Run & VTY

Runing the daemon as follow :
```
$ sudo bin/fastswan --help
fastswan v1.0.0 (2025/01/01)
Copyright (C) 2025 Alexandre Cassen, <acassen@gmail.com>
libbpf v1.6

Usage:
  fastswan
  fastswan -n
  fastswan -f fastswan.conf
  fastswan -d
  fastswan -h
  fastswan -v

Commands:
Either long or short options are allowed.
  fastswan --dont-fork          -n    Dont fork the daemon process.
  fastswan --use-file           -f    Use the specified configuration file.
                                Default is /etc/fastswan/fastswan.conf.
  fastswan --enable-bpf-debug   -b    Enable verbose libbpf log debug.
  fastswan --dump-conf          -d    Dump the configuration data.
  fastswan --log-console        -l    Log message to stderr.
  fastswan --log-detail         -D    Detailed log messages.
  fastswan --log-facility       -S    0-7 Set syslog facility to LOG_LOCAL[0-7]. (default=LOG_DAEMON)
  fastswan --help               -h    Display this short inlined help screen.
  fastswan --version            -v    Display the version number

$ sudo bin/fastswan --dont-fork --log-console --log-detail -f /etc/fastswan/fastswan.conf
```

Operations and live daemon interactions are available via a VTY. This is a standard VTY that networking people are used to:
```
$ telnet localhost 1664
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.

 Welcome to fastSwan VTY

fastSwan> show xdp xfrm offload statistics 
 p0:
   rx_pkts:4 rx_bytes:392
   tx_pkts:4 tx_bytes:392
 p1:
   rx_pkts:4 rx_bytes:392
   tx_pkts:4 tx_bytes:392
fastSwan> 
```
