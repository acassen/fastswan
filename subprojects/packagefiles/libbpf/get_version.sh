#!/bin/bash

# make a symlink so -I bpf will work.
# cannot put symlink in packagefile because it doesn't work on meson < 1.7.0
ln -sf src bpf

# fastswan BPF source includes <uapi/linux/bpf.h>; expose include/uapi
# under src/ so -Isrc resolves the uapi/ prefix.
ln -sf ../include/uapi src/uapi

grep "^LIBBPF_.*VERSION" src/Makefile | grep -v shell | sed 's/[:() ]//g' > version_env
source version_env
echo $LIBBPF_VERSION
