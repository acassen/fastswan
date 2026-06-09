#!/usr/bin/env bash

# Inspect current values
mlxconfig -d 0000:31:00.0 -e q
mlxconfig -d 0000:31:00.1 -e q

# Move hairpin data buffers into HCA SRAM
mlxconfig -d 0000:31:00.0 set HAIRPIN_DATA_BUFFER_LOCK=True
mlxconfig -d 0000:31:00.1 set HAIRPIN_DATA_BUFFER_LOCK=True

# Enable the flex parser profile needed by the IPsec accel path
mlxconfig -d 0000:31:00.0 set FLEX_PARSER_PROFILE_ENABLE=3
mlxconfig -d 0000:31:00.1 set FLEX_PARSER_PROFILE_ENABLE=3

# Apply the new config without a full reboot
mlxfwreset -d 0000:31:00.0 -y reset
mlxfwreset -d 0000:31:00.1 -y reset
