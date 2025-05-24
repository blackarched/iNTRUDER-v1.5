#!/bin/bash

INTERFACE="wlan0"
MON_INTERFACE="wlan0mon"

printf "[%s] Starting monitor mode on %s...\n" "$(date -Iseconds)" "$INTERFACE"
sudo airmon-ng start "$INTERFACE"

if [ $? -eq 0 ]; then
    printf "[%s] Monitor mode enabled on %s\n" "$(date -Iseconds)" "$MON_INTERFACE"
else
    printf "[%s] Failed to enable monitor mode on %s\n" "$(date -Iseconds)" "$INTERFACE" >&2
    exit 1
fi