#!/bin/bash

# Start tcpdump in background and dump into shared volume
tcpdump -i eth0 -w /app/traffic.pcap &

# Run middlebox script
python -u middlebox.py
