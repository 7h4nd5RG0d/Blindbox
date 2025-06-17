#!/bin/bash

# Start tcpdump in background and dump into shared volume
tcpdump -i eth0 -w /app/traffic.pcap &

# Run your middlebox script (you can redirect output if needed)
python middlebox.py
