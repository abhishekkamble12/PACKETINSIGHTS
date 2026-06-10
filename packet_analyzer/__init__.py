"""Packet analyzer package."""

import logging

# Suppress scapy warnings about missing libpcap provider on Windows
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
