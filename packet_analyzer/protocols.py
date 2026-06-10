from __future__ import annotations

import logging

# Suppress scapy warnings about missing libpcap provider on Windows
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.layers.inet import TCP, UDP
except ModuleNotFoundError:  # pragma: no cover - depends on local environment
    TCP = UDP = None


TCP_PORT_PROTOCOLS = {
    22: "SSH",
    25: "SMTP",
    80: "HTTP",
    443: "HTTPS",
}

UDP_PORT_PROTOCOLS = {
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
}


def detect_transport(packet) -> str | None:
    if TCP is None or UDP is None:
        return None

    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    return None


def detect_application_protocol(packet) -> str | None:
    if TCP is None or UDP is None:
        return None

    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        for port in (tcp_layer.sport, tcp_layer.dport):
            if port in TCP_PORT_PROTOCOLS:
                return TCP_PORT_PROTOCOLS[port]
        return "TCP"

    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        for port in (udp_layer.sport, udp_layer.dport):
            if port in UDP_PORT_PROTOCOLS:
                return UDP_PORT_PROTOCOLS[port]
        return "UDP"

    return None


class ProtocolDetector:
    """Identifies the most relevant protocol for a packet."""

    def detect(self, packet) -> str | None:
        return detect_application_protocol(packet)
