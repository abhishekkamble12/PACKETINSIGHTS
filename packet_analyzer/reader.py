from __future__ import annotations

from pathlib import Path

from packet_analyzer.parser import load_pcap


class PacketReader:
    """Loads packets from a PCAP file."""

    def read(self, pcap_path: str | Path):
        return load_pcap(pcap_path)
