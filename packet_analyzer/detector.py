from __future__ import annotations
import time


class ThreatDetector:
    """Runs rule-based logic over captured packets and flows to detect security alerts."""

    def __init__(
        self,
        port_scan_threshold: int = 3,
        dns_flood_threshold: int = 3,
        high_volume_bytes: int = 10000,
    ):
        # Low default thresholds are selected to allow detection on small captures/sample PCAPs
        self.port_scan_threshold = port_scan_threshold
        self.dns_flood_threshold = dns_flood_threshold
        self.high_volume_bytes = high_volume_bytes

    def detect(self, flows: list[dict[str, any]]) -> list[dict[str, any]]:
        """
        Analyzes a list of summarized flow records to identify potential threats.
        Returns a list of alert dictionaries.
        """
        alerts = []
        src_dst_ports: dict[str, set[int]] = {}
        src_dns_count: dict[str, int] = {}

        for flow in flows:
            src_ip = flow["src_ip"]
            dst_ip = flow["dst_ip"]
            dst_port = flow["dst_port"]
            protocol = flow["protocol"]

            # Port Scan Detection: track unique destination ports contacted by the same source IP
            if src_ip and dst_port is not None:
                src_dst_ports.setdefault(src_ip, set()).add(dst_port)

            # High-Volume Flow Detection
            if flow["byte_count"] > self.high_volume_bytes:
                alerts.append(
                    {
                        "timestamp": flow["start_time"],
                        "rule_name": "High Volume Flow",
                        "severity": "Medium",
                        "description": (
                            f"Flow {src_ip}:{flow['src_port']} -> {dst_ip}:{dst_port} ({protocol}) "
                            f"transmitted {flow['byte_count']} bytes."
                        ),
                        "src_ip": src_ip,
                        "flow_key": flow["flow_key"],
                    }
                )

            # DNS Flood Detection counter: count DNS packets by source IP
            if protocol == "DNS" or dst_port == 53:
                if src_ip:
                    src_dns_count[src_ip] = (
                        src_dns_count.get(src_ip, 0) + flow["packet_count"]
                    )

        # Check port scan alerts
        for src_ip, ports in src_dst_ports.items():
            if len(ports) >= self.port_scan_threshold:
                alerts.append(
                    {
                        "timestamp": 0.0,  # Will be adjusted below to start of capture
                        "rule_name": "Port Scan",
                        "severity": "High",
                        "description": f"Host {src_ip} scanned {len(ports)} different ports: {sorted(list(ports))}.",
                        "src_ip": src_ip,
                        "flow_key": None,
                    }
                )

        # Check DNS flood alerts
        for src_ip, count in src_dns_count.items():
            if count >= self.dns_flood_threshold:
                alerts.append(
                    {
                        "timestamp": 0.0,  # Will be adjusted below to start of capture
                        "rule_name": "DNS Flood",
                        "severity": "High",
                        "description": f"Host {src_ip} sent {count} DNS queries, exceeding threshold of {self.dns_flood_threshold}.",
                        "src_ip": src_ip,
                        "flow_key": None,
                    }
                )

        # Adjust timestamps for alerts without a specific flow timestamp to match capture start
        capture_start = 0.0
        if flows:
            capture_start = min(f["start_time"] for f in flows)

        for alert in alerts:
            if alert["timestamp"] == 0.0:
                alert["timestamp"] = capture_start

        # Sort alerts chronologically
        alerts.sort(key=lambda x: x["timestamp"])
        return alerts
