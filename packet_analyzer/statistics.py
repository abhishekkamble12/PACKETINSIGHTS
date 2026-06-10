from __future__ import annotations

from collections import Counter

from packet_analyzer.utils import top_items


class StatsEngine:
    """Accumulates packet statistics for reporting."""

    def __init__(self) -> None:
        self.protocol_stats: Counter[str] = Counter()
        self.source_ips: Counter[str] = Counter()
        self.destination_ips: Counter[str] = Counter()
        self.dns_queries: Counter[str] = Counter()
        self.tls_hosts: Counter[str] = Counter()
        self.http_requests: list[str] = []
        self.skipped_packets = 0
        self.flows: dict[tuple, dict[str, any]] = {}

    def record_protocol(self, protocol: str | None) -> None:
        if protocol:
            self.protocol_stats[protocol] += 1

    def record_endpoints(self, src_ip: object, dst_ip: object) -> None:
        if isinstance(src_ip, str):
            self.source_ips[src_ip] += 1
        if isinstance(dst_ip, str):
            self.destination_ips[dst_ip] += 1

    def record_dns_queries(self, domains: list[str]) -> None:
        for domain in domains:
            self.dns_queries[domain] += 1
            self.protocol_stats["DNS"] += 0

    def record_http_request(self, request: str | None) -> None:
        if request:
            self.http_requests.append(request)

    def record_tls_host(self, tls_host: str | None) -> None:
        if tls_host:
            self.tls_hosts[tls_host] += 1
            self.protocol_stats["TLS"] += 1

    def record_flow(
        self,
        src_ip: str | None,
        dst_ip: str | None,
        src_port: int | None,
        dst_port: int | None,
        protocol: str | None,
        timestamp: float,
        packet_size: int,
    ) -> None:
        from packet_analyzer.repository import get_flow_key
        flow_key = get_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)
        if flow_key not in self.flows:
            self.flows[flow_key] = {
                "src_ip": src_ip or "",
                "dst_ip": dst_ip or "",
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol or "",
                "packet_count": 0,
                "byte_count": 0,
                "start_time": timestamp,
                "end_time": timestamp,
                "duration": 0.0,
            }

        flow = self.flows[flow_key]
        flow["packet_count"] += 1
        flow["byte_count"] += packet_size
        if timestamp < flow["start_time"]:
            flow["start_time"] = timestamp
        if timestamp > flow["end_time"]:
            flow["end_time"] = timestamp
        flow["duration"] = max(0.0, flow["end_time"] - flow["start_time"])

    def mark_skipped_packet(self) -> None:
        self.skipped_packets += 1

    def build_results(self, *, pcap_path: str, total_packets: int) -> dict[str, object]:
        sorted_flows = sorted(
            [
                {
                    "src_ip": f["src_ip"],
                    "dst_ip": f["dst_ip"],
                    "src_port": f["src_port"],
                    "dst_port": f["dst_port"],
                    "protocol": f["protocol"],
                    "packet_count": f["packet_count"],
                    "byte_count": f["byte_count"],
                    "start_time": f["start_time"],
                    "end_time": f["end_time"],
                    "duration": f["duration"],
                    "flow_key": key,
                }
                for key, f in self.flows.items()
            ],
            key=lambda x: x["packet_count"],
            reverse=True,
        )

        return {
            "pcap_path": pcap_path,
            "total_packets": total_packets,
            "processed_packets": total_packets - self.skipped_packets,
            "skipped_packets": self.skipped_packets,
            "protocol_stats": dict(sorted(self.protocol_stats.items())),
            "top_sources": top_items(self.source_ips),
            "top_destinations": top_items(self.destination_ips),
            "top_dns_queries": top_items(self.dns_queries),
            "http_requests": self.http_requests[:5],
            "tls_hosts": top_items(self.tls_hosts),
            "flows": sorted_flows,
            "alerts": [],
        }
