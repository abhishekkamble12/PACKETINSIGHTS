from __future__ import annotations

import csv
import json
from pathlib import Path

from packet_analyzer.utils import ensure_directory


def build_report(results: dict[str, object]) -> str:
    protocol_stats = results["protocol_stats"]
    top_sources = results["top_sources"]
    top_destinations = results["top_destinations"]
    top_dns_queries = results["top_dns_queries"]
    http_requests = results["http_requests"]
    tls_hosts = results["tls_hosts"]
    flows = results.get("flows", [])
    alerts = results.get("alerts", [])

    lines = [
        "==================================",
        "PACKET ANALYSIS REPORT",
        "==================================",
        "",
        f"Analyzed File: {results['pcap_path']}",
        f"Total Packets: {results['total_packets']}",
        f"Processed Packets: {results['processed_packets']}",
        f"Skipped Packets: {results['skipped_packets']}",
        "",
        "Protocol Statistics:",
    ]

    for name, count in protocol_stats.items():
        lines.append(f"{name}: {count}")

    lines.extend(["", "Top Source IPs:"])
    lines.extend([f"{name}: {count}" for name, count in top_sources] or ["None"])

    lines.extend(["", "Top Destination IPs:"])
    lines.extend([f"{name}: {count}" for name, count in top_destinations] or ["None"])

    lines.extend(["", "Top DNS Queries:"])
    lines.extend([f"{name}: {count}" for name, count in top_dns_queries] or ["None"])

    lines.extend(["", "Sample HTTP Requests:"])
    lines.extend(http_requests or ["None"])

    lines.extend(["", "TLS Hosts:"])
    lines.extend([f"{name}: {count}" for name, count in tls_hosts] or ["None"])

    # 1. Flow Analysis Summary (Top 5)
    lines.extend(["", "Flow Analysis Summary (Top 5):"])
    if flows:
        for f in flows[:5]:
            sport_str = f"{f['src_port']}" if f["src_port"] is not None else "*"
            dport_str = f"{f['dst_port']}" if f["dst_port"] is not None else "*"
            lines.append(
                f"  {f['src_ip']}:{sport_str} <-> {f['dst_ip']}:{dport_str} ({f['protocol']}) | "
                f"Packets: {f['packet_count']} | Bytes: {f['byte_count']} | Duration: {f['duration']:.2f}s"
            )
    else:
        lines.append("  None")

    # 2. Security Alerts Summary
    lines.extend(["", "Security Alerts:"])
    if alerts:
        for a in alerts:
            lines.append(
                f"  [{a['severity'].upper()}] {a['rule_name']} - {a['description']} (Time: {a['timestamp']:.2f})"
            )
    else:
        lines.append("  No threat alerts detected.")

    lines.extend(["", "=================================="])
    return "\n".join(lines)


def save_report(content: str, output_path: str | Path) -> Path:
    destination = Path(output_path)
    ensure_directory(destination.parent)
    destination.write_text(content, encoding="utf-8")
    return destination


def save_json_report(results: dict[str, object], output_path: str | Path) -> Path:
    """Exports the full analysis results to a JSON file."""
    destination = Path(output_path)
    ensure_directory(destination.parent)

    # Convert tuples and other non-JSON types to lists or strings
    def serialize_helpers(obj):
        if isinstance(obj, tuple):
            return list(obj)
        if hasattr(obj, "items"):
            return dict(obj)
        return str(obj)

    serializable_results = json.loads(
        json.dumps(results, default=serialize_helpers)
    )

    with open(destination, "w", encoding="utf-8") as f:
        json.dump(serializable_results, f, indent=4)
    return destination


def save_csv_reports(
    results: dict[str, object],
    packet_records: list[dict[str, any]],
    base_output_path: str | Path,
) -> list[Path]:
    """
    Exports flow summary and packet log details to two CSV files.
    """
    base_path = Path(base_output_path)
    ensure_directory(base_path.parent)

    flows_path = base_path.with_name(f"{base_path.stem}_flows.csv")
    packets_path = base_path.with_name(f"{base_path.stem}_packets.csv")

    # 1. Flow Summary CSV
    flows = results.get("flows", [])
    flow_fields = [
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "packet_count",
        "byte_count",
        "start_time",
        "end_time",
        "duration",
    ]
    with open(flows_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=flow_fields, extrasaction="ignore")
        writer.writeheader()
        for flow in flows:
            writer.writerow(flow)

    # 2. Packet Log CSV
    packet_fields = [
        "timestamp",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "packet_size",
    ]
    with open(packets_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=packet_fields, extrasaction="ignore")
        writer.writeheader()
        for pkt in packet_records:
            writer.writerow(pkt)

    return [flows_path, packets_path]
