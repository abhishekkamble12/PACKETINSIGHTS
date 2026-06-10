from __future__ import annotations

from pathlib import Path

from packet_analyzer.utils import ensure_directory


def build_report(results: dict[str, object]) -> str:
    protocol_stats = results["protocol_stats"]
    top_sources = results["top_sources"]
    top_destinations = results["top_destinations"]
    top_dns_queries = results["top_dns_queries"]
    http_requests = results["http_requests"]
    tls_hosts = results["tls_hosts"]

    lines = [
        "================================",
        "PACKET ANALYSIS REPORT",
        "================================",
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

    lines.extend(["", "================================"])
    return "\n".join(lines)


def save_report(content: str, output_path: str | Path) -> Path:
    destination = Path(output_path)
    ensure_directory(destination.parent)
    destination.write_text(content, encoding="utf-8")
    return destination

