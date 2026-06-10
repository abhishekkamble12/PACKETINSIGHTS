from __future__ import annotations

import argparse
import logging
from pathlib import Path

# Suppress scapy warnings about missing libpcap provider on Windows
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.http import HTTPRequest
    from scapy.layers.inet import TCP

    from scapy.layers.tls.all import TLS, TLSClientHello, TLS_Ext_ServerName
    from scapy.packet import Raw
except ModuleNotFoundError as exc:  # pragma: no cover - depends on local environment
    DNS = DNSQR = HTTPRequest = TCP = TLS = TLSClientHello = TLS_Ext_ServerName = Raw = None
    SCAPY_IMPORT_ERROR = exc
else:
    SCAPY_IMPORT_ERROR = None

from packet_analyzer.parser import PacketParser, parse_dns, parse_http, parse_tls
from packet_analyzer.protocols import ProtocolDetector
from packet_analyzer.detector import ThreatDetector
from packet_analyzer.reader import PacketReader
from packet_analyzer.report import build_report, save_report
from packet_analyzer.statistics import StatsEngine
from packet_analyzer.utils import clean_text, normalize_domain


def extract_dns(packet) -> list[str]:
    if DNS is None or DNSQR is None:
        return []

    if not packet.haslayer(DNS) or packet[DNS].qdcount == 0:
        return []

    queries: list[str] = []
    question = packet[DNS].qd

    if isinstance(question, DNSQR):
        domain = normalize_domain(clean_text(question.qname))
        if domain:
            queries.append(domain)
        return queries

    while isinstance(question, DNSQR):
        domain = normalize_domain(clean_text(question.qname))
        if domain:
            queries.append(domain)
        question = question.payload

    return queries


def extract_http(packet) -> str | None:
    if HTTPRequest and packet.haslayer(HTTPRequest):
        request = packet[HTTPRequest]
        method = clean_text(getattr(request, "Method", None))
        host = clean_text(getattr(request, "Host", None))
        path = clean_text(getattr(request, "Path", None))
        return f"{method} {host}{path}".strip()

    if TCP is None or Raw is None:
        return None

    if not packet.haslayer(TCP) or not packet.haslayer(Raw):
        return None

    tcp_layer = packet[TCP]
    if tcp_layer.sport != 80 and tcp_layer.dport != 80:
        return None

    payload = clean_text(bytes(packet[Raw].load))
    if not payload:
        return None

    first_line = payload.splitlines()[0] if payload.splitlines() else ""
    if first_line.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ")):
        host = ""
        for line in payload.splitlines()[1:]:
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()
                break
        return f"{first_line} Host: {host}".strip()

    return None


def extract_tls(packet) -> str | None:
    if TCP is None or TLS is None:
        return None

    if not packet.haslayer(TCP):
        return None

    tcp_layer = packet[TCP]
    if tcp_layer.sport != 443 and tcp_layer.dport != 443:
        return None

    if not packet.haslayer(TLS):
        return "TLS traffic on port 443"

    client_hello = packet.getlayer(TLSClientHello)
    if client_hello is None:
        return "TLS traffic on port 443"

    ext = client_hello.getlayer(TLS_Ext_ServerName)
    if ext is None or not getattr(ext, "servernames", None):
        return "TLS traffic on port 443"

    for server_name in ext.servernames:
        hostname = normalize_domain(clean_text(getattr(server_name, "servername", None)))
        if hostname:
            return hostname

    return "TLS traffic on port 443"


def analyze_packets(
    pcap_path: str | Path, db_session=None
) -> tuple[dict[str, object], list[dict[str, any]]]:
    if SCAPY_IMPORT_ERROR is not None:
        raise RuntimeError(
            "Scapy is required to analyze PCAP files. Install dependencies with: pip install -r requirements.txt"
        ) from SCAPY_IMPORT_ERROR

    reader = PacketReader()
    parser = PacketParser()
    proto_detector = ProtocolDetector()
    stats = StatsEngine()

    packets = reader.read(pcap_path)
    db_records = []

    for packet in packets:
        try:
            metadata = parser.parse(packet)
            protocol = proto_detector.detect(packet)

            stats.record_protocol(protocol)
            stats.record_endpoints(metadata.get("src_ip"), metadata.get("dst_ip"))
            stats.record_dns_queries(extract_dns(packet))
            stats.record_http_request(extract_http(packet))
            stats.record_tls_host(extract_tls(packet))

            # Record flow details
            stats.record_flow(
                src_ip=metadata.get("src_ip"),
                dst_ip=metadata.get("dst_ip"),
                src_port=metadata.get("src_port"),
                dst_port=metadata.get("dst_port"),
                protocol=protocol,
                timestamp=metadata.get("timestamp", 0.0),
                packet_size=metadata.get("packet_size", 0),
            )

            # Build record in-memory for CSV and DB
            record = {
                "timestamp": metadata["timestamp"],
                "src_ip": metadata.get("src_ip"),
                "dst_ip": metadata.get("dst_ip"),
                "src_port": metadata.get("src_port"),
                "dst_port": metadata.get("dst_port"),
                "protocol": protocol,
                "packet_size": metadata.get("packet_size", 0),
                "dns_query": parse_dns(packet),
                "http_request": parse_http(packet),
                "tls_session": parse_tls(packet),
            }
            db_records.append(record)
        except Exception:
            stats.mark_skipped_packet()

    results = stats.build_results(
        pcap_path=str(Path(pcap_path).resolve()), total_packets=len(packets)
    )

    # Threat Detection
    threat_detector = ThreatDetector()
    alerts = threat_detector.detect(results["flows"])
    results["alerts"] = alerts

    if db_session is not None and db_records:
        from packet_analyzer.repository import PacketRepository

        repo = PacketRepository(db_session)
        repo.add_packets_bulk(db_records, alert_records=alerts)

    return results, db_records


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze packets from a PCAP file.")
    parser.add_argument("pcap", help="Path to the PCAP file to analyze.")
    parser.add_argument(
        "-o",
        "--output",
        default="reports/report.txt",
        help="Path to save the generated report.",
    )
    parser.add_argument(
        "--db-path",
        default="packets.db",
        help="Path to SQLite database to save analysis results (default: packets.db). Use 'none' to disable storage.",
    )
    parser.add_argument(
        "--json",
        help="Path to save the generated JSON report (e.g., reports/report.json).",
    )
    parser.add_argument(
        "--csv",
        help="Base path / prefix to save the generated CSV reports (e.g., reports/report).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    db_session = None
    if args.db_path and args.db_path.lower() != "none":
        from packet_analyzer.database import init_db, get_session_factory
        try:
            init_db(args.db_path)
            SessionFactory = get_session_factory(args.db_path)
            db_session = SessionFactory()
        except Exception as exc:
            print(f"Database Initialization Error: {exc}")
            return 1

    try:
        results, db_records = analyze_packets(args.pcap, db_session=db_session)
        report = build_report(results)
        output_path = save_report(report, args.output)

        print(report)
        print(f"\nReport saved to: {output_path.resolve()}")

        if args.json:
            from packet_analyzer.report import save_json_report
            json_path = save_json_report(results, args.json)
            print(f"JSON report saved to: {Path(json_path).resolve()}")

        if args.csv:
            from packet_analyzer.report import save_csv_reports
            csv_paths = save_csv_reports(results, db_records, args.csv)
            for path in csv_paths:
                print(f"CSV report saved to: {Path(path).resolve()}")

        if args.db_path and args.db_path.lower() != "none":
            print(f"Analysis results saved to database: {Path(args.db_path).resolve()}")
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"Error: {exc}")
        return 1
    finally:
        if db_session:
            db_session.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
