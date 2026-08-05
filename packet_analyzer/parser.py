from __future__ import annotations

import logging
from pathlib import Path

from packet_analyzer.utils import clean_text, normalize_domain


# Suppress scapy warnings about missing libpcap provider on Windows
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import rdpcap, wrpcap
    from scapy.error import Scapy_Exception
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw
except ModuleNotFoundError as exc:  # pragma: no cover - depends on local environment
    rdpcap = None
    wrpcap = None
    Scapy_Exception = Exception
    IP = TCP = UDP = Ether = Raw = None
    SCAPY_IMPORT_ERROR = exc
else:
    SCAPY_IMPORT_ERROR = None


def generate_sample_pcap(path: Path) -> None:
    """Generates a sample PCAP file with mock network traffic."""
    if wrpcap is None or Ether is None or IP is None or TCP is None or UDP is None or Raw is None:
        raise RuntimeError("Scapy is not fully installed/available to generate sample PCAP.")

    packets = []

    # 1. DNS Queries
    dns_domains = ["google.com", "github.com", "python.org", "wikipedia.org", "openai.com"]
    try:
        from scapy.layers.dns import DNS, DNSQR
        has_dns = True
    except ImportError:
        has_dns = False

    for i, domain in enumerate(dns_domains):
        if has_dns:
            pkt_q = (
                Ether()
                / IP(src=f"192.168.1.{10+i}", dst="8.8.8.8")
                / UDP(sport=53000 + i, dport=53)
                / DNS(rd=1, qd=DNSQR(qname=domain))
            )
        else:
            pkt_q = (
                Ether()
                / IP(src=f"192.168.1.{10+i}", dst="8.8.8.8")
                / UDP(sport=53000 + i, dport=53)
                / Raw(load=f"DNS query for {domain}".encode())
            )
        packets.append(pkt_q)

    # 2. HTTP Traffic (port 80)
    http_requests = [
        ("GET", "example.com", "/index.html"),
        ("POST", "api.example.com", "/v1/data"),
        ("GET", "python.org", "/downloads/"),
    ]
    for i, (method, host, url_path) in enumerate(http_requests):
        payload = f"{method} {url_path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        pkt_http = (
            Ether()
            / IP(src="192.168.1.10", dst="93.184.216.34")
            / TCP(sport=54000 + i, dport=80)
            / Raw(load=payload.encode())
        )
        packets.append(pkt_http)

    # 3. TLS / HTTPS Traffic (port 443)
    tls_domains = ["github.com", "google.com", "microsoft.com"]
    for i, domain in enumerate(tls_domains):
        try:
            from scapy.layers.tls.all import TLS, TLSClientHello, TLS_Ext_ServerName, ServerName
            pkt_tls = (
                Ether()
                / IP(src="192.168.1.10", dst="140.82.121.4")
                / TCP(sport=55000 + i, dport=443)
                / TLS(msg=[
                    TLSClientHello(
                        ext=[
                            TLS_Ext_ServerName(
                                servernames=[ServerName(servername=domain)]
                            )
                        ]
                    )
                ])
            )
            packets.append(pkt_tls)
        except Exception:
            pkt_tls_fallback = (
                Ether()
                / IP(src="192.168.1.10", dst="140.82.121.4")
                / TCP(sport=55000 + i, dport=443)
            )
            packets.append(pkt_tls_fallback)

    # 4. Other Protocols: SSH, SMTP, DHCP
    # SSH (port 22)
    packets.append(Ether() / IP(src="192.168.1.15", dst="192.168.1.200") / TCP(sport=60000, dport=22))
    # SMTP (port 25)
    packets.append(Ether() / IP(src="192.168.1.10", dst="74.125.142.27") / TCP(sport=60001, dport=25))
    # DHCP (UDP ports 67/68)
    packets.append(Ether() / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67))

    # Ensure parent directory exists
    path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(path), packets)


def load_pcap(pcap_path: str | Path):
    if rdpcap is None:
        raise RuntimeError(
            "Scapy is required to analyze PCAP files. Install dependencies with: pip install -r requirements.txt"
        ) from SCAPY_IMPORT_ERROR

    path = Path(pcap_path)
    if not path.exists():
        if path.suffix in (".pcap", ".cap") and wrpcap is not None:
            try:
                print(f"PCAP file not found: {path}")
                print("Generating a sample PCAP file with mock network traffic for analysis...")
                generate_sample_pcap(path)
            except Exception as e:
                print(f"Warning: Failed to generate sample PCAP file: {e}")

        if not path.exists():
            project_pcaps_dir = Path("pcaps")
            available_pcaps = []

            if project_pcaps_dir.exists():
                available_pcaps = sorted(
                    candidate.name for candidate in project_pcaps_dir.iterdir() if candidate.is_file() and candidate.suffix == ".pcap"
                )

            details = [f"PCAP file not found: {path}"]
            if path.name == "your_file.pcap":
                details.append("Replace 'your_file.pcap' with an actual capture filename.")
            if available_pcaps:
                details.append(f"Available PCAP files in .\\pcaps: {', '.join(available_pcaps)}")
            else:
                details.append("No .pcap files were found in .\\pcaps. Add one there and run the command again.")

            raise FileNotFoundError(" ".join(details))


    try:
        packets = rdpcap(str(path))
    except Scapy_Exception as exc:
        raise ValueError(f"Unable to read PCAP file: {path}") from exc

    if len(packets) == 0:
        raise ValueError("No packets detected in the provided PCAP file.")

    return packets


def extract_packet_metadata(packet) -> dict[str, object]:
    metadata: dict[str, object] = {
        "timestamp": getattr(packet, "time", None),
        "length": len(packet),
        "has_ethernet": bool(Ether and packet.haslayer(Ether)),
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
    }

    if IP and packet.haslayer(IP):
        ip_layer = packet[IP]
        metadata["src_ip"] = ip_layer.src
        metadata["dst_ip"] = ip_layer.dst

    if TCP and packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        metadata["src_port"] = tcp_layer.sport
        metadata["dst_port"] = tcp_layer.dport
    elif UDP and packet.haslayer(UDP):
        udp_layer = packet[UDP]
        metadata["src_port"] = udp_layer.sport
        metadata["dst_port"] = udp_layer.dport

    return metadata


class PacketParser:
    """Extracts normalized metadata from a packet."""

    def parse(self, packet) -> dict[str, object]:
        metadata = extract_packet_metadata(packet)
        return {
            "timestamp": float(metadata["timestamp"]) if metadata["timestamp"] is not None else 0.0,
            "src_ip": metadata["src_ip"],
            "dst_ip": metadata["dst_ip"],
            "src_port": metadata["src_port"],
            "dst_port": metadata["dst_port"],
            "packet_size": metadata["length"],
            "has_ethernet": metadata["has_ethernet"],
        }


def parse_dns(packet) -> dict[str, any] | None:
    """Extracts DNS query domain and query type from a packet."""
    try:
        from scapy.layers.dns import DNS, DNSQR
        has_dns = True
    except ImportError:
        has_dns = False

    if not has_dns or not packet.haslayer(DNS) or packet[DNS].qdcount == 0:
        return None

    question = packet[DNS].qd
    if isinstance(question, list) and len(question) > 0:
        question = question[0]
    if isinstance(question, DNSQR):
        domain = normalize_domain(clean_text(question.qname))
        if domain:
            qtype_val = getattr(question, "qtype", 1)
            qtype_name = "A"
            try:
                from scapy.layers.dns import dnstypes
                qtype_name = dnstypes.get(qtype_val, "A")
            except Exception:
                qtype_mapping = {
                    1: "A",
                    2: "NS",
                    5: "CNAME",
                    6: "SOA",
                    12: "PTR",
                    15: "MX",
                    16: "TXT",
                    28: "AAAA",
                }
                qtype_name = qtype_mapping.get(qtype_val, "A")

            if not isinstance(qtype_name, str):
                qtype_name = str(qtype_name)

            return {"domain": domain, "query_type": qtype_name}
    return None


def parse_http(packet) -> dict[str, any] | None:
    """Extracts HTTP method, host, and path from a packet."""
    try:
        from scapy.layers.http import HTTPRequest
        has_http_layer = True
    except ImportError:
        has_http_layer = False

    if has_http_layer and packet.haslayer(HTTPRequest):
        request = packet[HTTPRequest]
        method = clean_text(getattr(request, "Method", b"GET"))
        host = clean_text(getattr(request, "Host", b""))
        path = clean_text(getattr(request, "Path", b"/"))
        return {"method": method or "GET", "host": host, "path": path or "/"}

    try:
        from scapy.layers.inet import TCP
        from scapy.packet import Raw
        has_tcp_raw = True
    except ImportError:
        has_tcp_raw = False

    if not has_tcp_raw or not packet.haslayer(TCP) or not packet.haslayer(Raw):
        return None

    tcp_layer = packet[TCP]
    if tcp_layer.sport != 80 and tcp_layer.dport != 80:
        return None

    try:
        payload = clean_text(bytes(packet[Raw].load))
    except Exception:
        return None

    if not payload:
        return None

    lines = payload.splitlines()
    first_line = lines[0] if lines else ""
    if first_line.startswith(
        ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ")
    ):
        parts = first_line.split()
        method = parts[0] if len(parts) > 0 else "GET"
        path = parts[1] if len(parts) > 1 else "/"

        host = ""
        for line in lines[1:]:
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()
                break
        return {"method": method, "host": host, "path": path}

    return None


def parse_tls(packet) -> dict[str, any] | None:
    """Extracts TLS SNI and version from a packet."""
    try:
        from scapy.layers.inet import TCP
        has_tcp = True
    except ImportError:
        has_tcp = False

    if not has_tcp or not packet.haslayer(TCP):
        return None

    tcp_layer = packet[TCP]
    if tcp_layer.sport != 443 and tcp_layer.dport != 443:
        return None

    sni = "Unknown"
    tls_version = None

    try:
        from scapy.layers.tls.all import TLS, TLSClientHello, TLS_Ext_ServerName, ServerName
        if packet.haslayer(TLS):
            client_hello = packet.getlayer(TLSClientHello)
            if client_hello is not None:
                ext = client_hello.getlayer(TLS_Ext_ServerName)
                if ext is not None and getattr(ext, "servernames", None):
                    for server_name in ext.servernames:
                        hostname = normalize_domain(
                            clean_text(getattr(server_name, "servername", None))
                        )
                        if hostname:
                            sni = hostname
                            break

                version_val = getattr(client_hello, "version", None)
                if version_val is not None:
                    version_mapping = {
                        0x0303: "TLS 1.2",
                        0x0304: "TLS 1.3",
                        0x0302: "TLS 1.1",
                        0x0301: "TLS 1.0",
                    }
                    tls_version = version_mapping.get(
                        version_val, f"TLS {hex(version_val)}"
                    )
    except Exception:
        pass

    if sni == "Unknown":
        sni = "TLS traffic on port 443"

    return {"sni": sni, "tls_version": tls_version}

