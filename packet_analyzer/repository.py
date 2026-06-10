from __future__ import annotations

from sqlalchemy.orm import Session
from packet_analyzer.database import Packet, DNSQuery, HTTPRequest, TLSSession


class PacketRepository:
    """Repository class for DB operations related to Packets."""

    def __init__(self, session: Session):
        self.session = session

    def add_packets_bulk(self, packet_records: list[dict[str, any]]) -> None:
        """
        Inserts a list of packet dictionaries and their associated sub-protocols
        (DNS, HTTP, TLS) to the database efficiently.
        """
        if not packet_records:
            return

        db_packets = []
        for record in packet_records:
            db_packet = Packet(
                timestamp=record["timestamp"],
                src_ip=record.get("src_ip"),
                dst_ip=record.get("dst_ip"),
                src_port=record.get("src_port"),
                dst_port=record.get("dst_port"),
                protocol=record.get("protocol"),
                packet_size=record["packet_size"],
            )

            # Check if there is an associated DNS Query
            dns_data = record.get("dns_query")
            if dns_data:
                db_packet.dns_queries.append(
                    DNSQuery(
                        domain=dns_data["domain"],
                        query_type=dns_data.get("query_type", "A"),
                    )
                )

            # Check if there is an associated HTTP Request
            http_data = record.get("http_request")
            if http_data:
                db_packet.http_requests.append(
                    HTTPRequest(
                        method=http_data["method"],
                        host=http_data["host"],
                        path=http_data["path"],
                    )
                )

            # Check if there is an associated TLS Session
            tls_data = record.get("tls_session")
            if tls_data:
                db_packet.tls_sessions.append(
                    TLSSession(
                        sni=tls_data["sni"],
                        tls_version=tls_data.get("tls_version"),
                    )
                )

            db_packets.append(db_packet)

        # Batch insert all packets and their related records
        self.session.add_all(db_packets)
        self.session.commit()
