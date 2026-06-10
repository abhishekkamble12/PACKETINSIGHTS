from __future__ import annotations

from sqlalchemy.orm import Session
from packet_analyzer.database import Packet, DNSQuery, HTTPRequest, TLSSession, Flow, Alert


def get_flow_key(
    src_ip: str | None,
    dst_ip: str | None,
    src_port: int | None,
    dst_port: int | None,
    protocol: str | None,
) -> tuple:
    s_ip = src_ip or ""
    d_ip = dst_ip or ""
    s_port = src_port or 0
    d_port = dst_port or 0
    proto = protocol or ""

    # Sort for bidirectional grouping
    if s_ip < d_ip:
        return (s_ip, d_ip, s_port, d_port, proto)
    elif s_ip > d_ip:
        return (d_ip, s_ip, d_port, s_port, proto)
    else:
        if s_port <= d_port:
            return (s_ip, d_ip, s_port, d_port, proto)
        else:
            return (d_ip, s_ip, d_port, s_port, proto)


class PacketRepository:
    """Repository class for DB operations related to Packets, Flows, and Alerts."""

    def __init__(self, session: Session):
        self.session = session

    def add_packets_bulk(
        self,
        packet_records: list[dict[str, any]],
        alert_records: list[dict[str, any]] | None = None,
    ) -> None:
        """
        Inserts a list of packet records, groups them into flows, and optionally
        inserts security alerts linked to those flows.
        """
        if not packet_records:
            return

        flows_dict: dict[tuple, Flow] = {}

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

            # Flow Grouping
            flow_key = get_flow_key(
                db_packet.src_ip,
                db_packet.dst_ip,
                db_packet.src_port,
                db_packet.dst_port,
                db_packet.protocol,
            )

            if flow_key not in flows_dict:
                # The first packet in the flow sets the base properties
                flow_obj = Flow(
                    src_ip=db_packet.src_ip or "",
                    dst_ip=db_packet.dst_ip or "",
                    src_port=db_packet.src_port,
                    dst_port=db_packet.dst_port,
                    protocol=db_packet.protocol or "",
                    packet_count=0,
                    byte_count=0,
                    start_time=db_packet.timestamp,
                    end_time=db_packet.timestamp,
                    duration=0.0,
                )
                flows_dict[flow_key] = flow_obj
            else:
                flow_obj = flows_dict[flow_key]

            # Update flow counters and bounds
            flow_obj.packet_count += 1
            flow_obj.byte_count += db_packet.packet_size
            if db_packet.timestamp < flow_obj.start_time:
                flow_obj.start_time = db_packet.timestamp
            if db_packet.timestamp > flow_obj.end_time:
                flow_obj.end_time = db_packet.timestamp
            flow_obj.duration = max(0.0, flow_obj.end_time - flow_obj.start_time)

            # Link packet to the flow
            flow_obj.packets.append(db_packet)

        # Batch insert all flows (which cascades to packets, dns_queries, etc.)
        self.session.add_all(flows_dict.values())
        self.session.flush()  # Populates flow IDs for linking with alerts

        # Add alerts if present
        if alert_records:
            db_alerts = []
            for a_rec in alert_records:
                db_alert = Alert(
                    timestamp=a_rec["timestamp"],
                    rule_name=a_rec["rule_name"],
                    severity=a_rec["severity"],
                    description=a_rec["description"],
                    src_ip=a_rec.get("src_ip"),
                )
                # Attempt to link alert to its flow
                flow_key = a_rec.get("flow_key")
                if flow_key and flow_key in flows_dict:
                    db_alert.flow = flows_dict[flow_key]
                db_alerts.append(db_alert)
            self.session.add_all(db_alerts)

        self.session.commit()

