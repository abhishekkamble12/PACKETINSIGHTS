from __future__ import annotations

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))

from packet_analyzer.analyzer import analyze_packets
from packet_analyzer.report import build_report, save_json_report, save_csv_reports
from packet_analyzer.database import init_db, get_session_factory


def run_test():
    pcap_path = Path("pcaps/test.pcap")
    if not pcap_path.exists():
        print(f"Sample PCAP not found at {pcap_path}. Generating it...")
        from packet_analyzer.parser import generate_sample_pcap
        generate_sample_pcap(pcap_path)

    # Initialize a test SQLite database
    db_path = "test_packets.db"
    if Path(db_path).exists():
        try:
            Path(db_path).unlink()
        except Exception:
            pass

    print("Initializing database...")
    init_db(db_path)
    session_factory = get_session_factory(db_path)
    db_session = session_factory()

    print("Analyzing packets and persisting to DB...")
    results, db_records = analyze_packets(pcap_path, db_session=db_session)
    db_session.close()

    print("\n--- RESULTS SUMMARY ---")
    print(f"Total Packets: {results['total_packets']}")
    print(f"Processed: {results['processed_packets']}")
    print(f"Flows found: {len(results['flows'])}")
    print(f"Alerts triggered: {len(results['alerts'])}")

    print("\n--- DETECTED ALERTS ---")
    for alert in results["alerts"]:
        print(f"[{alert['severity']}] {alert['rule_name']}: {alert['description']}")

    # Build report
    report = build_report(results)
    
    # Save outputs
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    
    json_path = reports_dir / "test_report.json"
    print(f"\nSaving JSON report to {json_path}...")
    save_json_report(results, json_path)
    assert json_path.exists(), "JSON file was not created"

    csv_prefix = reports_dir / "test_report"
    print(f"Saving CSV reports with prefix {csv_prefix}...")
    csv_paths = save_csv_reports(results, db_records, csv_prefix)
    for path in csv_paths:
        print(f"Created CSV: {path}")
        assert path.exists(), f"CSV file {path} was not created"

    print("\nAll integration test checks passed successfully!")


if __name__ == "__main__":
    run_test()
