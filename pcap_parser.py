"""Shared packet-parsing utilities used by pcap_scanner.py,
breakdown_packets_scanner.py, and pcap_formatted.py.

Centralizes packet -> record extraction so all three tools work from the
same data instead of duplicating scapy/regex logic.
"""

import re
import time
from collections import Counter

import scapy.all as scapy

SQL_INJECTION_PATTERNS = ["' or 'a'='a", "1=1"]


def extract_http_headers(payload):
    headers = {}
    header_lines = re.findall(r'(.*?): (.*?)\r\n', payload)
    for header in header_lines:
        headers[header[0].lower()] = header[1]
    return headers


def is_sql_injection(payload):
    # Add more SQL injection patterns as needed
    return any(pattern in payload for pattern in SQL_INJECTION_PATTERNS)


def _classify_base_protocol(packet):
    if packet.haslayer(scapy.TCP):
        return "TCP"
    if packet.haslayer(scapy.UDP):
        return "UDP"
    return "Other"


def build_packet_record(packet, index):
    """Return a dict describing one packet, or None if it has no IP layer."""
    if not packet.haslayer(scapy.IP):
        return None

    try:
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(packet.time)))
    except TypeError:
        timestamp = "Unknown Timestamp"

    record = {
        "index": index,
        "timestamp": timestamp,
        "src_ip": packet[scapy.IP].src,
        "dst_ip": packet[scapy.IP].dst,
        "protocol": _classify_base_protocol(packet),
        "request_type": None,
        "url": None,
        "host": None,
        "status_code": None,
        "user_agent": None,
        "accept": None,
        "referer": None,
        "cookies_present": False,
        "multipart_form_data": False,
        "credentials_found": False,
        "credentials_hint": None,
        "sql_injection_suspected": False,
    }

    if packet.haslayer(scapy.Raw):
        payload = packet[scapy.Raw].load.decode(errors="ignore")

        method_match = re.search(r"(GET|POST|PUT|DELETE) (\S+) HTTP", payload)
        if method_match:
            record["request_type"] = method_match.group(1)
            record["url"] = method_match.group(2)
            record["protocol"] = f"HTTP {method_match.group(1)}"

        status_match = re.search(r"HTTP/1\.\d (\d{3})", payload)
        if status_match:
            record["status_code"] = status_match.group(1)

        headers = extract_http_headers(payload)
        record["host"] = headers.get("host")
        record["user_agent"] = headers.get("user-agent")
        record["accept"] = headers.get("accept")
        record["referer"] = headers.get("referer")
        record["cookies_present"] = "cookie" in headers
        record["multipart_form_data"] = "multipart/form-data" in headers.get("content-type", "")

        user_match = re.search(r"(?i)(?:user|username)=(\w+)", payload)
        password_match = re.search(r"(?i)password=([^&\s]+)", payload)
        if user_match or password_match:
            record["credentials_found"] = True
            user_hint = user_match.group(1) if user_match else "?"
            password_hint = (password_match.group(1)[:2] + "***") if password_match else "?"
            record["credentials_hint"] = f"user={user_hint}, password={password_hint}"

        record["sql_injection_suspected"] = is_sql_injection(payload)

    return record


def build_packet_records(pcap_path):
    """Parse every packet in a pcap file into a list of record dicts.

    No packet cap: parsing locally is free, only OpenAI calls are
    rate-limited, so downstream chunking is responsible for staying within
    token/rate budgets.
    """
    packets = scapy.rdpcap(pcap_path)
    records = []
    for index, packet in enumerate(packets, start=1):
        record = build_packet_record(packet, index)
        if record is not None:
            records.append(record)
    return records


def summarize_records(records):
    """Compute overview statistics used for report headers and to ground the
    AI executive summary in real numbers."""
    protocol_counts = Counter(r["protocol"] for r in records)
    http_records = [r for r in records if r["request_type"]]
    suspicious_records = [
        r for r in records if r["sql_injection_suspected"] or r["credentials_found"]
    ]

    return {
        "total_packets": len(records),
        "unique_src_ips": sorted({r["src_ip"] for r in records}),
        "unique_dst_ips": sorted({r["dst_ip"] for r in records}),
        "protocol_counts": dict(protocol_counts),
        "http_request_count": len(http_records),
        "suspicious_count": len(suspicious_records),
        "suspicious_records": suspicious_records,
    }


def format_record_line(record):
    """One-line, human-readable representation of a packet record, used both
    for a report's packet-level data section and as OpenAI chunk input."""
    parts = [
        f"#{record['index']} {record['timestamp']}",
        f"{record['src_ip']} -> {record['dst_ip']}",
        f"Protocol: {record['protocol']}",
    ]
    if record["request_type"]:
        parts.append(f"{record['request_type']} {record['url']}")
    if record["host"]:
        parts.append(f"Host: {record['host']}")
    if record["status_code"]:
        parts.append(f"Status: {record['status_code']}")
    if record["user_agent"]:
        parts.append(f"User-Agent: {record['user_agent']}")
    if record["accept"]:
        parts.append(f"Accept: {record['accept']}")
    if record["referer"]:
        parts.append(f"Referer: {record['referer']}")
    if record["cookies_present"]:
        parts.append("Cookies present")
    if record["multipart_form_data"]:
        parts.append("MIME multipart form data")
    if record["credentials_found"]:
        parts.append(f"Credentials found ({record['credentials_hint']})")
    if record["sql_injection_suspected"]:
        parts.append("Potential SQL Injection")

    return " | ".join(parts)
