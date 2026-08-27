#!/usr/bin/env python3
"""
generate_scenario_pcaps.py

Builds two synthetic pcap files for classroom packet-analysis exercises.
Every packet is crafted with scapy from scratch -- nothing here is a real
capture, and all IP ranges are non-routable (RFC 1918 for "internal" hosts,
RFC 5737 documentation ranges for "external" hosts) so nothing resolves to
a real machine on the internet.

1. data_exfiltration.pcap
   - An internal workstation logs into a corporate file server in the
     clear and successfully downloads several sensitive documents
     (financial report, HR salary sheet, legal merger agreement, source
     code export).
   - The same workstation then makes three separate attempts to push
     copies of that data out to external hosts. All three attempts fail,
     each via a different, realistic failure mode:
       a) DLP/proxy block -> HTTP 403 + server RST
       b) blackholed destination -> unanswered/retried SYNs, no reply
       c) TCP connects fine, application never responds -> client times
          out and aborts with RST
   - Includes a second, later attempt to the same blocked external host
     with a different file, so the "repeated failed attempts to the same
     suspicious destination" pattern is visible.

2. temp_file_lifecycle.pcap
   - An automation/service account repeatedly creates, verifies, and
     deletes temporary files on a file server (HTTP PUT / GET / DELETE),
     four cycles in a row.
   - The same host then successfully transfers a backup archive to a
     second server in three chunks, each one over a different
     destination TCP port (8080, 8443, 9090), all completing with 200 OK.

Run with:
    python3 generate_scenario_pcaps.py
Outputs are written next to this script.
"""

import hashlib
import os
import random
from datetime import datetime, timezone

from scapy.all import Ether, IP, TCP, Raw, wrpcap

random.seed(1337)

OUT_DIR = os.path.dirname(os.path.abspath(__file__))


def mac_for(ip):
    octets = [int(o) for o in ip.split(".")]
    return "02:00:%02x:%02x:%02x:%02x" % tuple(octets)


def http_request(method, path, host, headers=None, body=""):
    headers = headers or {}
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
    body_bytes = body.encode()
    if body_bytes:
        headers.setdefault("Content-Length", str(len(body_bytes)))
    for key, value in headers.items():
        lines.append(f"{key}: {value}")
    text = "\r\n".join(lines) + "\r\n\r\n" + body
    return text


def http_response(status, headers=None, body=""):
    headers = dict(headers or {})
    body_bytes = body.encode()
    headers.setdefault("Content-Length", str(len(body_bytes)))
    lines = [f"HTTP/1.1 {status}"]
    for key, value in headers.items():
        lines.append(f"{key}: {value}")
    text = "\r\n".join(lines) + "\r\n\r\n" + body
    return text


class TcpFlow:
    """Minimal stateful helper that crafts one synthetic TCP connection
    (correct-ish seq/ack bookkeeping, not a full RFC-793 implementation)."""

    def __init__(self, src_ip, dst_ip, sport, dport, t):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.sport = sport
        self.dport = dport
        self.t = t
        self.client_seq = random.randint(1_000_000, 2_000_000_000)
        self.server_seq = random.randint(1_000_000, 2_000_000_000)
        self.eth_c = Ether(src=mac_for(src_ip), dst=mac_for(dst_ip))
        self.eth_s = Ether(src=mac_for(dst_ip), dst=mac_for(src_ip))
        self.pkts = []

    def _tick(self, delta=0.010):
        self.t += delta
        return self.t

    def _c(self, flags, extra_seq=0, extra_ack=0):
        ip = IP(src=self.src_ip, dst=self.dst_ip)
        tcp = TCP(sport=self.sport, dport=self.dport, flags=flags,
                  seq=self.client_seq + extra_seq, ack=self.server_seq + extra_ack,
                  window=64240)
        return ip, tcp

    def _s(self, flags, extra_seq=0, extra_ack=0):
        ip = IP(src=self.dst_ip, dst=self.src_ip)
        tcp = TCP(sport=self.dport, dport=self.sport, flags=flags,
                  seq=self.server_seq + extra_seq, ack=self.client_seq + extra_ack,
                  window=64240)
        return ip, tcp

    def syn(self, gap=0.0):
        ip, tcp = self._c("S")
        pkt = self.eth_c / ip / tcp
        pkt.time = self._tick(gap or 0.010)
        self.pkts.append(pkt)
        self.client_seq += 1

    def syn_retransmit(self, gap):
        ip, tcp = self._c("S", extra_seq=-1)
        pkt = self.eth_c / ip / tcp
        pkt.time = self._tick(gap)
        self.pkts.append(pkt)

    def syn_ack(self):
        ip, tcp = self._s("SA")
        pkt = self.eth_s / ip / tcp
        pkt.time = self._tick()
        self.pkts.append(pkt)
        self.server_seq += 1

    def ack(self):
        ip, tcp = self._c("A")
        pkt = self.eth_c / ip / tcp
        pkt.time = self._tick()
        self.pkts.append(pkt)

    def handshake(self):
        self.syn()
        self.syn_ack()
        self.ack()

    def client_send(self, payload):
        data = payload.encode()
        ip, tcp = self._c("PA")
        pkt = self.eth_c / ip / tcp / Raw(load=data)
        pkt.time = self._tick(0.05)
        self.pkts.append(pkt)
        self.client_seq += len(data)
        ip2, tcp2 = self._s("A")
        ackpkt = self.eth_s / ip2 / tcp2
        ackpkt.time = self._tick(0.02)
        self.pkts.append(ackpkt)

    def server_send(self, payload):
        data = payload.encode()
        ip, tcp = self._s("PA")
        pkt = self.eth_s / ip / tcp / Raw(load=data)
        pkt.time = self._tick(0.08)
        self.pkts.append(pkt)
        self.server_seq += len(data)
        ip2, tcp2 = self._c("A")
        ackpkt = self.eth_c / ip2 / tcp2
        ackpkt.time = self._tick(0.02)
        self.pkts.append(ackpkt)

    def graceful_close(self, initiator="client"):
        first, second = (self._c, self._s) if initiator == "client" else (self._s, self._c)
        eth_first = self.eth_c if initiator == "client" else self.eth_s
        eth_second = self.eth_s if initiator == "client" else self.eth_c

        ip, tcp = first("FA")
        pkt = eth_first / ip / tcp
        pkt.time = self._tick(0.05)
        self.pkts.append(pkt)
        if initiator == "client":
            self.client_seq += 1
        else:
            self.server_seq += 1

        ip2, tcp2 = second("FA")
        pkt2 = eth_second / ip2 / tcp2
        pkt2.time = self._tick(0.02)
        self.pkts.append(pkt2)
        if initiator == "client":
            self.server_seq += 1
        else:
            self.client_seq += 1

        ip3, tcp3 = first("A")
        pkt3 = eth_first / ip3 / tcp3
        pkt3.time = self._tick(0.01)
        self.pkts.append(pkt3)

    def reset(self, sender="server"):
        if sender == "server":
            ip, tcp = self._s("RA")
            eth = self.eth_s
        else:
            ip, tcp = self._c("RA")
            eth = self.eth_c
        pkt = eth / ip / tcp
        pkt.time = self._tick(0.03)
        self.pkts.append(pkt)


def build_exfiltration_pcap(base_time):
    pkts = []
    t = base_time

    workstation = "10.20.5.14"
    fileserver = "10.20.5.100"
    blocked_host = "198.51.100.23"   # RFC 5737 documentation range
    blackhole_host = "203.0.113.77"  # RFC 5737 documentation range
    silent_host = "192.0.2.50"       # RFC 5737 documentation range

    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0.0.0"

    # --- Legitimate login + document downloads over one persistent connection ---
    flow = TcpFlow(workstation, fileserver, 51410, 80, t)
    flow.handshake()
    flow.client_send(http_request(
        "POST", "/login", "intranet.corp.local",
        headers={"User-Agent": ua, "Content-Type": "application/x-www-form-urlencoded"},
        body="user=jsmith&password=Summer2025!",
    ))
    flow.server_send(http_response(
        "200 OK",
        headers={"Set-Cookie": "SESSIONID=8f3a1c9d4e2b7766; Path=/; HttpOnly",
                 "Content-Type": "text/html"},
        body="<html>Welcome jsmith</html>",
    ))

    documents = [
        ("/documents/Q4_2025_Financial_Report.pdf", "application/pdf",
         "%PDF-1.4 (financial report contents truncated for capture)"),
        ("/hr/Employee_Salary_Master.xlsx",
         "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
         "PK\x03\x04 (salary spreadsheet contents truncated for capture)"),
        ("/legal/Project_Falcon_Merger_Agreement.docx",
         "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
         "PK\x03\x04 (merger agreement contents truncated for capture)"),
        ("/engineering/Source_Code_Export.zip", "application/zip",
         "PK\x03\x04 (source export contents truncated for capture)"),
    ]
    for path, content_type, body in documents:
        flow.client_send(http_request(
            "GET", path, "intranet.corp.local",
            headers={"User-Agent": ua, "Cookie": "SESSIONID=8f3a1c9d4e2b7766",
                     "Accept": "*/*"},
        ))
        flow.server_send(http_response(
            "200 OK", headers={"Content-Type": content_type}, body=body,
        ))
    flow.graceful_close()
    pkts.extend(flow.pkts)
    t = flow.t + 6.0

    # --- Failed exfiltration attempt #1: DLP/proxy block, server tears down with RST ---
    flow = TcpFlow(workstation, blocked_host, 51420, 8081, t)
    flow.handshake()
    flow.client_send(http_request(
        "POST", "/upload", blocked_host,
        headers={"User-Agent": "curl/8.4.0",
                 "Content-Type": "multipart/form-data; boundary=----ExfilBoundary"},
        body=("------ExfilBoundary\r\n"
              "Content-Disposition: form-data; name=\"file\"; filename=\"Q4_2025_Financial_Report.pdf\"\r\n"
              "Content-Type: application/pdf\r\n\r\n"
              "CONFIDENTIAL financial data (truncated)\r\n"
              "------ExfilBoundary--"),
    ))
    flow.server_send(http_response(
        "403 Forbidden", headers={"Content-Type": "text/plain"},
        body="Blocked by Corporate DLP Policy - Sensitive Data Transfer Denied",
    ))
    flow.reset(sender="server")
    pkts.extend(flow.pkts)
    t = flow.t + 4.0

    # --- Failed exfiltration attempt #2: destination blackholed, SYNs go unanswered ---
    flow = TcpFlow(workstation, blackhole_host, 51430, 4444, t)
    flow.syn()
    flow.syn_retransmit(1.0)
    flow.syn_retransmit(2.0)
    flow.syn_retransmit(4.0)
    pkts.extend(flow.pkts)
    t = flow.t + 5.0

    # --- Failed exfiltration attempt #3: retry against the same blocked host, different file ---
    flow = TcpFlow(workstation, blocked_host, 51440, 8081, t)
    flow.handshake()
    flow.client_send(http_request(
        "POST", "/upload", blocked_host,
        headers={"User-Agent": "curl/8.4.0",
                 "Content-Type": "multipart/form-data; boundary=----ExfilBoundary"},
        body=("------ExfilBoundary\r\n"
              "Content-Disposition: form-data; name=\"file\"; filename=\"Employee_Salary_Master.xlsx\"\r\n"
              "Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\r\n\r\n"
              "CONFIDENTIAL payroll data (truncated)\r\n"
              "------ExfilBoundary--"),
    ))
    flow.server_send(http_response(
        "403 Forbidden", headers={"Content-Type": "text/plain"},
        body="Blocked: PII Data Detected in Outbound Transfer",
    ))
    flow.reset(sender="server")
    pkts.extend(flow.pkts)
    t = flow.t + 4.0

    # --- Failed exfiltration attempt #4: TCP connects fine, app never responds, client times out ---
    flow = TcpFlow(workstation, silent_host, 51450, 9999, t)
    flow.handshake()
    flow.client_send(http_request(
        "POST", "/upload", silent_host,
        headers={"User-Agent": "curl/8.4.0", "Content-Type": "application/zip"},
        body="PK\x03\x04 (source export contents truncated for capture)",
    ))
    flow.t += 8.0  # simulate the client waiting for a response that never comes
    flow.reset(sender="client")
    pkts.extend(flow.pkts)

    return pkts


def build_temp_lifecycle_pcap(base_time):
    pkts = []
    t = base_time

    automation_host = "10.20.5.20"
    fileserver = "10.20.5.50"
    backup_target = "10.20.5.60"
    ua = "BackupAgent/2.3 (internal automation)"

    # --- Repeated create / verify / delete cycles for temp files ---
    for i in range(1, 5):
        tmp_name = "tmp_" + hashlib.md5(f"cycle{i}".encode()).hexdigest()[:8] + ".tmp"
        path = f"/tmp/{tmp_name}"
        blob = hashlib.sha256(f"payload{i}".encode()).hexdigest()

        flow = TcpFlow(automation_host, fileserver, 52000 + i, 8080, t)
        flow.handshake()

        flow.client_send(http_request(
            "PUT", path, "fileserver.corp.local",
            headers={"User-Agent": ua, "Content-Type": "application/octet-stream"},
            body=blob,
        ))
        flow.server_send(http_response("201 Created"))

        flow.client_send(http_request(
            "GET", path, "fileserver.corp.local",
            headers={"User-Agent": ua},
        ))
        flow.server_send(http_response(
            "200 OK", headers={"Content-Type": "application/octet-stream"}, body=blob,
        ))

        flow.client_send(http_request(
            "DELETE", path, "fileserver.corp.local",
            headers={"User-Agent": ua},
        ))
        flow.server_send(http_response("204 No Content"))

        flow.graceful_close()
        pkts.extend(flow.pkts)
        t = flow.t + 18.0  # scheduled job runs roughly every ~18s

    # --- Successful multi-part backup transfer, each part over a different port ---
    parts = [
        (8080, "backup_archive.tar.gz.part1"),
        (8443, "backup_archive.tar.gz.part2"),
        (9090, "backup_archive.tar.gz.part3"),
    ]
    for idx, (port, filename) in enumerate(parts, start=1):
        chunk = hashlib.sha256(f"chunk{idx}".encode()).hexdigest() * 4
        flow = TcpFlow(automation_host, backup_target, 53000 + idx, port, t)
        flow.handshake()
        flow.client_send(http_request(
            "POST", f"/transfer/{filename}", "backup.corp.local",
            headers={"User-Agent": ua, "Content-Type": "application/octet-stream"},
            body=chunk,
        ))
        flow.server_send(http_response(
            "200 OK", headers={"Content-Type": "text/plain"},
            body=f"Chunk {idx} of {len(parts)} received, checksum OK",
        ))
        flow.graceful_close()
        pkts.extend(flow.pkts)
        t = flow.t + 3.0

    return pkts


# --- Portal sign-in / API activity scenario -------------------------------

PORTAL_IP = "10.30.8.10"
PORTAL_PORT = 80
PORTAL_HOST = "portal.corp.local"
PORTAL_UA = "Mozilla/5.0 (corp workstation) CorpPortalClient/4.1"

# (username, password, department)
PORTAL_USERS = [
    ("mwong", "Winter2026!", "sales"),
    ("rpatel", "Blue$Sky42", "engineering"),
    ("ksato", "Tulip#88", "support"),
    ("egarcia", "Compass19", "sales"),
    ("tnguyen", "Harbor2026", "engineering"),
    ("lmartin", "Granite55!", "marketing"),
    ("dkim", "Pixel_007", "engineering"),
    ("avargas", "Sunrise21", "support"),
    ("csingh", "Nimbus#3", "marketing"),
    ("bwilson", "Cobalt2026", "sales"),
    ("opark", "Maple!99", "engineering"),
    ("ndupont", "Ember_44", "support"),
    ("afinance", "Ledger$2026", "finance"),
    ("bpayroll", "Payday!77", "finance"),
    ("qadams", "Voyage33", "marketing"),
    ("hyoung", "Quartz#12", "support"),
    ("jrivera", "Anchor2026", "sales"),
]

ANOMALY_USER = ("mchen", "Fallback_9", "engineering")

NORMAL_CALLS = [
    ("GET", "/api/v1/dashboard", "application/json"),
    ("GET", "/api/v1/notifications", "application/json"),
    ("GET", "/api/v1/profile", "application/json"),
    ("GET", "/api/v1/calendar/events", "application/json"),
    ("GET", "/api/v1/messages/inbox", "application/json"),
    ("GET", "/api/v1/directory/search?q=employee", "application/json"),
    ("GET", "/api/v1/timesheet", "application/json"),
    ("GET", "/api/v1/announcements", "application/json"),
    ("GET", "/api/v1/tasks", "application/json"),
    ("GET", "/api/v1/settings", "application/json"),
    ("POST", "/api/v1/tasks/update", "application/json"),
    ("POST", "/api/v1/timesheet/submit", "application/json"),
    ("GET", "/api/v1/helpdesk/tickets", "application/json"),
    ("GET", "/api/v1/org/chart", "application/json"),
]

# The "important paths for a financial directory and its report" that a
# handful of sessions will touch.
FINANCE_CALLS = [
    ("GET", "/finance/reports/Q3_2026_Revenue_Report.pdf", "application/pdf"),
    ("GET", "/finance/reports/Q3_2026_Expense_Summary.xlsx",
     "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    ("GET", "/finance/ledger/general_ledger_export.csv", "text/csv"),
    ("POST", "/api/v1/finance/payroll/export", "application/json"),
    ("GET", "/api/v1/finance/reports/list", "application/json"),
    ("GET", "/finance/audit/Q3_2026_Internal_Audit.pdf", "application/pdf"),
    ("GET", "/finance/budget/FY2026_Budget_Forecast.xlsx",
     "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
]


def portal_response_body(path, content_type):
    filename = path.rsplit("/", 1)[-1]
    if content_type == "application/pdf":
        return f"%PDF-1.4 ({filename} contents truncated for capture)"
    if content_type.endswith("spreadsheetml.sheet"):
        return f"PK\x03\x04 ({filename} contents truncated for capture)"
    if content_type == "text/csv":
        return ("account,description,debit,credit\n"
                "4010,Operating Revenue,0.00,182500.00\n"
                "5020,Payroll Expense,96400.00,0.00\n"
                "(remaining rows truncated for capture)")
    return '{"status": "ok"}'


def do_login(flow, username, password, cookie_token, fail_times=0):
    for _ in range(fail_times):
        flow.client_send(http_request(
            "POST", "/auth/login", PORTAL_HOST,
            headers={"User-Agent": PORTAL_UA, "Content-Type": "application/x-www-form-urlencoded"},
            body=f"username={username}&password=WrongPass123",
        ))
        flow.server_send(http_response(
            "401 Unauthorized", headers={"Content-Type": "application/json"},
            body='{"error": "invalid credentials"}',
        ))
    flow.client_send(http_request(
        "POST", "/auth/login", PORTAL_HOST,
        headers={"User-Agent": PORTAL_UA, "Content-Type": "application/x-www-form-urlencoded"},
        body=f"username={username}&password={password}",
    ))
    flow.server_send(http_response(
        "200 OK",
        headers={"Set-Cookie": f"SESSIONID={cookie_token}; Path=/; HttpOnly",
                 "Content-Type": "application/json"},
        body='{"status": "authenticated"}',
    ))


def do_logout(flow, cookie_token):
    flow.client_send(http_request(
        "POST", "/auth/logout", PORTAL_HOST,
        headers={"User-Agent": PORTAL_UA, "Cookie": f"SESSIONID={cookie_token}"},
    ))
    flow.server_send(http_response(
        "200 OK", headers={"Content-Type": "application/json"},
        body='{"status": "logged_out"}',
    ))


def build_user_session(pkts, t, user_ip, sport, username, password, calls,
                        fail_logins=0, think_time=(2.0, 20.0)):
    cookie_token = hashlib.md5(username.encode()).hexdigest()
    flow = TcpFlow(user_ip, PORTAL_IP, sport, PORTAL_PORT, t)
    flow.handshake()
    do_login(flow, username, password, cookie_token, fail_times=fail_logins)

    for method, path, content_type in calls:
        headers = {"User-Agent": PORTAL_UA, "Cookie": f"SESSIONID={cookie_token}"}
        body = ""
        if method == "POST":
            headers["Content-Type"] = "application/json"
            body = '{"note": "auto-generated request"}'
        flow.client_send(http_request(method, path, PORTAL_HOST, headers=headers, body=body))
        flow.server_send(http_response(
            "200 OK", headers={"Content-Type": content_type},
            body=portal_response_body(path, content_type),
        ))
        flow.t += random.uniform(*think_time)

    do_logout(flow, cookie_token)
    flow.graceful_close()
    pkts.extend(flow.pkts)
    return flow.t


def build_portal_activity_pcap(base_time, off_hours_time):
    pkts = []
    t = base_time

    finance_dept_users = {"afinance", "bpayroll"}
    typo_prone_users = {"csingh", "hyoung"}

    for idx, (username, password, _dept) in enumerate(PORTAL_USERS, start=1):
        user_ip = f"10.30.9.{100 + idx}"
        sport = 54000 + idx

        calls = [random.choice(NORMAL_CALLS) for _ in range(random.randint(12, 22))]
        if username in finance_dept_users:
            finance_subset = random.sample(FINANCE_CALLS, k=random.randint(3, 5))
            for fc in finance_subset:
                pos = random.randint(0, len(calls))
                calls.insert(pos, fc)

        fail_logins = 1 if username in typo_prone_users else 0

        t = build_user_session(pkts, t, user_ip, sport, username, password,
                                calls, fail_logins=fail_logins)
        t += random.uniform(60.0, 240.0)  # idle time before the next employee signs in

    # --- Anomaly: a non-finance account pulls sensitive ledger/payroll/audit
    #     files at an off-hours timestamp, clustered together rather than
    #     mixed into routine browsing. ---
    username, password, _dept = ANOMALY_USER
    user_ip = f"10.30.9.{100 + len(PORTAL_USERS) + 1}"
    sport = 54000 + len(PORTAL_USERS) + 1
    sensitive_targets = [
        ("GET", "/finance/ledger/general_ledger_export.csv", "text/csv"),
        ("POST", "/api/v1/finance/payroll/export", "application/json"),
        ("GET", "/finance/audit/Q3_2026_Internal_Audit.pdf", "application/pdf"),
    ]
    calls = [random.choice(NORMAL_CALLS) for _ in range(random.randint(2, 4))]
    calls[len(calls) // 2:len(calls) // 2] = sensitive_targets  # cluster them together mid-session

    build_user_session(pkts, off_hours_time, user_ip, sport, username, password,
                        calls, fail_logins=0)

    return pkts


def main():
    exfil_start = datetime(2026, 8, 20, 9, 14, 0, tzinfo=timezone.utc).timestamp()
    lifecycle_start = datetime(2026, 8, 21, 2, 5, 0, tzinfo=timezone.utc).timestamp()
    portal_start = datetime(2026, 8, 24, 9, 0, 0, tzinfo=timezone.utc).timestamp()
    portal_off_hours = datetime(2026, 8, 24, 23, 47, 0, tzinfo=timezone.utc).timestamp()

    exfil_pkts = build_exfiltration_pcap(exfil_start)
    lifecycle_pkts = build_temp_lifecycle_pcap(lifecycle_start)
    portal_pkts = build_portal_activity_pcap(portal_start, portal_off_hours)

    exfil_path = os.path.join(OUT_DIR, "data_exfiltration.pcap")
    lifecycle_path = os.path.join(OUT_DIR, "temp_file_lifecycle.pcap")
    portal_path = os.path.join(OUT_DIR, "portal_activity.pcap")

    wrpcap(exfil_path, exfil_pkts)
    wrpcap(lifecycle_path, lifecycle_pkts)
    wrpcap(portal_path, portal_pkts)

    print(f"Wrote {len(exfil_pkts)} packets to {exfil_path}")
    print(f"Wrote {len(lifecycle_pkts)} packets to {lifecycle_path}")
    print(f"Wrote {len(portal_pkts)} packets to {portal_path}")


if __name__ == "__main__":
    main()
