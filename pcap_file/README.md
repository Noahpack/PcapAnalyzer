# PCAP Investigation Lab

This folder contains synthetic packet captures built for manual investigation
practice in Wireshark. Every host, IP address, and credential in these files
is fictional (internal hosts use RFC 1918 ranges, external hosts use RFC 5737
documentation ranges) — nothing here touches or resolves to a real network.

Your job for each file is the same as a real analyst's: open it cold, form a
timeline, and answer the investigation questions using only evidence you can
point to in the capture (frame numbers, filters, stream contents).

## Files
- `data_exfiltration.pcap` — insider document access + outbound transfer attempts
- `temp_file_lifecycle.pcap` — temp file churn + multi-port backup transfer
- `portal_activity.pcap` — large sign-in/sign-out log with API activity (1,400+ packets)
- `IT6300FE.pcap` — course-provided capture (see original assignment materials)

## Getting Started
1. Open a file in Wireshark: `File > Open`, or `wireshark <file>.pcap` from a terminal.
2. Get the lay of the land before filtering anything:
   - `Statistics > Conversations` — every host pair and how much they talked.
   - `Statistics > Endpoints` — every distinct IP/port involved.
   - `Statistics > Protocol Hierarchy` — what protocols are present.
3. All traffic in these captures is plaintext HTTP-like traffic on top of TCP
   (no TLS), so payloads are fully readable — that's intentional, to let you
   practice reading requests/responses directly.
4. Right-click any packet and choose `Follow > TCP Stream` to read an entire
   request/response conversation as text, in order.

## Scenario 1: `data_exfiltration.pcap`
**Setup:** Security flagged unusual outbound activity from a single
workstation and wants to know what happened.

**Investigate:**
1. What internal server did the workstation authenticate to, and how? Is
   the login secure? What does that imply about anyone who can sniff this
   traffic?
2. List every document the workstation successfully retrieved. What made
   them sensitive?
3. After the downloads, the workstation tries to send data to hosts outside
   the internal network. How many distinct attempts are there, and to which
   destinations/ports?
4. For each outbound attempt, determine the outcome and the *mechanism* of
   failure/success. Not all failures look the same — some are blocked, some
   are unreachable, some just go quiet. Use TCP flags and timing to tell
   them apart.
5. One blocked destination is targeted more than once. What does that
   suggest about the actor's intent?

**Wireshark tips:**
- `http.request.method == "POST"` and `http.request.method == "GET"` to
  separate uploads from downloads.
- `ip.addr == 10.20.5.0/24` (internal) vs. everything else to spot
  destinations that are not part of the internal network.
- `tcp.flags.syn == 1 && tcp.flags.ack == 0` to find every connection
  attempt, then check whether each one ever got a `SYN, ACK` reply.
- `tcp.flags.reset == 1` to find resets, and check which side (client or
  server) sent each one — that tells you who gave up, or who actively
  rejected the connection.
- Compare the time gap between a request and the next packet in slow
  connections — a long gap before a client-sent RST is a strong sign of an
  application-level timeout rather than a network block.
- `Follow > TCP Stream` on the login connection and on each outbound attempt
  to read the full HTTP request/response text, including headers.

## Scenario 2: `temp_file_lifecycle.pcap`
**Setup:** An automation/service account's traffic pattern looks unusual —
lots of short-lived files being created and removed — and you're asked to
determine whether it's benign housekeeping or something worth escalating.

**Investigate:**
1. What HTTP methods does this host use to create, verify, and remove files?
   (Hint: it is not limited to GET/POST — if you use `breakdown_packets_scanner.py`
   from the parent folder, notice which requests it silently skips, and why.)
2. How many create/verify/delete cycles occur, and roughly how far apart are
   they in time? Does the pattern look automated or manual?
3. Separately, the same host also transfers a multi-part backup archive to
   another server. How many parts are there, and what destination port does
   each part use?
4. Do all parts of the backup transfer succeed? How can you tell from the
   TCP/HTTP evidence alone?
5. Write one sentence arguing this traffic is benign, and one sentence
   arguing it could be malicious staging behavior. What additional context
   (outside this pcap) would help you decide?

**Wireshark tips:**
- `http.request.method == "PUT"` and `http.request.method == "DELETE"` —
  Wireshark's dissector recognizes these even though the repo's sample
  Python scripts don't. This is a good opportunity to extend
  `breakdown_packets_scanner.py` yourself.
- `Statistics > Conversations > TCP` tab, sorted by port, to see every
  distinct destination port used by the same source host.
- `tcp.stream eq N` to isolate one connection at a time and step through it
  in order.
- Compare `frame.time_delta` between cycles to characterize the interval.

## Scenario 3: `portal_activity.pcap`
**Setup:** IT wants an access audit of the corporate portal: who signed in,
who signed out, and — critically — who touched anything under the finance
directory.

This file is intentionally large (1,400+ packets) to simulate a realistic
volume of "normal noise" that the interesting activity is hidden inside.
Filtering efficiently is the whole point of this scenario.

**Investigate:**
1. Build a simple registry: for each user session, capture username,
   sign-in time, sign-out time, and source IP. (Tip: you don't need to do
   this by hand for all of them — filter first, then sample.)
2. Are there any failed login attempts? Which accounts, and how many?
3. Filter for any request path under `/finance` or `/api/v1/finance`. Which
   users touched these paths, and what did each of them access?
4. Most finance-path access should correlate with a specific department.
   Does every session that touches finance data fit that pattern? Find the
   one that doesn't.
5. For the session you flagged in (4), look at: the time of day, how many
   other requests happened in that session, and how the sensitive requests
   are positioned relative to the rest of the session's traffic. Does it
   look like incidental browsing or a targeted pull?

**Wireshark tips:**
- `http.request.uri contains "finance"` is your fastest way to cut through
  the noise in a 1,400-packet file.
- `http.request.uri == "/auth/login" || http.request.uri == "/auth/logout"`
  to build the sign-in/sign-out registry.
- `http.response.code == 401` to find failed login attempts.
- `http.cookie` (or `http.set_cookie` on responses) lets you correlate every
  request in a session back to the same `SESSIONID`, even across a
  persistent connection.
- Sort the packet list by `frame.time` (default) and pay attention to
  timestamps that fall well outside normal business hours.
- `Statistics > HTTP > Requests` gives you a quick frequency count of every
  URI requested — sensitive paths that are hit rarely will stand out from
  routine API calls that repeat constantly.

## General Wireshark Techniques Worth Practicing
- **Display filters vs. capture filters:** everything above is a *display*
  filter, applied after the fact — you don't need to know what you're
  looking for before opening the file.
- **Follow > TCP Stream:** the fastest way to read a full conversation as
  text instead of packet-by-packet.
- **Statistics > Conversations / Endpoints:** your first stop in any unknown
  capture, to understand who is talking to whom before you filter.
- **`tcp.analysis.flags`:** surfaces retransmissions, duplicate ACKs, and
  other anomalies Wireshark detects automatically.
- **File > Export Objects > HTTP:** extracts any transferred file-like
  content from HTTP traffic in one step.
- **Coloring rules:** customize them (or use the defaults) to make resets,
  retransmissions, and errors visually obvious while scrolling.
- **Ctrl+F (Find Packet) with "String" scope set to "Packet bytes":** useful
  for locating a specific filename, username, or keyword when you don't
  know which field it's in.

## Suggested Deliverable
For each scenario, write a short incident-style report containing:
1. A timeline of key events (with frame numbers/timestamps as evidence).
2. The accounts, hosts, and files/paths involved.
3. Your assessment: benign, suspicious, or malicious — and why.
4. One recommendation for what you'd do next (block, alert, escalate,
   ignore) if this were a real environment.

You can validate your manual findings against the parent folder's
`pcap_scanner.py` and `breakdown_packets_scanner.py`, but note they only
recognize `GET`/`POST` requests — some of what you need to find in these
scenarios (e.g. `PUT`/`DELETE` traffic) requires reading the capture
directly in Wireshark, or extending those scripts yourself.
