# 10_Detections
This repository contains 10 different alerts detections using security onion.

🧭  Security Onion Investigation Roadmap 

Each level builds practical SOC and incident response skills.

---

🔹  Level 1: Network Traffic & Basic Alerts 

 Goal:  Get comfortable with Zeek, Suricata, and Kibana dashboards.

 🧩 Scenario 1 — Suspicious DNS Traffic

*  Attack simulation:  Use `nslookup` or `dig` to query weird domains like `malicious-example.ru`.
*  Where to look: 

  * Zeek DNS logs (`/nsm/bro/logs/current/dns.log`)
  * Kibana → “Zeek DNS” dashboard
*  Investigate: 

  * What domain was queried?
  * What IP was returned?
  * Was it contacted later via HTTP/HTTPS?

     🧩 Scenario 2 — Port Scanning (Reconnaissance)

*  Attack simulation:  Run `nmap -sS -p 1-1024 <SO-monitored-host>`
*  Investigate: 

  * Identify the source IP (attacker).
  * Check Zeek’s `conn.log` and `notice.log`.
  * Create a detection rule for scan behavior (multiple ports in short time).

---

🔹  Level 2: Web-based Attacks 

 Goal:  Learn HTTP/IDS correlation.

🧩 Scenario 3 — SQL Injection Simulation

*  Attack simulation:  Use `sqlmap` against a test web app (like DVWA or Mutillidae in your lab).
*  Investigate: 

  * Check Suricata alerts for SQLi signatures.
  * Look at Zeek `http.log` — what payloads were sent?
  * Pivot in Kibana from alert → network flow → HTTP request.

🧩 Scenario 4 — Cross-Site Scripting (XSS)

*  Attack simulation:  Inject simple payloads like `<script>alert(    XSS    )</script>` on a DVWA page.
*  Investigate: 

  * Search HTTP logs for suspicious `<script>` tags.
  * Correlate alerts from Suricata.

---

🔹  Level 3: Malware Command & Control (C2) 

 Goal:  Analyze post-exploitation network patterns.

🧩 Scenario 5 — Beaconing Behavior

*  Attack simulation:  Use `Metasploit` with `meterpreter` beacon to another VM.
*  Investigate: 

  * In Zeek `conn.log`, spot periodic traffic.
  * Use Kibana visualizations to plot frequency and size.
  * Correlate with Suricata alerts.

🧩 Scenario 6 — File Download via HTTP

*  Attack simulation:  Download a sample malware (e.g., EICAR test file).
*  Investigate: 

  * Detect file transfer using Zeek `files.log`.
  * Confirm Suricata alert for potential malware.
  * Check MD5/SHA1 hashes of the file.

---

🔹  Level 4: Endpoint + Network Correlation 

 Goal:  Combine Wazuh host logs and network indicators.

🧩 Scenario 7 — Brute Force Attack

*  Attack simulation:  Run Hydra or Medusa to brute-force SSH or web login.
*  Investigate: 

  * Check Wazuh for failed logins.
  * Check Zeek/Suricata for repeated connections.
  * Correlate both to confirm brute-force pattern.

🧩 Scenario 8 — Privilege Escalation Attempt

*  Attack simulation:  Simulate user privilege escalation with `sudo su` or by editing system files.
*  Investigate: 

  * Wazuh → Alerts for privilege escalation.
  * Correlate with recent inbound connections.

---

🔹  Level 5: Full Incident Response Simulation 

 Goal:  Conduct a full-cycle SOC investigation.

🧩 Scenario 9 — Compromised Host Investigation

* Simulate: phishing or malware infection using test payloads.
* Steps:

  1. Detect unusual outbound traffic.
  2. Correlate endpoint and network data.
  3. Extract artifacts (PCAPs, hashes, domains).
  4. Build a mini report.

🧩 Scenario 10 — Threat Hunting Challenge

* Use Zeek + Kibana to proactively hunt:

  * Unusual user agents
  * Suspicious SSL certificates
  * Connections to newly registered domains

