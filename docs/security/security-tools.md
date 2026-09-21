# AutoSOC — Security Tools Research

**Version:** 0.1.0  
**Owner:** Pranjal (Cybersecurity Pipeline)  
**Status:** Draft — Day 1  
**Last Updated:** 2026-09-21

---

## 1. Purpose

This document provides a reference for each security tool that AutoSOC integrates with or depends on. For each tool, it documents the tool's purpose, what it consumes and produces, how AutoSOC will use it, and at which pipeline stage it enters.

This is a **research and integration planning document** — no tool is implemented today.

---

## 2. Tool Summary Table

| Tool | Category | Layer | Role in AutoSOC |
|------|----------|-------|----------------|
| Sysmon | Endpoint telemetry | Ingestion | Process, network, file, registry events from Windows hosts |
| Zeek | Network traffic analysis | Ingestion | Protocol-level network logs from traffic capture |
| Suricata | Network IDS/IPS | Ingestion + Detection | Signature-based network alerts + raw flow data |
| Sigma | Detection rule format | Detection | Vendor-agnostic rule authoring and compilation |
| MITRE ATT&CK | Knowledge framework | Cross-cutting | Technique taxonomy for detection mapping, triage, reporting |

---

## 3. Sysmon

### 3.1 Purpose

Sysmon (System Monitor) is a free Windows system service and device driver developed by Microsoft Sysinternals. When installed on a Windows endpoint, it logs detailed security-relevant system activity to the Windows Event Log.

Sysmon is one of the highest-fidelity endpoint telemetry sources available for Windows without deploying a commercial EDR product. It is widely used in threat hunting, incident response, and detection engineering.

### 3.2 Input

Sysmon itself has no "input" in the traditional sense — it hooks into the Windows kernel and intercepts system calls:
- `NtCreateProcess` / `NtCreateUserProcess` (process creation)
- Kernel network callbacks (network connections)
- File system filter driver (file events)
- Registry callbacks (registry events)
- DNS client hooks (DNS queries)

Sysmon's **configuration** (XML config file) controls which events are captured and which are filtered. A high-quality Sysmon config (e.g., SwiftOnSecurity, Olaf Hartong's `sysmon-modular`) is critical to avoiding event volume overload while retaining high-fidelity detections.

**Key Sysmon configuration projects:**
- [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) — widely used baseline
- [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular) — modular, ATT&CK-aligned configuration

### 3.3 Output

Sysmon writes events to:
- **Windows Event Log channel:** `Microsoft-Windows-Sysmon/Operational`
- **Format:** Windows XML Event Log (EVTX)
- **Event IDs:** 1–29 (varies by Sysmon version; v15+ adds process tampering events)

Sysmon events are typically forwarded off-host via:
- **Winlogbeat** (Elastic) → Elasticsearch / Logstash
- **Windows Event Forwarding (WEF)** → central WEC server → Winlogbeat
- **NXLog** → various SIEM backends
- **Splunk Universal Forwarder** → Splunk

### 3.4 AutoSOC Integration

| Aspect | Detail |
|--------|--------|
| **Parser** | Pranjal will write a Sysmon XML → ParsedEvent parser |
| **Field mapping** | Documented in `security-event-model.md` §5.1 |
| **Normalized event types** | `process.create`, `process.terminate`, `process.inject`, `network.connection`, `network.dns`, `file.create`, `file.modify`, `file.delete`, `registry.*` |
| **Sigma rules** | Sysmon is the primary backend for most Windows Sigma rules; AutoSOC will compile Sigma rules targeting Sysmon field names |
| **High-value events for detection** | EventID 1 (process.create + command line), EventID 3 (network.connection), EventID 8 (CreateRemoteThread = injection), EventID 22 (DNS) |
| **Deployment for testing** | Sysmon installed on lab Windows VM(s); events forwarded via Winlogbeat to pipeline |

### 3.5 Integration Stage

```
[Windows Endpoint with Sysmon] → [Winlogbeat] → [Ingestion Layer] → [Sysmon Parser] → [Normalization]
```

### 3.6 Known Limitations

- **Windows only** — no Linux/macOS equivalent in the Sysinternals suite
- **Volume** — a poorly tuned Sysmon config generates enormous event volume (EventID 3 especially)
- **No process memory** — Sysmon cannot inspect in-memory code; fileless malware after initial injection may evade it
- **Tamper risk** — sophisticated attackers can unload or reconfigure Sysmon; EventID 4 (service state) and EventID 16 (config change) should be monitored
- **Correlation gap** — Sysmon events are per-endpoint; cross-host correlation requires the pipeline
- **No raw traffic** — complements but does not replace Zeek/Suricata for network visibility

---

## 4. Zeek

### 4.1 Purpose

Zeek (formerly Bro) is an open-source network analysis framework. Unlike Suricata (signature-based), Zeek performs **protocol analysis** — it reassembles TCP streams, parses application-layer protocols, and produces structured logs for every observed network activity.

Zeek is the gold standard for network visibility in academic and enterprise SOC environments. It is highly programmable via its scripting language.

### 4.2 Input

- **Network traffic capture** via:
  - SPAN/mirror port on a managed switch
  - Network TAP (passive optical or copper tap)
  - `libpcap` on a network interface in promiscuous mode
  - PF_RING, AF_PACKET, DPDK for high-throughput environments
- **PCAP files** for offline/retrospective analysis (critical for dataset evaluation)

**For AutoSOC evaluation:** Zeek will process PCAP files from datasets (CIC-IDS2017, UNSW-NB15, etc.) to generate structured logs for pipeline testing.

### 4.3 Output

Zeek produces a directory of **tab-separated log files** (or JSON with `@load tuning/json-logs`):

| Log File | Content |
|----------|---------|
| `conn.log` | All TCP/UDP/ICMP connections: 5-tuple + bytes + duration + state |
| `dns.log` | DNS queries and responses |
| `http.log` | HTTP requests and responses |
| `ssl.log` | TLS handshake details (SNI, cert subject, cipher) |
| `x509.log` | Certificate details |
| `files.log` | Files transferred over network (with hash) |
| `smtp.log` | SMTP email activity |
| `ssh.log` | SSH connections |
| `rdp.log` | RDP sessions |
| `smb_files.log` | SMB file transfer |
| `weird.log` | Protocol anomalies |
| `notice.log` | Zeek-generated alerts (from Zeek scripts) |
| `packet_filter.log` | BPF filter applied |

### 4.4 AutoSOC Integration

| Aspect | Detail |
|--------|--------|
| **Parser** | Pranjal will write Zeek log → ParsedEvent parsers (one per log type, or a unified JSON parser) |
| **Field mapping** | Documented in `security-event-model.md` §5.2 |
| **Normalized event types** | `network.connection`, `network.dns`, `network.http`, `alert.ids` |
| **Use in evaluation** | Process PCAP files from benchmark datasets through Zeek to generate `conn.log`, `dns.log`, etc. for pipeline testing |
| **Zeek scripting** | Custom Zeek scripts for DGA detection, beaconing detection, and long-connection detection to be developed (Day 3+) |
| **Deployment** | Zeek runs on a Linux sensor (VM or container) with NIC in promiscuous mode or fed PCAP files |

### 4.5 Integration Stage

```
[Network Traffic / PCAP] → [Zeek] → [Zeek log files (JSON)] → [Ingestion Layer] → [Zeek Parser] → [Normalization]
```

### 4.6 Known Limitations

- **No packet payload** — Zeek logs protocol metadata, not payload bytes; DPI at payload level requires custom scripting or integration with other tools
- **Encrypted traffic (TLS 1.3)** — TLS 1.3 with ESNI limits visibility; SNI still available but certificate details may not be
- **PCAP file size** — high-speed links produce enormous PCAP files; storage is a practical concern for dataset evaluation
- **No signatures** — Zeek does not do signature-based detection out of the box (notices are scripted, not signature-based)
- **Learning curve** — Zeek scripting language is powerful but non-trivial; complex scripts require dedicated development

---

## 5. Suricata

### 5.1 Purpose

Suricata is a high-performance, open-source network threat detection engine that functions as an Intrusion Detection System (IDS), Intrusion Prevention System (IPS), and Network Security Monitor (NSM).

Suricata uses **signature-based detection** — it matches network traffic against a library of rules and generates alerts. It complements Zeek's protocol-analysis approach by providing immediate, rule-driven alert generation.

Suricata is maintained by the Open Information Security Foundation (OISF).

### 5.2 Input

- **Live traffic:** Same as Zeek — SPAN port, TAP, or promiscuous mode NIC
- **IPS mode:** Inline between network segments via `nfqueue` or `af-packet` with `--simulate-ips`
- **PCAP files:** `suricata -r <file.pcap>` for offline analysis
- **Rule sets:**
  - [Emerging Threats Open (ET Open)](https://rules.emergingthreats.net/) — free, community-maintained
  - [Emerging Threats Pro (ET Pro)](https://www.proofpoint.com/us/products/advanced-threat-protection/et-pro-ruleset) — commercial
  - [Snort rules](https://www.snort.org/downloads/#rule-downloads) — compatible with Suricata
  - Custom rules authored in Suricata rule format

### 5.3 Output

Suricata's primary output is the **EVE JSON log** (`/var/log/suricata/eve.json`):

```json
{
  "timestamp": "2026-09-21T06:55:03.123456+0000",
  "flow_id": 1234567890,
  "in_iface": "eth0",
  "event_type": "alert",
  "src_ip": "192.168.1.45",
  "src_port": 54321,
  "dest_ip": "203.0.113.10",
  "dest_port": 4444,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2027865,
    "rev": 3,
    "signature": "ET MALWARE Agent Tesla Exfiltration",
    "category": "Malware Command and Control Activity",
    "severity": 1
  },
  "host": "sensor-lan01"
}
```

Additional EVE log event types: `flow`, `dns`, `http`, `tls`, `fileinfo`, `anomaly`, `stats`.

Suricata also produces:
- `fast.log` — human-readable one-line alerts
- `stats.log` — performance statistics
- `suricata.log` — service log

### 5.4 AutoSOC Integration

| Aspect | Detail |
|--------|--------|
| **Parser** | Pranjal will write Suricata EVE JSON → ParsedEvent parser |
| **Field mapping** | Documented in `security-event-model.md` §5.3 |
| **Normalized event types** | `alert.ids` (primary), `network.connection`, `network.dns`, `network.http` |
| **Rule management** | ET Open rules enabled by default; custom rules for AutoSOC-specific detections developed separately |
| **Alert → pipeline** | EVE JSON tailed by Filebeat → ingestion → Suricata parser → normalization |
| **Use in evaluation** | Run Suricata on PCAP files from benchmark datasets; compare Suricata alerts to dataset ground-truth labels |
| **IPS mode** | Not planned for Day 1; future for active response scenarios |

### 5.5 Integration Stage

```
[Network Traffic / PCAP] → [Suricata] → [EVE JSON (eve.json)] → [Filebeat/tail] → [Ingestion] → [Suricata Parser] → [Normalization]
```

### 5.6 Known Limitations

- **Rule quality varies** — ET Open rules have significant false-positive rates in enterprise environments; tuning required
- **Encrypted traffic** — like Zeek, cannot inspect encrypted payloads without TLS decryption
- **Signature coverage lag** — novel/zero-day attacks may not have rules; ML complementarity is essential
- **Performance tuning** — Suricata requires careful tuning (worker threads, memory, rule sets) for high-throughput links
- **No endpoint visibility** — Suricata sees only network traffic; complements but does not replace Sysmon

---

## 6. Sigma

### 6.1 Purpose

Sigma is a **generic, vendor-agnostic signature format** for log-based detection. It allows security researchers and detection engineers to write detection rules once in YAML format, then compile them to queries for any supported SIEM or log analysis backend.

Sigma rules describe **what to detect** (field conditions) without specifying **how to query** (backend-specific syntax). This separation is critical for AutoSOC, which aims to be backend-agnostic.

Sigma is maintained as an open-source project on GitHub: [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma).

### 6.2 Input

**Sigma rule (YAML):**

```yaml
title: Suspicious Encoded PowerShell Command
id: f3dbd234-5e8a-4b21-a9c3-deadbeef1234
status: experimental
description: Detects execution of PowerShell with encoded command argument, commonly used in malware droppers and post-exploitation tools.
references:
  - https://attack.mitre.org/techniques/T1059/001/
author: AutoSOC Team
date: 2026/09/21
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID: 1
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc '
      - '-ec '
  condition: selection
falsepositives:
  - Legitimate administrative scripts using encoded commands
level: high
```

**pySigma** is the Python library used to parse Sigma rules and compile them to backend queries.

### 6.3 Output

**Compiled Elasticsearch query (example):**
```json
{
  "query": {
    "bool": {
      "must": [
        {"term": {"winlog.event_id": 1}},
        {"bool": {"should": [
          {"wildcard": {"process.command_line": "*-EncodedCommand*"}},
          {"wildcard": {"process.command_line": "*-enc *"}},
          {"wildcard": {"process.command_line": "*-ec *"}}
        ]}}
      ]
    }
  }
}
```

**Other supported backends:** Splunk SPL, Microsoft Sentinel KQL, OpenSearch, Kibana, Chronicle, QRadar, and more.

### 6.4 AutoSOC Integration

| Aspect | Detail |
|--------|--------|
| **Rule language** | Sigma YAML; AutoSOC rules authored against normalized field names |
| **Backend** | pySigma compiles to Elasticsearch DSL (initial); other backends added as needed |
| **Normalized field mapping** | Sigma rules will use AutoSOC-normalized field names (e.g., `process`, `command_line`, `event_type`) not Sysmon-native names |
| **Community rules** | SigmaHQ/sigma-rules curated and imported; filtered by product and confidence level |
| **Custom rules** | AutoSOC-specific rules in `rules/sigma/autosoc/` directory |
| **Rule updates** | CI/CD pipeline pulls new Sigma releases; requires review before production deployment |
| **ATT&CK mapping** | Sigma tags (`attack.t1059.001` etc.) directly map to MITRE ATT&CK; used to populate `metadata.mitre_techniques` |
| **Rule evaluation in pipeline** | Compiled Sigma queries run against normalized event store; matches → DetectionResult |

### 6.5 Integration Stage

```
[Sigma YAML Rules] → [pySigma compiler] → [Backend queries (ES DSL)] → [Detection Layer: Rule-Based] → [Alert Generation]
```

### 6.6 Known Limitations

- **Schema dependency** — Sigma rules compiled for one log schema (e.g., Winlogbeat index) may not match AutoSOC's normalized schema without a field mapping layer
- **pySigma backends vary in maturity** — some backends have incomplete feature support
- **No temporal/behavioral detection** — Sigma rules evaluate single events; cannot express "more than 5 failed logins in 10 minutes" natively (requires pipeline aggregation)
- **False positive tuning** — community rules often need field-value tuning for specific environments
- **Rule conflicts** — multiple rules may match the same event; priority and suppression logic required

---

## 7. MITRE ATT&CK

### 7.1 Purpose

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. It is the de facto standard taxonomy for threat-informed defense.

ATT&CK provides:
- A structured taxonomy of **Tactics** (the adversary's goal) and **Techniques** (how they achieve it)
- **Sub-techniques** for granular behavior description
- **Procedure examples** linking techniques to real-world threat groups
- **Mitigations** and **Detections** per technique

AutoSOC uses ATT&CK as the **lingua franca** across all pipeline components and user-facing outputs.

**Frameworks:**
- **ATT&CK for Enterprise** (Windows, Linux, macOS, Cloud, Network) — primary for AutoSOC
- **ATT&CK for ICS** — future, if ICS/OT telemetry is added
- **ATT&CK for Mobile** — out of scope for v1

**Current version:** MITRE ATT&CK v16 (as of late 2024; check [attack.mitre.org](https://attack.mitre.org) for latest)

### 7.2 Input

ATT&CK is a knowledge base, not a tool. It is consumed via:
- **STIX 2.1 bundles** — machine-readable JSON format; published by MITRE at [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data)
- **ATT&CK Python library (`mitreattack-python`)** — programmatic access to ATT&CK data
- **Navigator** — ATT&CK Navigator is a web app for coverage visualization; AutoSOC dashboard (Shreyash) will integrate ATT&CK Navigator layers
- **API** — TAXII server at `https://attack-taxii.mitre.org`

### 7.3 Output

ATT&CK data provides:
- Technique IDs (e.g., `T1059.001` = PowerShell)
- Tactic names (e.g., Execution, Persistence, Lateral Movement)
- Data sources per technique (e.g., "Process: Process Creation" maps to Sysmon EventID 1)
- Detection guidance per technique
- Associated threat groups and software

### 7.4 AutoSOC Integration

ATT&CK permeates all layers of AutoSOC:

| Layer | ATT&CK Usage |
|-------|-------------|
| **Normalization** | `metadata.mitre_techniques` populated by rule matches |
| **Sigma rules** | Each rule tagged with ATT&CK technique IDs |
| **Suricata rules** | ET Open rules include ATT&CK metadata in rule `metadata` field |
| **Alert generation** | Alerts carry `mitre_tactics` and `mitre_techniques` |
| **Incident triage** | LLM agent references ATT&CK technique descriptions to explain attacker behavior |
| **RAG store (future)** | ATT&CK technique pages, detection notes, and procedure examples ingested into vector store for LLM retrieval |
| **Dashboard (Shreyash)** | ATT&CK Navigator heatmap of detection coverage; technique-level drill-down |
| **Evaluation** | Detection coverage mapped to ATT&CK matrix; identify gaps |

**Specific integration tasks:**
1. Load ATT&CK STIX bundle at startup; build in-memory technique → {tactic, description, data_sources, detection_notes} index
2. Alert enrichment: add ATT&CK tactic names from technique IDs
3. RAG ingestion: each technique's description + detection notes as a document chunk
4. Navigator layer generation: produce ATT&CK Navigator JSON from detection coverage

### 7.5 Integration Stage

```
[MITRE ATT&CK STIX Bundle] → [ATT&CK index in memory/DB] → [Normalization] → [Alert enrichment] → [LLM RAG store] → [Dashboard]
```

### 7.6 Known Limitations

- **ATT&CK is descriptive, not prescriptive** — it documents observed behaviors, not a complete catalog of all possible techniques
- **Version drift** — techniques are added, deprecated, and modified across versions; pipeline must track ATT&CK version
- **Sub-technique granularity** — some detections map to multiple sub-techniques; many-to-many relationship requires careful modeling
- **Detection coverage gaps** — many ATT&CK techniques have no reliable automated detection (only manual investigation or forensic artifacts)
- **Mapping quality** — Sigma rule ATT&CK tags vary in accuracy; community-contributed tags should be reviewed

---

## 8. Tool Interaction Matrix

| | Sysmon | Zeek | Suricata | Sigma | ATT&CK |
|--|--------|------|----------|-------|--------|
| **Sysmon** | — | Complementary (endpoint vs. network) | Complementary | Primary Windows rule target | Technique tags in rules |
| **Zeek** | Complementary | — | Parallel network visibility | Network rule target | Technique tags in notices |
| **Suricata** | Complementary | Parallel | — | Alert enrichment | ET rules have ATT&CK metadata |
| **Sigma** | Consumes Sysmon events | Consumes Zeek logs | Complements (different layer) | — | Tags each rule |
| **ATT&CK** | Data sources include Sysmon | Data sources include Zeek | Maps to network techniques | Rules tagged with ATT&CK | — |

---

## 9. Future Tools (Not Day 1)

| Tool | Category | Planned Role |
|------|----------|-------------|
| **MISP** | Threat Intelligence Platform | IOC sharing, TI feed management |
| **OpenCTI** | CTI Platform | Structured threat intelligence, threat actor tracking |
| **TheHive** | Incident Response Platform | Case management integration |
| **Velociraptor** | DFIR / EDR | Live endpoint forensics for incident investigation |
| **Elastic Stack** | Storage + Search | Primary backend for event storage and search |
| **OpenSearch** | Storage + Search | Alternative to Elastic Stack |
| **pySigma** | Rule compilation | Sigma → Elasticsearch query compilation |
| **Yara** | Malware signature | File-based malware scanning integration |

---

*Document maintained by Pranjal. Tool versions and integration specifics to be updated as implementation progresses.*
