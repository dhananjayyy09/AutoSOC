# AutoSOC — Normalized Security Event Model

**Version:** 0.1.0  
**Owner:** Pranjal (Cybersecurity Pipeline)  
**Status:** Draft — Day 1  
**Last Updated:** 2026-09-21

---

## 1. Purpose

AutoSOC ingests telemetry from diverse sources — endpoint detection, network traffic analysis, and intrusion detection systems. Each source uses its own schema, naming conventions, and field semantics.

The **Normalized Security Event Model** defines a common, source-agnostic schema that all incoming events are mapped into before entering the detection pipeline. This enables:

- Unified rule authoring across sources (Sigma-compatible)
- Cross-source correlation without source-specific logic in detection rules
- Consistent feature vectors for ML models
- Source-agnostic alert generation and triage
- Reproducible evaluation across datasets

> **Design principle:** Not every field will be present in every event. Fields are classified as *required*, *optional*, *derived*, or *source-specific*. The pipeline must handle missing fields gracefully — absent optional fields are stored as `null`, never as empty strings or default values.

---

## 2. Field Classification

| Class | Meaning |
|-------|---------|
| **Required** | Must be present in every normalized event; pipeline rejects events missing these |
| **Optional** | Present in many but not all sources; stored as `null` when absent |
| **Derived** | Not directly from the raw event; computed during normalization (e.g., from IP geolocation, DNS resolution, hash lookup) |
| **Source-specific** | Meaningful only for a particular telemetry source; stored in the `metadata` bag rather than top-level fields |

---

## 3. Core Schema

```json
{
  "event_id":           "<string>",
  "timestamp":          "<ISO 8601 UTC>",
  "source":             "<string>",
  "event_type":         "<string>",
  "host":               "<string>",
  "user":               "<string | null>",
  "source_ip":          "<IPv4 | IPv6 | null>",
  "destination_ip":     "<IPv4 | IPv6 | null>",
  "source_port":        "<integer 0–65535 | null>",
  "destination_port":   "<integer 0–65535 | null>",
  "protocol":           "<string | null>",
  "process":            "<string | null>",
  "file_hash":          "<string | null>",
  "domain":             "<string | null>",
  "command_line":       "<string | null>",
  "severity":           "<integer 1–5>",
  "raw_event":          "<string>",
  "metadata":           "<object>"
}
```

---

## 4. Field Definitions

### 4.1 `event_id`

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Classification** | Required |
| **Format** | UUID v4 (`xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`) |
| **Description** | Globally unique identifier assigned by the AutoSOC normalization layer. Never taken directly from the source. Source-assigned IDs (e.g., Sysmon EventRecordID) are preserved in `metadata`. |
| **Example** | `"a3f1e290-7d4c-4e8a-9b0f-123456789abc"` |

---

### 4.2 `timestamp`

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Classification** | Required |
| **Format** | ISO 8601 with UTC timezone — `YYYY-MM-DDTHH:MM:SS.sssZ` |
| **Description** | UTC time the event occurred (not the time it was ingested). Sources that provide local time must have timezone offsets applied during normalization. When sub-second precision is available it must be preserved. Ingestion time is stored separately in `metadata.ingest_time`. |
| **Example** | `"2026-09-21T06:42:17.334Z"` |
| **Notes** | Clock skew between sources is a known issue; future versions will implement NTP-aware correction. |

---

### 4.3 `source`

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Classification** | Required |
| **Allowed Values** | `sysmon`, `zeek`, `suricata`, `windows_event_log`, `auditd`, `osquery`, `custom` |
| **Description** | Identifies the telemetry source that produced the raw event. Determines which source-specific normalization mapping is applied. |
| **Example** | `"sysmon"` |

---

### 4.4 `event_type`

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Classification** | Required |
| **Format** | Snake_case category, dot-separated for subtypes |
| **Description** | Normalized event category. Decoupled from the source's own event codes. Enables cross-source rule authoring. |
| **Allowed Values (initial set)** | See table below |
| **Example** | `"process.create"` |

**Normalized Event Type Taxonomy (v0.1)**

| Value | Covers |
|-------|--------|
| `process.create` | New process spawned |
| `process.terminate` | Process ended |
| `process.inject` | Memory injection detected |
| `network.connection` | TCP/UDP connection initiated or observed |
| `network.dns` | DNS query/response |
| `network.http` | HTTP/S request |
| `network.alert` | IDS/IPS network-layer alert |
| `file.create` | File created |
| `file.modify` | File modified |
| `file.delete` | File deleted |
| `file.rename` | File renamed |
| `registry.create` | Registry key/value created |
| `registry.modify` | Registry key/value modified |
| `registry.delete` | Registry key/value deleted |
| `auth.logon` | Authentication / logon event |
| `auth.logoff` | Logoff event |
| `auth.failure` | Failed authentication attempt |
| `alert.ids` | Signature-based IDS alert |
| `alert.anomaly` | ML or statistical anomaly detection alert |

---

### 4.5 `host`

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Classification** | Required |
| **Description** | The hostname or FQDN of the machine where the event originated. For network sensors (Zeek, Suricata) this is the hostname of the monitoring sensor, not a conversation endpoint. |
| **Example** | `"dc01.corp.local"` |

---

### 4.6 `user`

| Property | Value |
|----------|-------|
| **Type** | `string \| null` |
| **Classification** | Optional |
| **Description** | Username associated with the event. For process events, the user running the process. For auth events, the user attempting to authenticate. Not applicable for pure network flow events from Zeek/Suricata. Normalized to lowercase. Domain prefix stripped to `metadata.user_domain` if present. |
| **Example** | `"john.doe"` |

---

### 4.7 `source_ip`

| Property | Value |
|----------|-------|
| **Type** | `string \| null` |
| **Classification** | Optional |
| **Format** | Canonical IPv4 dotted-decimal or IPv6 compressed notation (RFC 5952) |
| **Description** | IP address initiating the connection or generating the event. For process events, null unless the process performed a network action. |
| **Example** | `"192.168.1.45"` |

---

### 4.8 `destination_ip`

| Property | Value |
|----------|-------|
| **Type** | `string \| null` |
| **Classification** | Optional |
| **Format** | Same as `source_ip` |
| **Description** | IP address receiving the connection. |
| **Example** | `"203.0.113.72"` |

---

### 4.9 `source_port`

| Property | Value |
|----------|-------|
| **Type** | `integer \| null` |
| **Classification** | Optional |
| **Range** | 0–65535 |
| **Description** | TCP/UDP source port. Null for non-network events. |
| **Example** | `54321` |

---

### 4.10 `destination_port`

| Property | Value |
|----------|-------|
| **Type** | `integer \| null` |
| **Classification** | Optional |
| **Range** | 0–65535 |
| **Description** | TCP/UDP destination port. |
| **Example** | `443` |

---

### 4.11 `protocol`

| Property | Value |
|----------|-------|
| **Type** | `string \| null` |
| **Classification** | Optional |
| **Allowed Values** | `tcp`, `udp`, `icmp`, `dns`, `http`, `tls`, `smtp`, `ftp`, `ssh`, `rdp`, `smb`, `other` |
| **Description** | Application or transport protocol. Normalized to lowercase. For Zeek logs the application-layer protocol is preferred when available. |
| **Example** | `"tcp"` |

---

### 4.12 `process`

| Property | Value |
|----------|-------|
| **Type** | `string \| null` |
| **Classification** | Optional |
| **Description** | Process name (basename of the executable, no path). Full path preserved in `metadata.process_path`. Parent process name in `metadata.parent_process`. |
| **Example** | `"powershell.exe"` |

---

### 4.13 `file_hash`

| Property | Value |
|----------|-------|
| **Type** | `string \| null` |
| **Classification** | Optional |
| **Format** | Hex-encoded digest. Algorithm indicated by prefix: `md5:`, `sha1:`, `sha256:`. SHA-256 preferred. |
| **Description** | Cryptographic hash of the primary file involved in the event. For process events, the hash of the executable image. For file events, the hash of the file. Multiple hashes stored in `metadata.hashes`. |
| **Example** | `"sha256:e3b0c44298fc1c149afb4c8996fb92427ae41e4649b934ca495991b7852b855"` |

---

### 4.14 `domain`

| Property | Value |
|----------|-------|
| **Type** | `string \| null` |
| **Classification** | Optional |
| **Format** | Fully qualified domain name, lowercase, without trailing dot |
| **Description** | Domain name relevant to the event. For DNS events, the queried domain. For network events, the SNI hostname from TLS or HTTP Host header. For process events, the domain the process contacted if resolved. |
| **Example** | `"malicious-c2.example.com"` |

---

### 4.15 `command_line`

| Property | Value |
|----------|-------|
| **Type** | `string \| null` |
| **Classification** | Optional |
| **Description** | Full command-line string used to invoke a process. Only available from endpoint sources (Sysmon EventID 1, auditd). Empty string and whitespace-only values stored as `null`. Sensitive arguments (passwords, tokens) are redacted by the normalization layer before storage. |
| **Example** | `"powershell.exe -NonInteractive -EncodedCommand JAB..."` |

---

### 4.16 `severity`

| Property | Value |
|----------|-------|
| **Type** | `integer` |
| **Classification** | Required |
| **Range** | 1 (informational) to 5 (critical) |
| **Description** | Normalized severity score assigned during normalization. Not taken directly from source severity levels (which differ across tools). Mapping from source-native severity to AutoSOC scale documented per source in Section 5. |

**Severity Scale**

| Level | Label | Meaning |
|-------|-------|---------|
| 1 | Informational | Audit/telemetry only, no threat signal |
| 2 | Low | Weak signal; unlikely to indicate compromise alone |
| 3 | Medium | Requires investigation; may be benign or malicious |
| 4 | High | Strong indicator of malicious activity |
| 5 | Critical | Confirmed or near-certain malicious activity |

---

### 4.17 `raw_event`

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Classification** | Required |
| **Description** | The original, unmodified raw event as received from the source, serialized as a string (JSON-encoded if the source format is JSON, XML-encoded if XML). Preserved for forensic replay and analyst review. Never modified after ingest. |
| **Max Length** | 65,536 bytes (64 KiB); events exceeding this are truncated with `metadata.raw_truncated: true` |

---

### 4.18 `metadata`

| Property | Value |
|----------|-------|
| **Type** | `object` |
| **Classification** | Required (may be empty object `{}`) |
| **Description** | Free-form bag for source-specific, derived, and enrichment fields. All fields not fitting the top-level schema go here. Structured sub-objects are encouraged over flat key blobs. |

**Standard `metadata` sub-keys (reserved)**

| Key | Type | Description |
|-----|------|-------------|
| `metadata.ingest_time` | ISO 8601 string | Time the event was received by AutoSOC ingestion |
| `metadata.pipeline_version` | string | Version of the normalization pipeline that processed this event |
| `metadata.source_event_id` | string | Original event ID from the source (e.g., Sysmon EventRecordID) |
| `metadata.source_severity` | string/int | Raw severity from source before normalization |
| `metadata.raw_truncated` | boolean | True if `raw_event` was truncated |
| `metadata.hashes` | object | Map of algorithm → hex digest (e.g., `{"md5": "...", "sha256": "..."}`) |
| `metadata.process_path` | string | Full filesystem path of the process executable |
| `metadata.parent_process` | string | Parent process name |
| `metadata.parent_pid` | integer | Parent process ID |
| `metadata.pid` | integer | Process ID |
| `metadata.user_domain` | string | Domain portion of a domain-qualified username |
| `metadata.geo` | object | GeoIP result: `{country, city, asn, org}` |
| `metadata.threat_intel` | object | TI enrichment result (future) |
| `metadata.mitre_techniques` | array of strings | MITRE ATT&CK technique IDs matched (e.g., `["T1059.001"]`) |
| `metadata.tags` | array of strings | Analyst or pipeline tags |

---

## 5. Source-Specific Field Mappings

> These mappings define how each telemetry source's native fields are translated to the normalized schema. Fields not listed here go into `metadata` with their original names preserved under `metadata.source_fields`.

---

### 5.1 Sysmon (Windows Endpoint)

**What Sysmon provides:** Sysmon (System Monitor) is a Windows service that logs detailed process creation, network connections, file hashing, registry changes, and other endpoint telemetry into the Windows Event Log.

**Event Log channel:** `Microsoft-Windows-Sysmon/Operational`  
**Format:** Windows XML Event Log (EVTX), typically forwarded via WEF or Winlogbeat → Elasticsearch.

#### Sysmon EventID Coverage

| Sysmon EventID | Description | AutoSOC `event_type` |
|---------------|-------------|----------------------|
| 1 | Process Create | `process.create` |
| 2 | File creation time changed | `file.modify` |
| 3 | Network Connection | `network.connection` |
| 4 | Sysmon service state changed | *(filtered, not normalized)* |
| 5 | Process Terminated | `process.terminate` |
| 6 | Driver Loaded | `file.create` |
| 7 | Image Loaded (DLL) | `file.create` |
| 8 | CreateRemoteThread | `process.inject` |
| 9 | RawAccessRead | `file.modify` |
| 10 | ProcessAccess | `process.inject` |
| 11 | FileCreate | `file.create` |
| 12 | RegistryEvent (key/value create/delete) | `registry.create` / `registry.delete` |
| 13 | RegistryEvent (value set) | `registry.modify` |
| 15 | FileCreateStreamHash | `file.create` |
| 22 | DNSEvent | `network.dns` |
| 23 | FileDelete | `file.delete` |
| 25 | ProcessTampering | `process.inject` |

#### Sysmon → AutoSOC Field Mapping

| Sysmon Field | AutoSOC Field | Notes |
|-------------|---------------|-------|
| `System.TimeCreated[@SystemTime]` | `timestamp` | Convert to UTC ISO 8601 |
| `System.Computer` | `host` | |
| `EventData.User` | `user` | Strip domain prefix to `metadata.user_domain` |
| `EventData.Image` | `process` | Basename only; full path → `metadata.process_path` |
| `EventData.CommandLine` | `command_line` | EventID 1 only |
| `EventData.Hashes` | `file_hash` | Parse `SHA256=...` from multi-hash string; full set → `metadata.hashes` |
| `EventData.DestinationIp` | `destination_ip` | EventID 3 only |
| `EventData.DestinationPort` | `destination_port` | EventID 3 only |
| `EventData.SourceIp` | `source_ip` | EventID 3 only |
| `EventData.SourcePort` | `source_port` | EventID 3 only |
| `EventData.Protocol` | `protocol` | EventID 3 only; normalize to lowercase |
| `EventData.QueryName` | `domain` | EventID 22 only |
| `EventData.ProcessId` | `metadata.pid` | |
| `EventData.ParentProcessId` | `metadata.parent_pid` | |
| `EventData.ParentImage` | `metadata.parent_process` | Basename only |
| `System.EventRecordID` | `metadata.source_event_id` | |

**Sysmon fields that are always source-specific (go to `metadata.source_fields`):**
`RuleName`, `TargetObject` (registry), `Details` (registry value), `Contents` (stream hash), `CurrentDirectory`, `IntegrityLevel`, `LogonId`, `LogonGuid`, `ProcessGuid`, `ParentCommandLine`, `FileVersion`, `Description`, `Product`, `Company`, `OriginalFileName`

**Severity mapping (Sysmon):**
Sysmon does not emit severity levels. AutoSOC assigns severity during normalization based on `event_type`:

| event_type | Default Severity |
|------------|-----------------|
| `process.inject`, `process.create` (suspicious) | 3 |
| `network.connection` | 2 |
| `network.dns` | 1 |
| `file.create`, `file.modify` | 1 |
| `registry.modify` | 2 |
| All others | 1 |

> Severity is further adjusted upward by detection rules and ML models downstream.

---

### 5.2 Zeek (Network Traffic Analysis)

**What Zeek provides:** Zeek (formerly Bro) is a network analysis framework that produces structured logs for protocol activity — `conn.log`, `dns.log`, `http.log`, `ssl.log`, `files.log`, `weird.log`, etc.

**Format:** Tab-separated values (TSV) or JSON, depending on configuration. Each log type has distinct fields.

#### Zeek Log Types → AutoSOC `event_type`

| Zeek Log | AutoSOC `event_type` |
|----------|----------------------|
| `conn.log` | `network.connection` |
| `dns.log` | `network.dns` |
| `http.log` | `network.http` |
| `ssl.log` / `tls.log` | `network.connection` |
| `files.log` | `file.create` (download) |
| `weird.log` | `network.alert` |
| `notice.log` | `alert.ids` |

#### Zeek → AutoSOC Field Mapping

| Zeek Field | AutoSOC Field | Applies To | Notes |
|-----------|---------------|------------|-------|
| `ts` | `timestamp` | All | Zeek uses Unix epoch float; convert to ISO 8601 UTC |
| `id.orig_h` | `source_ip` | conn, http, dns, ssl | |
| `id.orig_p` | `source_port` | conn, http, dns, ssl | |
| `id.resp_h` | `destination_ip` | conn, http, dns, ssl | |
| `id.resp_p` | `destination_port` | conn, http, dns, ssl | |
| `proto` | `protocol` | conn | Lowercase; `tcp`/`udp`/`icmp` |
| `service` | `protocol` | conn | Application-layer protocol override |
| `query` | `domain` | dns | |
| `host` | `domain` | http | HTTP `Host` header |
| `server_name` | `domain` | ssl | TLS SNI |
| `md5` / `sha1` | `file_hash` | files | SHA-256 preferred; store all in `metadata.hashes` |

**Fields stored in `metadata.source_fields` for Zeek:**
`uid` (Zeek connection UID), `conn_state`, `history`, `orig_bytes`, `resp_bytes`, `orig_pkts`, `resp_pkts`, `local_orig`, `local_resp`, `tunnel_parents`, `query_type`, `answers`, `rcode`, `method` (HTTP), `uri` (HTTP), `status_code` (HTTP), `user_agent`, `resp_mime_types`, `version` (SSL/TLS), `cipher`, `curve`, `subject`, `issuer`, `validation_status`

**`host` field for Zeek:**  
Zeek does not inherently know its own hostname; the sensor hostname must be injected at ingest time from configuration (e.g., the hostname of the machine running Zeek or the span port label).

**Severity mapping (Zeek):**
- `conn.log`, `dns.log`, `http.log`, `ssl.log` → severity `1` (telemetry)
- `weird.log` → severity `2`
- `notice.log` → severity mapped from Zeek notice `severity` field: `Notice` → 2, `Warning` → 3, `Critical` → 4

---

### 5.3 Suricata (Network IDS/IPS)

**What Suricata provides:** Suricata is a high-performance network IDS/IPS/NSM engine that matches traffic against signature rules (Emerging Threats, ET Pro, custom). Outputs structured EVE JSON logs.

**Format:** EVE JSON (`/var/log/suricata/eve.json`), newline-delimited JSON.

#### Suricata Event Types → AutoSOC `event_type`

| Suricata `event_type` | AutoSOC `event_type` |
|----------------------|----------------------|
| `alert` | `alert.ids` |
| `flow` | `network.connection` |
| `dns` | `network.dns` |
| `http` | `network.http` |
| `tls` | `network.connection` |
| `fileinfo` | `file.create` |
| `anomaly` | `alert.anomaly` |
| `netflow` | `network.connection` |

#### Suricata → AutoSOC Field Mapping

| Suricata Field | AutoSOC Field | Notes |
|---------------|---------------|-------|
| `timestamp` | `timestamp` | Already ISO 8601; verify UTC |
| `src_ip` | `source_ip` | |
| `dest_ip` | `destination_ip` | |
| `src_port` | `source_port` | |
| `dest_port` | `destination_port` | |
| `proto` | `protocol` | Normalize to lowercase |
| `dns.rrname` | `domain` | DNS query name |
| `http.hostname` | `domain` | HTTP Host header |
| `tls.sni` | `domain` | TLS SNI |
| `fileinfo.md5` / `fileinfo.sha256` | `file_hash` | |
| `alert.severity` | `severity` | See mapping below |
| `host` | `host` | Suricata sensor hostname |

**Fields stored in `metadata.source_fields` for Suricata:**
`flow_id`, `in_iface`, `alert.action` (allowed/blocked), `alert.gid`, `alert.signature_id`, `alert.rev`, `alert.signature`, `alert.category`, `alert.metadata`, `http.url`, `http.http_user_agent`, `http.status`, `http.length`, `tls.version`, `tls.subject`, `tls.issuerdn`, `tls.fingerprint`, `app_proto`, `flow.*` fields

**Suricata severity mapping:**

Suricata rules have a `priority` field (1 = highest, 4 = lowest):

| Suricata `alert.severity` / Priority | AutoSOC `severity` |
|--------------------------------------|-------------------|
| 1 (Critical) | 5 |
| 2 (Major) | 4 |
| 3 (Minor) | 3 |
| 4 (Informational) | 2 |
| Non-alert events | 1 |

---

## 6. Derived Fields

These fields are not taken from any raw event but are computed during or after normalization.

| Field (in `metadata`) | Source | Description |
|----------------------|--------|-------------|
| `metadata.geo` | GeoIP database (MaxMind GeoLite2) | Country, city, ASN, org derived from `source_ip` or `destination_ip` |
| `metadata.is_internal_src` | RFC 1918 / configured subnet list | Boolean: whether `source_ip` is in internal network space |
| `metadata.is_internal_dst` | RFC 1918 / configured subnet list | Boolean: whether `destination_ip` is in internal network space |
| `metadata.mitre_techniques` | Detection rule matches | MITRE ATT&CK technique IDs from fired rules |
| `metadata.threat_intel` | TI feed lookup (future) | Whether IPs/domains/hashes appear in threat intel feeds |
| `metadata.alert_id` | Pipeline (future) | ID of the alert generated from this event |

---

## 7. Canonical Example Events

### 7.1 Sysmon — Process Create (event_type: process.create)

```json
{
  "event_id": "f2a3e881-0b1c-4f7d-9a2e-deadbeef0001",
  "timestamp": "2026-09-21T06:42:17.334Z",
  "source": "sysmon",
  "event_type": "process.create",
  "host": "workstation-07.corp.local",
  "user": "john.doe",
  "source_ip": null,
  "destination_ip": null,
  "source_port": null,
  "destination_port": null,
  "protocol": null,
  "process": "powershell.exe",
  "file_hash": "sha256:aabbccdd...",
  "domain": null,
  "command_line": "powershell.exe -NonInteractive -EncodedCommand JABzAD0A...",
  "severity": 3,
  "raw_event": "<Event xmlns='...'><System>...</System><EventData>...</EventData></Event>",
  "metadata": {
    "ingest_time": "2026-09-21T06:42:18.001Z",
    "pipeline_version": "0.1.0",
    "source_event_id": "82341",
    "pid": 4288,
    "parent_process": "cmd.exe",
    "parent_pid": 3100,
    "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "user_domain": "CORP",
    "hashes": {
      "md5": "04029957f36c2f05b3b2cf77af3ae9d3",
      "sha256": "aabbccdd..."
    },
    "mitre_techniques": ["T1059.001"],
    "tags": []
  }
}
```

### 7.2 Suricata — IDS Alert (event_type: alert.ids)

```json
{
  "event_id": "c9b1a762-3e4f-4a81-b0c2-deadbeef0002",
  "timestamp": "2026-09-21T06:55:03.000Z",
  "source": "suricata",
  "event_type": "alert.ids",
  "host": "sensor-lan01",
  "user": null,
  "source_ip": "192.168.1.45",
  "destination_ip": "185.220.101.34",
  "source_port": 54321,
  "destination_port": 443,
  "protocol": "tcp",
  "process": null,
  "file_hash": null,
  "domain": "malicious-c2.example.com",
  "command_line": null,
  "severity": 4,
  "raw_event": "{\"timestamp\":\"2026-09-21T06:55:03\",\"event_type\":\"alert\",...}",
  "metadata": {
    "ingest_time": "2026-09-21T06:55:03.500Z",
    "pipeline_version": "0.1.0",
    "source_event_id": "flow_id:1234567890",
    "source_fields": {
      "alert": {
        "action": "allowed",
        "gid": 1,
        "signature_id": 2027865,
        "rev": 3,
        "signature": "ET MALWARE Potential C2 Domain",
        "category": "Malware Command and Control Activity"
      },
      "app_proto": "tls"
    },
    "mitre_techniques": ["T1071.001"],
    "tags": []
  }
}
```

### 7.3 Zeek — DNS Query (event_type: network.dns)

```json
{
  "event_id": "88fa1023-ccde-4b12-a997-deadbeef0003",
  "timestamp": "2026-09-21T07:01:44.812Z",
  "source": "zeek",
  "event_type": "network.dns",
  "host": "sensor-zeek01",
  "user": null,
  "source_ip": "10.0.0.55",
  "destination_ip": "8.8.8.8",
  "source_port": 53214,
  "destination_port": 53,
  "protocol": "udp",
  "process": null,
  "file_hash": null,
  "domain": "suspicious-domain.xyz",
  "command_line": null,
  "severity": 1,
  "raw_event": "{\"ts\":1758146504.812,\"uid\":\"Cl1Ab23Xyz...\",\"id.orig_h\":\"10.0.0.55\",...}",
  "metadata": {
    "ingest_time": "2026-09-21T07:01:45.100Z",
    "pipeline_version": "0.1.0",
    "source_event_id": "Cl1Ab23Xyz...",
    "source_fields": {
      "uid": "Cl1Ab23Xyz...",
      "query": "suspicious-domain.xyz",
      "qtype_name": "A",
      "rcode_name": "NOERROR",
      "answers": ["192.0.2.100"],
      "TTLs": [300.0]
    },
    "tags": []
  }
}
```

---

## 8. Schema Validation Rules

The normalization layer enforces these constraints before any event is stored:

1. `event_id` must be a valid UUID v4 — reject otherwise
2. `timestamp` must parse as ISO 8601 UTC — reject otherwise
3. `source` must be one of the allowed values — reject otherwise
4. `event_type` must be in the taxonomy table — store as `alert.unknown` with original type in metadata if unrecognized
5. `host` must be non-empty — reject if empty
6. `severity` must be an integer in [1, 5] — clamp if out of range, log warning
7. `source_ip` and `destination_ip` must be valid IPv4 or IPv6 addresses when non-null — set to null if invalid, log warning
8. `source_port` and `destination_port` must be 0–65535 when non-null — set to null if out of range
9. `raw_event` must be non-empty — reject if empty
10. `metadata` must be a JSON object — reject if not an object

---

## 9. Open Issues / Future Work

| Issue | Description |
|-------|-------------|
| **Timezone handling** | Sources with local timestamps and no tz offset require config-driven offset injection |
| **Clock skew** | Multi-sensor environments will have small timestamp deltas; correlation needs skew tolerance |
| **IPv6 normalization** | RFC 5952 compressed form must be enforced consistently |
| **Schema versioning** | `metadata.pipeline_version` alone is insufficient; will need schema version in the index mapping |
| **auditd mapping** | Linux auditd is a key source; mapping not yet drafted |
| **osquery mapping** | osquery adds fleet visibility; mapping not yet drafted |
| **Alert deduplication** | Multiple sources may fire for the same underlying activity; dedup strategy TBD |
| **Sensitive field redaction** | `command_line` redaction rules need a formal policy |

---

*Document maintained by Pranjal. Review by DJ (schema storage implications) and Shreyash (display field decisions) requested before v0.2.*
