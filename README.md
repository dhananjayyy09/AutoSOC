# AutoSOC — Explainable Multi-Agent AI Platform for Autonomous Security Operations and Threat Hunting

AutoSOC is a research and engineering platform that combines large language models (LLMs), multi-agent orchestration, and classical detection engineering to build an explainable, autonomous Security Operations Center (SOC).

---

## Team

| Developer | Responsibility |
|-----------|----------------|
| **DJ** | Architecture, backend, AI infrastructure, orchestration, DevOps |
| **Pranjal** | Cybersecurity pipeline, detection, threat intelligence, security data, evaluation |
| **Shreyash** | Frontend, dashboard, visualization, UX |

---

## Project Goals

- Autonomous triage of security alerts with LLM-driven reasoning
- Explainable detections grounded in MITRE ATT&CK
- Multi-agent coordination for threat hunting, enrichment, and response
- Normalized security-event model across heterogeneous telemetry sources
- Reproducible evaluation on public IDS/EDR/network datasets

---

## Repository Layout

```
AutoSOC/
├── README.md
├── docs/
│   ├── ChangeLog.md                         # WHAT changed (mandatory Day 2+)
│   ├── Decisions.md                         # WHY architecture decisions were made (mandatory Day 2+)
│   ├── Flow.md                              # HOW security data flows (mandatory Day 2+)
│   ├── security/
│   │   ├── security-event-model.md          # Normalized event schema (v0.2.0)
│   │   ├── security-data-contract.md        # Master security data contract (Day 2)
│   │   ├── detection-pipeline.md            # Full pipeline architecture (v0.1.2)
│   │   ├── security-tools.md                # Tool integration research
│   │   ├── security-baseline.md             # Security requirements baseline
│   │   └── phase2-implementation-plan.md   # Phase 2 Weeks 4–7 implementation plan
│   └── research/
│       ├── dataset-plan.md                  # Dataset evaluation and selection
│       └── literature-tracker.csv           # Research paper tracker
├── backend/                                 # DJ — API, orchestration, infrastructure
├── agents/                                  # DJ — AI agent definitions
├── frontend/                                # Shreyash — dashboard and UI
└── data/                                    # Pranjal — sample data, schemas, loaders
```

---

## Day 1 Status

- [x] Repository initialized — branch `feature/pranjal/day1-security-foundation`
- [x] Security event model documented
- [x] Detection pipeline documented
- [x] Security tools researched
- [x] Dataset plan completed
- [x] Literature tracker seeded
- [x] Security baseline drafted

---

## Day 2 Status (Pranjal — Security Data Architecture)

- [x] Security data contract formalized (`docs/security/security-data-contract.md`)
- [x] Event lifecycle documented with all 8 stages, inputs, outputs, failure paths
- [x] Source adapter contracts defined (Sysmon, Zeek, Suricata, Auth logs)
- [x] Detection Result contract defined (formal schema + terminology disambiguation)
- [x] Feature Set contract defined (feature schema + derivation rules)
- [x] Validation stage established as explicit pipeline stage (separate from Normalization)
- [x] Duplicate event strategy documented (flag, never discard)
- [x] Architectural boundaries documented (9 interface rules)
- [x] Phase 2 Weeks 4–7 implementation plan created
- [x] ChangeLog.md, Decisions.md, Flow.md initialized (mandatory traceability)
- [x] Security Event Model updated to v0.2.0 (`ingestion_id`, `event_category`, `metadata.raw_hash`)
- [x] Detection Pipeline updated to v0.1.2 (Validation stage in diagram and definitions)

---

## Getting Started

> Setup instructions will be added by DJ as the backend scaffolding matures.

---

## License

Research use only. License TBD.
