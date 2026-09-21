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
│   ├── security/
│   │   ├── security-event-model.md      # Normalized event schema
│   │   ├── detection-pipeline.md        # Full pipeline architecture
│   │   ├── security-tools.md            # Tool integration research
│   │   └── security-baseline.md         # Security requirements baseline
│   └── research/
│       ├── dataset-plan.md              # Dataset evaluation and selection
│       └── literature-tracker.csv       # Research paper tracker
├── backend/                             # DJ — API, orchestration, infrastructure
├── agents/                              # DJ — AI agent definitions
├── frontend/                            # Shreyash — dashboard and UI
└── data/                                # Pranjal — sample data, schemas, loaders
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

## Getting Started

> Setup instructions will be added by DJ as the backend scaffolding matures.

---

## License

Research use only. License TBD.
