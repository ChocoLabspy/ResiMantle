# ResiMantle

ResiMantle is a non-invasive security layer for Node.js applications and AI-facing tooling. It sits around an application instead of rewriting it: scanning the exposed surface, watching runtime behavior, tightening containment when pressure rises, and leaving an auditable record of the decisions it makes.

The design principle is simple: protect the wood without reshaping it. ResiMantle should adapt to an existing codebase, not force the codebase to adapt to it.

## Overview

- Leaves application code and business logic untouched
- Adds runtime wrapping, containment, auditability, and behavioral signals externally
- Supports sidecar-driven control, compatibility-aware baselines, and capability-scoped quarantine
- Tracks parent-child lineage across wrapped processes, child processes, and worker threads

## Documentation

- [Getting started](docs/getting-started.md)
- [Architecture](docs/architecture.md)
- [Control plane design](docs/control-plane-architecture.md)
- [Configuration](docs/configuration.md)
- [Contributing](CONTRIBUTING.md)

## What It Does

```
┌──────────────────────────────────────────────────┐
│                  ResiMantle Layer                 │
│  ┌──────────────────────────────────────────┐    │
│  │  Monitors · Guards · Contains · Alerts   │    │
│  └──────────────────────────────────────────┘    │
│      ↕ observes        ↕ protects                │
│  ┌──────────────────────────────────────────┐    │
│  │         Your Application (untouched)     │    │
│  │         ·····························    │    │
│  │         code · configs · database        │    │
│  └──────────────────────────────────────────┘    │
└──────────────────────────────────────────────────┘
```

ResiMantle generates recommendations, reports, and containment decisions, but it does not patch the protected application automatically.

---

## Why ResiMantle?

AI-assisted development and automation make reconnaissance, misuse, and lateral movement cheaper. A defensive layer that only scans once is not enough; the system also needs runtime visibility, progressively stronger containment, and a clean audit trail.

ResiMantle is intended for that gap:

- surface scanning for secrets, dependencies, and risky configuration
- runtime wrapping for file, HTTP, socket, and process activity
- policy-driven gating and compatibility-aware tightening
- canaries, decoys, and audit evidence for suspicious exploration

---

## Quick Start From Source

```bash
git clone <your-repository-url>
cd ResiMantle
pnpm install
pnpm build
pnpm --filter resimantle start -- status
```

For runtime wrapping:

```bash
pnpm --filter resimantle start -- run node index.js
```

ResiMantle stores its generated state under `.resimantle/` and keeps the protected application itself unchanged.

---

## Repository Layout

```text
apps/cli/       CLI entrypoint and operator-facing commands
packages/core/  Runtime, sidecar, policy, audit, and defensive layers
packages/types/ Shared package types
docs/           Architecture, configuration, roadmap, and operating docs
examples/       Example policy and configuration files
```

## Configuration Footprint

```
your-project/
├── resimantle.config.json    ← Configuration file
└── .resimantle/              ← Generated output (gitignored)
    ├── policy.json
    ├── behavior-profile.json
    ├── events.log
    ├── report.md
    ├── canaries.json
    └── risk-map.json
```

---

## 🏗️ Architecture

ResiMantle is organized into **9 defensive layers**, each with a specific purpose:

```
ResiMantle Engine
│
├── 1. Surface Coat ·········· Initial surface-level protection
│   └── Secrets, dependencies, configs, exposed endpoints
│
├── 2. AI Defense Layer ······ AI-specific threat protection
│   └── Prompt injection, tool abuse, agent containment
│
├── 3. Resin Traps ··········· Canaries, decoys & honeypots
│   └── Fake tokens, decoy endpoints, prompt canaries
│
├── 4. Runtime Monitor ······· Real-time behavior observation
│   └── Endpoint usage, DB access, AI calls, timing
│
├── 5. Behavior Model ········ Normal behavior baseline
│   └── Statistical profiles, access patterns, frequencies
│
├── 6. Deep Seal ············· Progressive deep protection
│   └── Hardened zones for rare/sensitive operations
│
├── 7. Access Gatekeeper ····· Multi-level access decisions
│   └── ALLOW → LOG → LIMIT → APPROVE → QUARANTINE → BLOCK
│
├── 8. Policy Engine ········· Declarative policy rules
│   └── Auditable, configurable, context-aware
│
└── 9. Audit & Explain ······· Full traceability
    └── Decision logs, reports, human-readable explanations
```

> See [Architecture Documentation](docs/architecture.md) for detailed technical breakdowns.

> See [Control Plane Architecture](docs/control-plane-architecture.md) for the target vNext design, including adaptive deception, false victory, and quarantine flows.

---

## 🔬 Maturation Phases

Like real resin, ResiMantle's protection **cures over time**:

| Phase | Name | Description |
|-------|------|-------------|
| 🟢 | **Fresh Coat** | Initial scan — secrets, dependencies, surface risks |
| 🔵 | **Absorption** | Runtime observation — learns what executes, what doesn't |
| 🟣 | **Deep Seal** | Hardens sensitive zones — admin, database, AI, webhooks |
| 🟠 | **Curing** | Anomaly detection with precision — behavioral model active |
| 🔴 | **Recoat** | Continuous — every change gets a new protective layer |

---

## 🛡️ Key Features

### Surface Protection
- 🔑 Secret & credential exposure detection
- 📦 Dependency vulnerability scanning
- ⚙️ Dangerous configuration detection
- 🚪 Sensitive endpoint identification

### AI Defense
- 🧠 Prompt injection detection
- 🔧 Tool-use policy enforcement for AI agents
- 🔒 AI call proxying & auditing
- 🚫 Agent action containment

### Defensive Traps
- 🪤 Canary token generation & monitoring
- 🎭 Decoy endpoints and files
- 📝 Prompt canary injection
- 🕵️ Automated exploration detection

### Runtime Intelligence
- 📊 Real-time behavior profiling
- 📈 Access pattern learning
- ⚠️ Anomaly detection
- 🔍 Rare path identification

### Access Control
- 🚦 7-level response system (Allow → Block)
- 📋 Declarative policy engine
- 🧾 Full audit trail
- 💬 Human-readable decision explanations

---

## 🎯 Primary Use Cases

| Target | Examples |
|--------|----------|
| **Discord Bots** | Token protection, command monitoring, permission auditing |
| **Node.js APIs** | Middleware protection, endpoint monitoring, rate limiting |
| **AI Applications** | Prompt shielding, tool policy, agent containment |
| **Open Source Projects** | Zero-effort security layer for solo maintainers |

---

## 🚫 What ResiMantle is NOT

- ❌ Not an exploit generator or offensive tool
- ❌ Not an auto-patcher that modifies your code
- ❌ Not an AI with control over your project
- ❌ Not a replacement for developers
- ❌ Not a promise of absolute security

ResiMantle is **purely defensive**: observe, cover, alert, contain, restrict, audit, isolate, and recommend.

---

## 🔒 Ethical Principles

1. Never generate functional exploits
2. Never include offensive payloads
3. Never automate intrusion
4. Never attack the attacker
5. Never modify code without explicit permission
6. Never hide actions from the project owner
7. Always maintain auditable logs
8. Always explain decisions transparently
9. Process data locally — no external data collection by default
10. Open source and community-driven

> See [Ethics Documentation](docs/ethics.md) for the complete ethical framework.

---

## 🗺️ Roadmap

- [x] **Stage 1**: Concept, architecture & repository setup
- [ ] **Stage 2**: MVP — CLI, surface scan, basic canaries, report generation
- [ ] **Stage 3**: Runtime wrapper — Node.js execution monitoring
- [ ] **Stage 4**: Discord bot protection module
- [ ] **Stage 5**: AI proxy — prompt injection detection, tool control
- [ ] **Stage 6**: Advanced policy engine with context-aware decisions
- [ ] **Stage 7**: Web dashboard — risk map, anomaly history, security score

> See [Detailed Roadmap](docs/roadmap.md) for milestones and timelines.

---

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md) before submitting a pull request.

```bash
# Development setup
git clone <your-repository-url>
cd ResiMantle
pnpm install
pnpm build
pnpm test
```

---

## 📄 License

[MIT License](LICENSE) © ResiMantle Contributors

---


