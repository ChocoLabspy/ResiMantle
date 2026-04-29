# ResiMantle Architecture

ResiMantle is built on a 9-layer architectural model designed to provide progressive, non-invasive security for modern applications.

This document describes the current implemented foundation. For the expanded target architecture with adaptive deception, false-victory handling, quarantine mode, and a central control plane, see [Control Plane Architecture](./control-plane-architecture.md).

```mermaid
graph TD
    subgraph "ResiMantle Layer"
        L1[1. Surface Coat] --> L2[2. AI Defense Layer]
        L2 --> L3[3. Resin Traps]
        L3 --> L4[4. Runtime Monitor]
        L4 --> L5[5. Behavior Model]
        L5 --> L6[6. Deep Seal]
        
        L6 --> L7[7. Access Gatekeeper]
        L7 --> L8[8. Policy Engine]
        L7 --> L9[9. Audit & Explain Layer]
    end
    
    subgraph "Your Application (Untouched)"
        App[Application Code]
        DB[(Database)]
        API[External APIs / AI]
    end
    
    L1 -.-> App
    L4 -.-> App
    L7 -.-> DB
    L2 -.-> API
```

## Layer Description

1. **Surface Coat**: Initial static protection. Checks for exposed secrets, dependency vulnerabilities, and misconfigurations without modifying code.
2. **AI Defense Layer**: Protection against AI-specific attacks like prompt injection and unauthorized tool use.
3. **Resin Traps**: Decoys, canaries, and honeypots designed to detect automated exploration and malicious agents.
4. **Runtime Monitor**: Observes application behavior in real-time.
5. **Behavior Model**: Establishes a baseline of normal operation using the data from the Runtime Monitor.
6. **Deep Seal**: Hardens sensitive zones based on behavioral insights.
7. **Access Gatekeeper**: The decision engine that evaluates requests against policies and the behavior model.
8. **Policy Engine**: Evaluates declarative security rules.
9. **Audit & Explain Layer**: Provides full traceability and human-readable explanations for all decisions made by the system.
