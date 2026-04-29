# Maturation Phases

ResiMantle's protection cures over time, moving through 5 distinct phases.

## 1. Fresh Coat (Initial Application)
When ResiMantle is first installed, it does not immediately understand your project. It applies basic, external, low-risk defenses.
- Scans for exposed secrets.
- Checks dependencies.
- Generates initial canary tokens.
- Identifies obvious sensitive endpoints (e.g., `/admin`).

## 2. Absorption (Learning)
The resin begins to sink in. The system observes:
- Which endpoints are executed frequently.
- Which modules interact with the database.
- Which API routes are rarely or never touched.
- Normal tool usage patterns by AI agents.

## 3. Deep Seal (Hardening)
Protection deepens. ResiMantle applies stricter controls around sensitive zones based on observation.
- Rare admin endpoints are placed under "REQUIRE_APPROVAL" policy.
- Database access from unexpected modules is flagged or blocked.
- AI tools that write to the filesystem are restricted.

## 4. Curing (Full Operation)
The resin hardens. The system now has a stable behavioral model.
- Anomalies are detected with high precision.
- The Access Gatekeeper actively blocks or quarantines suspicious requests.
- Prompts are filtered aggressively.

## 5. Recoat (Continuous)
Every new deployment or code change receives a new layer.
- The behavior model adjusts.
- New endpoints start back in the "Absorption" phase while old endpoints remain "Sealed".
