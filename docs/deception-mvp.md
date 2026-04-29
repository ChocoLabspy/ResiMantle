# Deception Resin + False Victory MVP

This document defines the first implementation-worthy MVP for the two most differentiated parts of ResiMantle:

- **Deception Resin Layer**
- **False Victory Layer**

The goal is not to build the full control plane in one step. The goal is to ship a small, defensible, auditable first version that proves the product thesis:

> suspicious actors can be shown a controlled synthetic surface, and selected hostile actions can be redirected into believable non-operative outcomes, without modifying the protected source code.

## MVP Outcome

At the end of this MVP, ResiMantle should be able to:

1. bind a suspicious actor or session to a synthetic deception story
2. expose a small number of believable synthetic assets through controlled adapters
3. detect when those assets are touched, searched, reused, or invoked
4. return a plausible success response for a narrow class of suspicious actions without touching production truth
5. produce an audit trail that explains the entire chain

## Non-Goals

This MVP should not attempt to do the following:

- full filesystem virtualization
- system-wide per-user overlays
- autonomous story generation with LLMs
- broad false-success responses across all routes and tools
- deception for trusted operators
- any behavior that creates real side effects in production

## Why This Scope Is Correct

The repository already contains the right primitives:

- `CanaryManager` for synthetic credentials and tripwires
- `DecoyGenerator` for synthetic HTTP surfaces
- `PromptCanary` for attribution watermarks
- `PolicyEngine` and `Gatekeeper` for decision control
- `RuntimeMonitor` and `BehaviorModel` for signals
- `Audit` for evidence and reporting

What is missing is not more bait. What is missing is a narrow system that can bind those assets to actors and drive consistent outcomes across read, search, HTTP, and tool flows.

## MVP Architectural Slice

This MVP introduces a small control loop for only these two layers.

```text
Signal sources
  -> PromptShield / RuntimeMonitor / Gatekeeper
  -> suspicion score / policy input

Deception Broker
  -> choose story template
  -> bind story to actor or session
  -> publish synthetic assets to adapters

Overlay adapters
  -> read overlay
  -> search overlay
  -> http decoy overlay

False Victory Broker
  -> evaluate suspicious action
  -> redirect to shadow sink
  -> return plausible non-operative success

Audit Ledger
  -> record story selection
  -> record asset touch
  -> record false-victory decision
```

## MVP Capabilities

### Deception Resin MVP

The first version should support exactly four asset kinds:

- synthetic credentials
- synthetic documents
- synthetic endpoints
- prompt watermarks

The first version should support exactly three adapter surfaces:

- read overlay
- search overlay
- runtime HTTP decoy overlay

The first version should ship with a small catalog of story templates, not arbitrary generation.

Suggested initial templates:

- `billing-shadow`: fake billing sync service, database URL, admin endpoint, runbook
- `internal-debug`: fake debug service, token rotation endpoint, internal notes
- `ai-ops`: fake model ops webhook, prompt policy file, tool execution notes

### False Victory MVP

The first version should only allow false-victory responses for two categories:

- suspicious write-like tool actions routed into a shadow sink
- suspicious access to decoy admin or control endpoints that should appear operationally valid but non-sensitive

Examples:

- a suspicious actor invokes a decoy token rotation route and receives `202 Accepted` with a synthetic job id
- a suspicious actor triggers a suspicious export-like tool action and receives a completed result that references a synthetic artifact in a shadow workspace

## Safety Rules

These constraints are mandatory for the MVP:

1. false victory must never mutate the production system
2. only suspicious, deceptive, or quarantined actors may receive synthetic overlays or false success states
3. all synthetic assets must be tagged as synthetic in internal metadata, even if not visible externally
4. every deception and false-victory action must be attributable to a policy decision and an actor context
5. trusted humans and trusted automation must bypass this machinery by default

## Proposed Source Layout

To minimize churn, the MVP should extend the current repository shape rather than introduce a brand new subsystem tree.

```text
packages/core/src/layers/
  resin-traps/
    types.ts                # extend with stories, assets, bindings, trigger events
    canary-manager.ts       # keep, but integrate with asset registry
    decoy-generator.ts      # keep, but story-aware
    prompt-canary.ts        # keep, but bind watermark to session or actor
    story-catalog.ts        # new
    story-broker.ts         # new
    trap-registry.ts        # new
    overlay-provider.ts     # new
    read-overlay.ts         # new
    search-overlay.ts       # new
    http-decoy-overlay.ts   # new

  false-victory/
    types.ts                # new
    broker.ts               # new
    shadow-sink.ts          # new
    plans.ts                # new
```

This keeps the current `resin-traps` implementation recognizable while allowing a dedicated `false-victory` layer to emerge cleanly.

## Core Contracts

The MVP should converge on a small set of contracts before any broad implementation starts.

```ts
export type StoryAssetKind =
  | 'credential'
  | 'document'
  | 'endpoint'
  | 'prompt-watermark';

export interface StoryAsset {
  id: string;
  storyId: string;
  synthetic: true;
  kind: StoryAssetKind;
  handle: string;
  content?: string;
  triggerOn: Array<'read' | 'search' | 'invoke' | 'reuse'>;
  metadata: Record<string, unknown>;
}

export interface StoryTemplate {
  id: string;
  name: string;
  stackTags: string[];
  riskTags: string[];
  assets: StoryAsset[];
}

export interface StoryBinding {
  id: string;
  actorId: string;
  sessionId: string;
  storyId: string;
  scope: 'session' | 'actor';
  createdAt: string;
  expiresAt?: string;
}

export interface TrapTrigger {
  id: string;
  actorId: string;
  sessionId: string;
  assetId: string;
  triggerType: 'read' | 'search' | 'invoke' | 'reuse';
  timestamp: string;
  details: Record<string, unknown>;
}

export interface FalseVictoryPlan {
  id: string;
  name: string;
  appliesTo: Array<'tool-write' | 'decoy-admin-route'>;
  responseShape: 'accepted-job' | 'completed-export' | 'forbidden-looking-success';
  shadowSink: string;
  explanation: string;
}

export interface FalseVictoryResult {
  applied: boolean;
  planId?: string;
  response?: {
    statusCode?: number;
    body?: Record<string, unknown>;
    headers?: Record<string, string>;
  };
}
```

## Component Responsibilities

### Story Catalog

Stores a small static set of deception stories with believable assets.

Requirements:

- no dynamic hallucinated stories in MVP
- each story must be coherent across credentials, docs, and routes
- each asset must declare how it can be triggered

### Story Broker

Selects a story template for a suspicious actor.

Inputs:

- actor or session context
- stack tags inferred from configuration or scan output
- risk tags from AI defense, runtime monitor, or gatekeeper

Outputs:

- one active `StoryBinding`
- a materialized asset list for adapters

Selection rule for MVP:

- one story per suspicious session
- deterministic selection when possible for reproducibility
- no more than one active story per actor per channel in the same window

### Trap Registry

Persists story bindings, materialized assets, and trigger history under `.resimantle/`.

Suggested files:

- `.resimantle/deception-stories.json`
- `.resimantle/deception-bindings.json`
- `.resimantle/trap-events.log`

### Overlay Providers

The overlay providers are the execution boundary for deception.

MVP providers:

- `read-overlay`: returns synthetic file content or document snippets when a suspicious actor requests a targeted resource
- `search-overlay`: injects story assets into search results for suspicious actors
- `http-decoy-overlay`: serves decoy route behavior from story assets

The provider contract should be simple.

```ts
export interface OverlayProvider {
  kind: 'read' | 'search' | 'http';
  canHandle(input: Record<string, unknown>): boolean;
  resolve(input: Record<string, unknown>): Promise<{
    matched: boolean;
    assetId?: string;
    response?: Record<string, unknown>;
  }>;
}
```

### False Victory Broker

Evaluates whether a suspicious action should be redirected into a safe synthetic success path.

Inputs:

- actor context
- gatekeeper decision context
- matched false-victory plan
- optional shadow sink state

Rules for MVP:

- never apply to trusted actors
- never apply without audit recording
- never apply when the original action already produced a real side effect
- prefer `accepted-job` style responses because they are plausible and low-risk

### Shadow Sink

Provides a no-op destination for false-victory flows.

MVP behavior:

- accept a payload or execution request
- write a synthetic record into `.resimantle/shadow/`
- return metadata that can be shaped into a believable response

This is the safety boundary that keeps false victory from crossing into real execution.

## End-to-End Flows

### Flow A: Suspicious Read Becomes Deception

1. `PromptShield` or `RuntimeMonitor` emits a suspicious extraction signal.
2. The actor trust state moves to `suspicious`.
3. `StoryBroker` binds `billing-shadow` to the session.
4. The actor reads a targeted resource.
5. `read-overlay` returns a synthetic runbook snippet with a synthetic database URL.
6. `TrapRegistry` records the read trigger.
7. If the database URL is later reused, `CanaryManager` records the reuse trigger.

### Flow B: Search Results Become Guided Recon Noise

1. A suspicious actor searches for `token`, `admin`, or `database`.
2. `search-overlay` injects one or more story assets into the result set.
3. The actor clicks or reads one of those assets.
4. `TrapRegistry` records a search-originated trigger.
5. The actor is now correlated more strongly with reconnaissance behavior.

### Flow C: Suspicious Action Gets False Victory

1. A suspicious actor invokes a decoy admin route or suspicious export-like tool action.
2. `Gatekeeper` and `PolicyEngine` mark the action eligible for false victory.
3. `FalseVictoryBroker` selects a plan.
4. `ShadowSink` stores a synthetic artifact or job record.
5. The actor receives a plausible success response.
6. `Audit` records the original attempted action, matched policy, chosen plan, and returned response class.

## First Coding Iteration

The first coding iteration should be intentionally narrow.

### Iteration 1 scope

- extend `resin-traps/types.ts`
- add `story-catalog.ts`
- add `trap-registry.ts`
- make `CanaryManager` and `PromptCanary` session-aware
- add a minimal `story-broker.ts`
- add `false-victory/types.ts` and `broker.ts`
- add one `shadow-sink.ts`

### Iteration 1 exclusions

- no dynamic search engine integration beyond a simple adapter contract
- no OS-level filesystem overlays
- no broad HTTP middleware generation changes outside synthetic decoy endpoints
- no quarantine routing yet

## Audit Requirements

The MVP should create explicit audit events for:

- `STORY_BOUND`
- `STORY_ASSET_READ`
- `STORY_ASSET_SEARCHED`
- `STORY_ASSET_INVOKED`
- `CANARY_REUSED`
- `FALSE_VICTORY_APPLIED`
- `SHADOW_SINK_WRITTEN`

Every audit event must include:

- actor id
- session id
- story id if present
- asset id if present
- policy reference if present
- adapter kind
- timestamp

## Testing Strategy

The first tests should be small and deterministic.

Unit tests:

- story broker binds exactly one story for a suspicious session
- read overlay returns only synthetic assets belonging to the bound story
- false-victory broker refuses trusted actors
- shadow sink writes artifacts only under `.resimantle/shadow`
- canary reuse after synthetic read emits both trigger classes

Integration tests:

- suspicious session reads a synthetic document and later reuses a synthetic credential
- suspicious decoy route returns a false-victory response and leaves production state untouched

## MVP Success Criteria

This MVP is successful if ResiMantle can demonstrate the following in a reproducible test:

1. a suspicious actor receives a bound synthetic story
2. the actor touches one or more synthetic assets
3. those touches are correlated in the audit trail
4. a suspicious action is redirected into a shadow sink
5. the actor receives a believable success response
6. no production truth is mutated during the flow

## Practical Recommendation

Do not start by inventing a large generic framework. Start by making `resin-traps` stateful and actor-aware, and by adding one narrow `false-victory` package with strict guardrails.

If that works end to end, the rest of the control-plane design can grow around something real instead of around abstractions alone.