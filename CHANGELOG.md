# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-04-29

### Added
- Non-invasive runtime wrapping for Node.js processes through the CLI and preload layer.
- Local sidecar control plane with scoped bootstrap, heartbeat attestation, and adaptive containment updates.
- Capability-scoped containment for reads, processes, and sockets, including inheritance across child processes and worker threads.
- Compatibility baseline learning that can auto-apply safe allowlist rules to live containment.
- Parent-child lineage tracking in control snapshots and operator-facing summaries.
- Nine defensive layers covering surface analysis, AI defense, traps, runtime monitoring, behavior, sealing, access control, policy, and audit.
- GitHub automation for CI, security auditing, and tag-based release publishing.

### Changed
- Repository metadata, documentation, and contribution guidance now point to the public GitHub repository.
- Root test script now uses the stable Vitest invocation validated for this repository.

### Verified
- Workspace typecheck passes.
- Workspace build passes.
- Full Vitest suite passes with 39 tests.
