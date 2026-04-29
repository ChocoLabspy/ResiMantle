# Contributing to ResiMantle

Thank you for your interest in contributing to ResiMantle! This guide will help you get started.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Security Considerations](#security-considerations)

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

1. Fork the repository if you do not have direct write access
2. Clone the repository: `git clone https://github.com/ChocoLabspy/ResiMantle.git`
3. If you are working from a fork, update `origin` to your fork and keep `upstream` pointed at the main repository
4. Create a feature branch: `git checkout -b feature/your-feature-name`
5. Make your changes and submit a pull request

## Development Setup

### Prerequisites

- **Node.js** >= 20.0.0
- **pnpm** >= 9.0.0

### Installation

```bash
# Clone the repository
git clone https://github.com/ChocoLabspy/ResiMantle.git
cd ResiMantle
git remote rename origin upstream

# Install dependencies
pnpm install

# Build all packages
pnpm build

# Run tests
pnpm test

# Run type checking
pnpm typecheck

# Run linting
pnpm lint
```

If you are working from a fork, add your fork back as `origin` using the HTTPS or SSH URL shown by GitHub for that fork.

## Project Structure

```
ResiMantle/
├── apps/
│   └── cli/              # CLI application (resimantle command)
├── packages/
│   ├── core/             # Core engine with all 9 defensive layers
│   └── types/            # Shared type definitions
├── docs/                 # Documentation
└── examples/             # Example configurations
```

## Development Workflow

### Branch Naming

- `feature/` — New features
- `fix/` — Bug fixes
- `docs/` — Documentation changes
- `refactor/` — Code refactoring
- `test/` — Test additions or modifications

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(core): add prompt injection detection to AI Defense Layer
fix(cli): correct config file path resolution on Windows
docs: update architecture diagram with Deep Seal details
test(core): add unit tests for Access Gatekeeper decisions
chore: update TypeScript to 5.8
```

## Coding Standards

- **TypeScript** — All code must be written in TypeScript with strict mode
- **ESLint** — All code must pass linting: `pnpm lint`
- **Prettier** — All code must be formatted: `pnpm format`
- **No `any`** — Avoid `any` types; use `unknown` if the type is truly unknown
- **Consistent imports** — Use `import type` for type-only imports
- **Error handling** — Use custom error classes from `@resimantle/core`
- **Logging** — Use the structured logger, never `console.log`

## Testing

- Write tests for all new functionality
- Place test files alongside source files: `feature.ts` → `feature.test.ts`
- Use **Vitest** as the test runner
- Aim for meaningful coverage, not 100% for its own sake

```bash
# Run all tests
pnpm test

# Run tests in watch mode
pnpm test:watch

# Run with coverage
pnpm test:coverage
```

## Pull Request Process

1. Ensure your code passes all checks: `pnpm lint && pnpm typecheck && pnpm test`
2. Update documentation if your changes affect the public API
3. Add a clear description of what your PR does and why
4. Link any related issues
5. Request a review from a maintainer
6. Address all review feedback

### PR Checklist

- [ ] Code compiles without errors (`pnpm build`)
- [ ] All tests pass (`pnpm test`)
- [ ] Linting passes (`pnpm lint`)
- [ ] Types check (`pnpm typecheck`)
- [ ] Documentation updated (if applicable)
- [ ] No secrets, credentials, or offensive code included

## Security Considerations

ResiMantle is a **defensive** security tool. When contributing:

- ✅ **DO** build detection, observation, and containment features
- ✅ **DO** create canary and decoy mechanisms
- ✅ **DO** improve anomaly detection and policy enforcement
- ✅ **DO** add logging and audit capabilities
- ❌ **DO NOT** add exploit generation capabilities
- ❌ **DO NOT** include offensive payloads or attack automation
- ❌ **DO NOT** add features that modify the protected project's source code
- ❌ **DO NOT** add external data collection without explicit user consent

See [SECURITY.md](SECURITY.md) for our security policy and [docs/ethics.md](docs/ethics.md) for our ethical framework.

---

Thank you for helping make software more secure! 🛡️
