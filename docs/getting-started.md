# Getting Started

Welcome to ResiMantle. This guide will help you install and apply the first coat of protection to your application.

## Prerequisites

- Node.js version 20 or higher
- pnpm version 9 or higher
- A Node.js project you want to protect

## Installation

At the moment the repository is intended to be run from source.

```bash
git clone <your-repository-url>
cd ResiMantle
pnpm install
pnpm build
```

## Initialization

Run the CLI from the repository root and point it at the project you want to protect:

```bash
cd /path/to/your-project
node /path/to/ResiMantle/apps/cli/dist/bin/resimantle.js init
```

This will create a `resimantle.config.json` file in your root directory and an ignored `.resimantle/` folder where logs and behavioral data will be stored.

## Your First Scan (Fresh Coat)

Before monitoring runtime, run a static surface scan to check for immediate, obvious risks:

```bash
node /path/to/ResiMantle/apps/cli/dist/bin/resimantle.js scan
```

This will output a summary to your terminal and generate a detailed report in `.resimantle/report.md`. It will look for exposed secrets, vulnerable dependencies, and obvious misconfigurations. **It will not change any files in your project.**

## Running with ResiMantle

To start building a behavioral profile of your application, you need to run it through the ResiMantle wrapper:

```bash
# Instead of: node src/index.js
node /path/to/ResiMantle/apps/cli/dist/bin/resimantle.js run node src/index.js
```

As your application runs, ResiMantle will silently observe the endpoints being called, database queries being made, and AI tools being used.
