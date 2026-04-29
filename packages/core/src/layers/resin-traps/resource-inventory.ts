import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { basename, dirname, extname, join, relative } from 'node:path';
import type { RuntimeEvent } from '../runtime-monitor';
import type { Finding, ScanSummary } from '@resimantle/types';

export interface ResourceProfile {
  resource: string;
  actions: string[];
  stackTags: string[];
  riskTags: string[];
  sources: string[];
  observedCount: number;
  lastObservedAt: string;
}

export interface InferredResourceContext {
  stackTags: string[];
  riskTags: string[];
  matchedResources: string[];
}

export interface ObserveResourceInput {
  resource: string;
  action: string;
  stackTags?: string[];
  riskTags?: string[];
  source: 'surface-scan' | 'runtime' | 'heuristic' | 'manual';
  observedAt?: string;
}

const STACK_RULES: Array<{ pattern: RegExp; tags: string[] }> = [
  { pattern: /(billing|ledger|invoice|payment|stripe)/i, tags: ['billing', 'payments'] },
  { pattern: /(database|postgres|mysql|sql|query|dump|backup)/i, tags: ['database', 'postgres'] },
  { pattern: /(admin|internal|debug)/i, tags: ['admin', 'api'] },
  { pattern: /(ai|agent|prompt|tool|model)/i, tags: ['ai', 'tools'] },
  { pattern: /(webhook|hooks?)/i, tags: ['webhooks'] },
  { pattern: /(auth|oauth|login|signup|token)/i, tags: ['auth'] },
];

const RISK_RULES: Array<{ pattern: RegExp; tags: string[] }> = [
  { pattern: /(admin|internal|debug)/i, tags: ['admin'] },
  { pattern: /(database|sql|dump|backup|ledger)/i, tags: ['database', 'export'] },
  { pattern: /(secret|credential|key|token|rotate|canary)/i, tags: ['tokens', 'secrets'] },
  { pattern: /(prompt|tool|agent|model)/i, tags: ['prompt', 'tool'] },
  { pattern: /(webhook|hooks?)/i, tags: ['webhook'] },
  { pattern: /(exec|spawn|shell|powershell|cmd)/i, tags: ['process'] },
];

const DEPENDENCY_RULES: Array<{ pattern: RegExp; stackTags: string[]; riskTags: string[] }> = [
  { pattern: /(^|\b)(next|react-router|express|fastify|koa|hono|nestjs|trpc)(\b|$)/i, stackTags: ['web', 'api'], riskTags: [] },
  { pattern: /(^|\b)(pg|postgres|mysql|mariadb|sqlite|redis|prisma|drizzle|sequelize|typeorm|mongoose)(\b|$)/i, stackTags: ['database', 'postgres'], riskTags: ['database'] },
  { pattern: /(^|\b)(stripe|adyen|paddle|braintree)(\b|$)/i, stackTags: ['billing', 'payments'], riskTags: ['tokens'] },
  { pattern: /(^|\b)(auth0|next-auth|lucia|passport|clerk|supertokens)(\b|$)/i, stackTags: ['auth'], riskTags: ['tokens'] },
  { pattern: /(^|\b)(openai|anthropic|langchain|ollama|llamaindex|vercel-ai-sdk)(\b|$)/i, stackTags: ['ai', 'tools'], riskTags: ['prompt', 'tool'] },
];

const ROUTE_ROOTS = [
  'app',
  'pages',
  'routes',
  'api',
  'src/app',
  'src/pages',
  'src/routes',
  'src/router',
  'src/api',
  'server/routes',
] as const;

const LOCKFILE_TAGS: Record<string, string[]> = {
  'pnpm-lock.yaml': ['workspace', 'pnpm'],
  'package-lock.json': ['npm'],
  'yarn.lock': ['yarn'],
};

const ROUTE_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs']);

export class ResourceInventory {
  private profiles = new Map<string, ResourceProfile>();
  private initialized = false;
  private storePath: string;

  constructor(resiMantleDir: string) {
    this.storePath = join(resiMantleDir, 'resource-inventory.json');
  }

  async initialize(): Promise<void> {
    if (this.initialized) {
      return;
    }

    if (!existsSync(this.storePath)) {
      this.initialized = true;
      return;
    }

    try {
      const raw = await readFile(this.storePath, 'utf-8');
      const parsed = JSON.parse(raw) as ResourceProfile[];
      for (const profile of parsed) {
        this.profiles.set(profile.resource, profile);
      }
    } catch {
      // Ignore inventory load failures and rebuild from runtime observations.
    }

    this.initialized = true;
  }

  async ingestScanSummary(summary: ScanSummary): Promise<void> {
    await this.initialize();

    for (const finding of summary.findings) {
      await this.observeScanFinding(finding);
    }
  }

  async observeRuntimeEvent(event: RuntimeEvent): Promise<void> {
    await this.initialize();

    const inferred = inferTags(`${event.category} ${event.resource} ${JSON.stringify(event.details)}`);
    this.upsertProfile({
      resource: event.resource,
      action: event.category,
      stackTags: inferred.stackTags,
      riskTags: inferred.riskTags,
      source: 'runtime',
      observedAt: event.timestamp,
    });
  }

  async observe(input: ObserveResourceInput): Promise<void> {
    await this.initialize();
    this.upsertProfile(input);
  }

  async ingestProjectTopology(projectRoot: string): Promise<void> {
    await this.initialize();

    const manifestPaths = await discoverPackageManifestPaths(projectRoot);
    const manifestTags = new Map<string, Pick<InferredResourceContext, 'stackTags' | 'riskTags'>>();

    for (const manifestPath of manifestPaths) {
      const tags = await inferManifestTags(manifestPath);
      manifestTags.set(manifestPath, tags);
      this.upsertProfile({
        resource: toRelativeResource(projectRoot, manifestPath),
        action: 'topology-manifest',
        stackTags: tags.stackTags,
        riskTags: tags.riskTags,
        source: 'heuristic',
      });
    }

    for (const [lockfile, tags] of Object.entries(LOCKFILE_TAGS)) {
      const lockfilePath = join(projectRoot, lockfile);
      if (!existsSync(lockfilePath)) {
        continue;
      }

      this.upsertProfile({
        resource: lockfile,
        action: 'topology-lockfile',
        stackTags: tags,
        riskTags: [],
        source: 'heuristic',
      });
    }

    const routeFiles = await discoverRouteFiles(projectRoot);
    for (const routeFile of routeFiles) {
      const routeResource = deriveRouteResource(projectRoot, routeFile);
      const owner = selectOwningManifest(routeFile, manifestPaths);
      const ownerTags = owner ? manifestTags.get(owner) : undefined;
      const inferred = inferTags(`${routeResource} ${routeFile}`);

      this.upsertProfile({
        resource: routeResource,
        action: 'topology-route',
        stackTags: unique([
          ...(ownerTags?.stackTags ?? []),
          ...inferred.stackTags,
        ]),
        riskTags: unique([
          ...(ownerTags?.riskTags ?? []),
          ...inferred.riskTags,
        ]),
        source: 'heuristic',
      });
    }
  }

  infer(resource: string, action: string, hints: { stackTags?: string[]; riskTags?: string[] } = {}): InferredResourceContext {
    const normalized = normalizeResource(resource);
    const resourceTokens = tokenize(resource);
    const matchedProfiles = Array.from(this.profiles.values()).filter(profile => {
      const candidate = normalizeResource(profile.resource);
      return candidate === normalized
        || normalized.includes(candidate)
        || candidate.includes(normalized)
        || countSharedTokens(resourceTokens, tokenize(profile.resource)) > 0;
    });

    const inferred = inferTags(`${action} ${resource}`);

    return {
      stackTags: unique([
        ...(hints.stackTags ?? []),
        ...matchedProfiles.flatMap(profile => profile.stackTags),
        ...inferred.stackTags,
      ]),
      riskTags: unique([
        ...(hints.riskTags ?? []),
        ...matchedProfiles.flatMap(profile => profile.riskTags),
        ...inferred.riskTags,
      ]),
      matchedResources: matchedProfiles.map(profile => profile.resource),
    };
  }

  getProfile(resource: string): ResourceProfile | undefined {
    return this.profiles.get(resource);
  }

  getAllProfiles(): ResourceProfile[] {
    return Array.from(this.profiles.values()).sort((left, right) => left.resource.localeCompare(right.resource));
  }

  async persist(): Promise<void> {
    await this.initialize();
    const dir = join(this.storePath, '..');

    if (!existsSync(dir)) {
      await mkdir(dir, { recursive: true });
    }

    await writeFile(this.storePath, JSON.stringify(this.getAllProfiles(), null, 2), 'utf-8');
  }

  private async observeScanFinding(finding: Finding): Promise<void> {
    const resource = finding.file ?? finding.title;
    const inferred = inferTags(`${finding.type} ${finding.title} ${finding.description} ${resource}`);

    this.upsertProfile({
      resource,
      action: finding.type,
      stackTags: inferred.stackTags,
      riskTags: inferred.riskTags,
      source: 'surface-scan',
    });
  }

  private upsertProfile(input: ObserveResourceInput): void {
    const existing = this.profiles.get(input.resource);
    const observedAt = input.observedAt ?? new Date().toISOString();
    const inferred = inferTags(`${input.action} ${input.resource}`);

    if (!existing) {
      this.profiles.set(input.resource, {
        resource: input.resource,
        actions: unique([input.action]),
        stackTags: unique([...(input.stackTags ?? []), ...inferred.stackTags]),
        riskTags: unique([...(input.riskTags ?? []), ...inferred.riskTags]),
        sources: unique([input.source]),
        observedCount: 1,
        lastObservedAt: observedAt,
      });
      return;
    }

    existing.actions = unique([...existing.actions, input.action]);
    existing.stackTags = unique([...existing.stackTags, ...(input.stackTags ?? []), ...inferred.stackTags]);
    existing.riskTags = unique([...existing.riskTags, ...(input.riskTags ?? []), ...inferred.riskTags]);
    existing.sources = unique([...existing.sources, input.source]);
    existing.observedCount += 1;
    existing.lastObservedAt = observedAt;
  }
}

async function inferManifestTags(manifestPath: string): Promise<Pick<InferredResourceContext, 'stackTags' | 'riskTags'>> {
  try {
    const raw = await readFile(manifestPath, 'utf-8');
    const manifest = JSON.parse(raw) as {
      name?: string;
      scripts?: Record<string, string>;
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      peerDependencies?: Record<string, string>;
      optionalDependencies?: Record<string, string>;
    };

    const dependencyNames = Object.keys({
      ...(manifest.dependencies ?? {}),
      ...(manifest.devDependencies ?? {}),
      ...(manifest.peerDependencies ?? {}),
      ...(manifest.optionalDependencies ?? {}),
    });
    const scriptNames = Object.keys(manifest.scripts ?? {});
    const combined = [manifest.name ?? basename(dirname(manifestPath)), ...dependencyNames, ...scriptNames].join(' ');
    const inferred = inferTags(combined);

    const dependencyTags = dependencyNames.reduce<Pick<InferredResourceContext, 'stackTags' | 'riskTags'>>((accumulator, dependency) => {
      for (const rule of DEPENDENCY_RULES) {
        if (!rule.pattern.test(dependency)) {
          continue;
        }

        accumulator.stackTags.push(...rule.stackTags);
        accumulator.riskTags.push(...rule.riskTags);
      }

      return accumulator;
    }, { stackTags: [], riskTags: [] });

    return {
      stackTags: unique([...inferred.stackTags, ...dependencyTags.stackTags]),
      riskTags: unique([...inferred.riskTags, ...dependencyTags.riskTags]),
    };
  } catch {
    return { stackTags: [], riskTags: [] };
  }
}

async function discoverPackageManifestPaths(projectRoot: string): Promise<string[]> {
  const manifests = new Set<string>();
  const rootManifest = join(projectRoot, 'package.json');
  if (existsSync(rootManifest)) {
    manifests.add(rootManifest);
  }

  for (const manifest of await walkForFiles(projectRoot, 'package.json', 3, 24)) {
    manifests.add(manifest);
  }

  return Array.from(manifests).sort((left, right) => left.length - right.length);
}

async function discoverRouteFiles(projectRoot: string): Promise<string[]> {
  const files = new Set<string>();

  for (const routeRoot of ROUTE_ROOTS) {
    const absoluteRoot = join(projectRoot, routeRoot);
    if (!existsSync(absoluteRoot)) {
      continue;
    }

    for (const filePath of await walkRouteFiles(absoluteRoot, 4, 80)) {
      files.add(filePath);
    }
  }

  return Array.from(files).sort();
}

async function walkForFiles(directory: string, targetName: string, maxDepth: number, maxResults: number): Promise<string[]> {
  const results: string[] = [];

  async function visit(currentDirectory: string, depth: number): Promise<void> {
    if (depth > maxDepth || results.length >= maxResults) {
      return;
    }

    const entries = await readdir(currentDirectory, { withFileTypes: true });
    for (const entry of entries) {
      if (results.length >= maxResults) {
        return;
      }

      const absolutePath = join(currentDirectory, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === '.resimantle') {
          continue;
        }
        await visit(absolutePath, depth + 1);
        continue;
      }

      if (entry.name === targetName) {
        results.push(absolutePath);
      }
    }
  }

  await visit(directory, 0);
  return results;
}

async function walkRouteFiles(directory: string, maxDepth: number, maxResults: number): Promise<string[]> {
  const results: string[] = [];

  async function visit(currentDirectory: string, depth: number): Promise<void> {
    if (depth > maxDepth || results.length >= maxResults) {
      return;
    }

    const entries = await readdir(currentDirectory, { withFileTypes: true });
    for (const entry of entries) {
      if (results.length >= maxResults) {
        return;
      }

      const absolutePath = join(currentDirectory, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === '.resimantle') {
          continue;
        }
        await visit(absolutePath, depth + 1);
        continue;
      }

      if (!ROUTE_EXTENSIONS.has(extname(entry.name).toLowerCase())) {
        continue;
      }

      if (!isRouteLikeFile(entry.name, absolutePath)) {
        continue;
      }

      results.push(absolutePath);
    }
  }

  await visit(directory, 0);
  return results;
}

function isRouteLikeFile(fileName: string, absolutePath: string): boolean {
  const normalized = normalizeResource(absolutePath);
  return fileName.startsWith('route.')
    || fileName.startsWith('page.')
    || fileName.startsWith('index.')
    || normalized.includes('/api/')
    || normalized.includes('/routes/')
    || normalized.includes('/router/');
}

function selectOwningManifest(filePath: string, manifestPaths: string[]): string | undefined {
  let bestMatch: string | undefined;

  for (const manifestPath of manifestPaths) {
    const manifestRoot = dirname(manifestPath);
    const rel = relative(manifestRoot, filePath);
    if (rel.startsWith('..')) {
      continue;
    }

    if (!bestMatch || manifestRoot.length > dirname(bestMatch).length) {
      bestMatch = manifestPath;
    }
  }

  return bestMatch;
}

function deriveRouteResource(projectRoot: string, routeFile: string): string {
  let relativePath = normalizeResource(toRelativeResource(projectRoot, routeFile));
  relativePath = relativePath
    .replace(/^src\//, '')
    .replace(/^server\//, '')
    .replace(/^pages\//, '')
    .replace(/^app\//, '')
    .replace(/^routes\//, '')
    .replace(/^router\//, '')
    .replace(/^api\//, 'api/');

  const segments = relativePath
    .split('/')
    .filter(Boolean)
    .map(segment => segment.replace(extname(segment), ''))
    .filter(segment => segment !== 'route' && segment !== 'page' && segment !== 'index')
    .map(segment => segment.replace(/^\[\.\.\.(.+)\]$/, '*$1'))
    .map(segment => segment.replace(/^\[(.+)\]$/, ':$1'));

  const joined = segments.join('/');
  return joined.startsWith('api/') ? `/${joined}` : `/${joined}`;
}

function toRelativeResource(projectRoot: string, absolutePath: string): string {
  const rel = relative(projectRoot, absolutePath);
  return rel ? rel.replace(/\\/g, '/') : basename(absolutePath);
}

function inferTags(value: string): Pick<InferredResourceContext, 'stackTags' | 'riskTags'> {
  const stackTags = STACK_RULES.flatMap(rule => rule.pattern.test(value) ? rule.tags : []);
  const riskTags = RISK_RULES.flatMap(rule => rule.pattern.test(value) ? rule.tags : []);
  return {
    stackTags: unique(stackTags),
    riskTags: unique(riskTags),
  };
}

function normalizeResource(value: string): string {
  return value.replace(/\\/g, '/').trim().toLowerCase();
}

function tokenize(value: string): string[] {
  return normalizeResource(value)
    .split(/[^a-z0-9]+/)
    .filter(token => token.length >= 3);
}

function countSharedTokens(left: string[], right: string[]): number {
  const rightSet = new Set(right);
  return left.filter(token => rightSet.has(token)).length;
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values.filter(Boolean)));
}