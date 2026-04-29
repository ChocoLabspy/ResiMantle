import type { DecoyEndpoint } from './types';

/**
 * Default decoy endpoints that look like real admin/sensitive routes.
 * When an attacker or AI agent discovers and accesses these endpoints,
 * it triggers an immediate alert — they don't exist in the real app.
 */
const DEFAULT_DECOYS: DecoyEndpoint[] = [
  { path: '/admin/config', method: 'GET', description: 'Fake admin configuration panel' },
  { path: '/admin/users/export', method: 'GET', description: 'Fake user data export endpoint' },
  { path: '/api/v1/internal/debug', method: 'GET', description: 'Fake internal debug API' },
  { path: '/api/v1/internal/keys', method: 'GET', description: 'Fake API key listing' },
  { path: '/.env', method: 'GET', description: 'Fake environment file access' },
  { path: '/wp-admin', method: 'GET', description: 'Fake WordPress admin (honeypot)' },
  { path: '/phpmyadmin', method: 'GET', description: 'Fake phpMyAdmin (honeypot)' },
  { path: '/api/v1/admin/database/dump', method: 'POST', description: 'Fake database dump endpoint' },
  { path: '/.git/config', method: 'GET', description: 'Fake git config exposure' },
  { path: '/backup.sql', method: 'GET', description: 'Fake SQL backup file' },
  { path: '/api/v1/tokens/rotate', method: 'POST', description: 'Fake token rotation endpoint' },
  { path: '/graphql/introspection', method: 'POST', description: 'Fake GraphQL introspection' },
];

/**
 * Generates decoy endpoints (honeypot routes) that can be deployed
 * in the application's HTTP server to detect reconnaissance activity.
 *
 * Any request to these endpoints is a strong signal of malicious intent,
 * since they don't correspond to any real functionality.
 */
export class DecoyGenerator {
  /**
   * Returns the default set of decoy endpoints.
   */
  async generateEndpoints(): Promise<DecoyEndpoint[]> {
    return [...DEFAULT_DECOYS];
  }

  /**
   * Generates Express/Koa-compatible middleware code for a decoy endpoint.
   */
  generateMiddlewareCode(decoy: DecoyEndpoint): string {
    return [
      `// ResiMantle Decoy: ${decoy.description}`,
      `app.${decoy.method.toLowerCase()}('${decoy.path}', (req, res) => {`,
      `  // ALERT: This endpoint was accessed — potential reconnaissance!`,
      `  resimantle.trapTriggered('DECOY_ACCESSED', {`,
      `    path: '${decoy.path}',`,
      `    method: '${decoy.method}',`,
      `    ip: req.ip,`,
      `    headers: req.headers,`,
      `  });`,
      `  // Return a realistic-looking but fake response`,
      `  res.status(403).json({ error: 'Forbidden', message: 'Insufficient permissions' });`,
      `});`,
    ].join('\n');
  }
}
