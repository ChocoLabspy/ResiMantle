import { randomUUID } from 'node:crypto';
import type { RuntimeEvent } from '../types';
import { RuntimeEventCategory } from '../types';

type EventCallback = (event: RuntimeEvent) => void;

/**
 * The HttpCollector intercepts outbound HTTP/HTTPS requests made by the
 * application being monitored. It monkey-patches the `http.request` and
 * `https.request` methods to capture metadata about every outgoing call
 * WITHOUT modifying the request itself or its response.
 *
 * This is the "resin" approach: observe, don't alter.
 */
export class HttpCollector {
  private onEvent: EventCallback;
  private originalHttpRequest: typeof import('node:http').request | null = null;
  private originalHttpsRequest: typeof import('node:https').request | null = null;
  private originalHttpGet: typeof import('node:http').get | null = null;
  private originalHttpsGet: typeof import('node:https').get | null = null;
  private active = false;
  private ignorePatterns: RegExp[];

  constructor(onEvent: EventCallback, ignorePatterns: string[] = []) {
    this.onEvent = onEvent;
    this.ignorePatterns = ignorePatterns.map(p => new RegExp(p));
  }

  /**
   * Activates the HTTP interceptor by wrapping Node's http/https modules.
   * The original methods are preserved for clean restoration.
   */
  async activate(): Promise<void> {
    if (this.active) return;

    const http = await import('node:http');
    const https = await import('node:https');

    // Save originals
    this.originalHttpRequest = http.request;
    this.originalHttpsRequest = https.request;
    this.originalHttpGet = http.get;
    this.originalHttpsGet = https.get;

    const self = this;

    // Wrap http.request
    const wrappedHttpRequest = function (this: unknown, ...args: unknown[]) {
      return self.wrapRequest('http', self.originalHttpRequest!, args);
    } as typeof http.request;
    (http as any).request = wrappedHttpRequest;

    // Wrap https.request
    const wrappedHttpsRequest = function (this: unknown, ...args: unknown[]) {
      return self.wrapRequest('https', self.originalHttpsRequest!, args);
    } as typeof https.request;
    (https as any).request = wrappedHttpsRequest;

    // Wrap http.get
    const wrappedHttpGet = function (this: unknown, ...args: unknown[]) {
      const req = self.wrapRequest('http', self.originalHttpRequest!, args);
      req.end();
      return req;
    } as typeof http.get;
    (http as any).get = wrappedHttpGet;

    // Wrap https.get
    const wrappedHttpsGet = function (this: unknown, ...args: unknown[]) {
      const req = self.wrapRequest('https', self.originalHttpsRequest!, args);
      req.end();
      return req;
    } as typeof https.get;
    (https as any).get = wrappedHttpsGet;

    this.active = true;
  }

  /**
   * Restores the original http/https methods, cleanly removing the interception.
   */
  async deactivate(): Promise<void> {
    if (!this.active) return;

    const http = await import('node:http');
    const https = await import('node:https');

    if (this.originalHttpRequest) (http as any).request = this.originalHttpRequest;
    if (this.originalHttpsRequest) (https as any).request = this.originalHttpsRequest;
    if (this.originalHttpGet) (http as any).get = this.originalHttpGet;
    if (this.originalHttpsGet) (https as any).get = this.originalHttpsGet;

    this.active = false;
  }

  /**
   * Wraps a single request call, capturing metadata and timing.
   */
  private wrapRequest(
    protocol: string,
    originalFn: Function,
    args: unknown[],
  ) {
    const startTime = Date.now();
    const requestInfo = this.extractRequestInfo(protocol, args);

    // Check ignore patterns
    if (this.shouldIgnore(requestInfo.url)) {
      return originalFn.apply(null, args);
    }

    // Call the original function
    const req = originalFn.apply(null, args);

    // Listen for response to capture status code and timing
    req.on('response', (res: any) => {
      const event: RuntimeEvent = {
        id: randomUUID(),
        timestamp: new Date().toISOString(),
        category: RuntimeEventCategory.HTTP_OUTBOUND,
        actor: this.getCallerInfo(),
        resource: requestInfo.url,
        details: {
          method: requestInfo.method,
          hostname: requestInfo.hostname,
          port: requestInfo.port,
          path: requestInfo.path,
          statusCode: res.statusCode,
          headers: this.sanitizeHeaders(requestInfo.headers),
        },
        blocked: false,
        durationMs: Date.now() - startTime,
      };

      this.onEvent(event);
    });

    // Capture errors too
    req.on('error', (err: Error) => {
      const event: RuntimeEvent = {
        id: randomUUID(),
        timestamp: new Date().toISOString(),
        category: RuntimeEventCategory.HTTP_OUTBOUND,
        actor: this.getCallerInfo(),
        resource: requestInfo.url,
        details: {
          method: requestInfo.method,
          hostname: requestInfo.hostname,
          error: err.message,
        },
        blocked: false,
        durationMs: Date.now() - startTime,
      };

      this.onEvent(event);
    });

    return req;
  }

  /**
   * Extracts URL, method, and headers from the arguments passed to http.request.
   */
  private extractRequestInfo(protocol: string, args: unknown[]): {
    url: string;
    method: string;
    hostname: string;
    port: string;
    path: string;
    headers: Record<string, string>;
  } {
    const first = args[0];

    // http.request(url, options?, callback?)
    if (typeof first === 'string') {
      try {
        const url = new URL(first);
        return {
          url: first,
          method: ((args[1] as any)?.method || 'GET').toUpperCase(),
          hostname: url.hostname,
          port: url.port || (protocol === 'https' ? '443' : '80'),
          path: url.pathname + url.search,
          headers: (args[1] as any)?.headers || {},
        };
      } catch {
        return { url: first, method: 'GET', hostname: '', port: '', path: '', headers: {} };
      }
    }

    // http.request(URL, options?, callback?)
    if (first instanceof URL) {
      return {
        url: first.toString(),
        method: ((args[1] as any)?.method || 'GET').toUpperCase(),
        hostname: first.hostname,
        port: first.port || (protocol === 'https' ? '443' : '80'),
        path: first.pathname + first.search,
        headers: (args[1] as any)?.headers || {},
      };
    }

    // http.request(options, callback?)
    if (typeof first === 'object' && first !== null) {
      const opts = first as Record<string, any>;
      const hostname = opts.hostname || opts.host || 'localhost';
      const port = opts.port || (protocol === 'https' ? '443' : '80');
      const path = opts.path || '/';
      return {
        url: `${protocol}://${hostname}:${port}${path}`,
        method: (opts.method || 'GET').toUpperCase(),
        hostname,
        port: String(port),
        path,
        headers: opts.headers || {},
      };
    }

    return { url: 'unknown', method: 'UNKNOWN', hostname: '', port: '', path: '', headers: {} };
  }

  /**
   * Removes sensitive headers (Authorization, Cookie, etc.) from logs.
   */
  private sanitizeHeaders(headers: Record<string, string>): Record<string, string> {
    const sanitized: Record<string, string> = {};
    const sensitiveKeys = new Set(['authorization', 'cookie', 'set-cookie', 'x-api-key', 'x-auth-token']);

    for (const [key, value] of Object.entries(headers)) {
      if (sensitiveKeys.has(key.toLowerCase())) {
        sanitized[key] = '[REDACTED]';
      } else {
        sanitized[key] = value;
      }
    }
    return sanitized;
  }

  /**
   * Attempts to determine the caller by inspecting the stack trace.
   */
  private getCallerInfo(): string {
    const stack = new Error().stack;
    if (!stack) return 'unknown';

    const lines = stack.split('\n');
    // Skip internal frames (this file, node internals)
    for (const line of lines.slice(3)) {
      if (line.includes('node_modules') || line.includes('node:internal')) continue;
      const match = line.match(/at\s+(?:(.+?)\s+\()?(.+?):(\d+):\d+\)?/);
      if (match) {
        return match[2] || match[1] || 'unknown';
      }
    }
    return 'unknown';
  }

  private shouldIgnore(url: string): boolean {
    return this.ignorePatterns.some(p => p.test(url));
  }
}
