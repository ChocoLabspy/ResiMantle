import { pino } from 'pino';

/**
 * Creates a structured logger instance for ResiMantle.
 * Logs are typically written to .resimantle/events.log in production,
 * and to stdout in development.
 */
export const createLogger = (logLevel = 'info') => {
  return pino({
    level: logLevel,
    transport: {
      target: 'pino-pretty', // Use pino-pretty for dev, file transport for prod later
      options: {
        colorize: true,
        ignore: 'pid,hostname',
        translateTime: 'SYS:standard',
      },
    },
  });
};

export const logger = createLogger();
