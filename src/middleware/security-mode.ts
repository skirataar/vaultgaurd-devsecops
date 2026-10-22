import { Request, Response, NextFunction } from 'express';
import { ENV } from '../config/env';
import { SecurityMode } from '../types';

/**
 * Security Mode Toggle Middleware
 * Dynamically switches application behavior between 'vulnerable' and 'secure' modes.
 *
 * Precedence:
 * 1. HTTP Request Header: 'x-security-mode: vulnerable | secure'
 * 2. Query Parameter: '?mode=vulnerable | secure'
 * 3. Environment Variable: process.env.SECURITY_MODE (defaulting to 'vulnerable')
 */
export function securityModeMiddleware(req: Request, res: Response, next: NextFunction): void {
  const headerMode = req.headers['x-security-mode']?.toString().toLowerCase();
  const queryMode = req.query.mode?.toString().toLowerCase();

  let mode: SecurityMode = ENV.SECURITY_MODE;

  if (headerMode === 'secure' || headerMode === 'vulnerable') {
    mode = headerMode as SecurityMode;
  } else if (queryMode === 'secure' || queryMode === 'vulnerable') {
    mode = queryMode as SecurityMode;
  }

  req.securityMode = mode;
  res.setHeader('X-Active-Security-Mode', mode);

  next();
}
