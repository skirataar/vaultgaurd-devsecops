import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { ENV } from '../config/env';
import { AuthenticatedUserPayload } from '../types';

/**
 * Authentication Middleware: Validates Bearer JWT tokens and populates req.user.
 * Ensures both `sub` and `userId` are populated on the request context for multi-tenant checks.
 */
export function authenticateToken(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({
      error: 'Unauthorized: Missing or malformed Bearer token',
      code: 'AUTH_REQUIRED',
    });
    return;
  }

  const token = authHeader.split(' ')[1];
  const isVulnerable = req.securityMode === 'vulnerable';

  try {
    const decoded = jwt.verify(token, ENV.JWT_SECRET, {
      ignoreExpiration: isVulnerable, // In vulnerable mode, expired tokens are allowed
    }) as any;

    const sub = decoded.sub || decoded.userId;
    const userId = decoded.userId || decoded.sub;

    req.user = {
      sub,
      userId,
      email: decoded.email,
      role: decoded.role,
      tenantId: decoded.tenantId,
      iat: decoded.iat,
      exp: decoded.exp,
    };

    next();
  } catch (err: any) {
    res.status(401).json({
      error: 'Unauthorized: Invalid or expired token',
      details: isVulnerable ? err.message : undefined,
    });
  }
}
