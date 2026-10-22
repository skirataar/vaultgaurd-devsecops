import { Request } from 'express';

export type SecurityMode = 'vulnerable' | 'secure';

export interface AuthenticatedUserPayload {
  sub: string;
  userId: string;
  email: string;
  role: 'MERCHANT' | 'ADMIN' | 'USER' | 'AUDITOR';
  tenantId: string;
  iat?: number;
  exp?: number;
}

declare global {
  namespace Express {
    interface Request {
      securityMode: SecurityMode;
      user?: AuthenticatedUserPayload;
    }
  }
}
