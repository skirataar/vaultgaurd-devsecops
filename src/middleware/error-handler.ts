import { Request, Response, NextFunction } from 'express';

export function errorHandler(err: any, req: Request, res: Response, next: NextFunction): void {
  const isVulnerable = req.securityMode === 'vulnerable';

  if (process.env.NODE_ENV !== 'test') {
    console.error('[SERVER ERROR]', err);
  }

  res.status(err.status || 500).json({
    error: err.message || 'Internal Server Error',
    code: err.code || 'INTERNAL_ERROR',
    stack: isVulnerable ? err.stack : undefined,
  });
}
