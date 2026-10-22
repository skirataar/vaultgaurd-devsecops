import { Request, Response, NextFunction } from 'express';

export function requestLogger(req: Request, res: Response, next: NextFunction): void {
  const start = Date.now();
  const method = req.method;
  const url = req.originalUrl || req.url;

  res.on('finish', () => {
    const duration = Date.now() - start;
    const mode = req.securityMode || 'unknown';
    if (process.env.NODE_ENV !== 'test') {
      console.log(`[HTTP] ${method} ${url} -> ${res.statusCode} (${duration}ms) [mode: ${mode}]`);
    }
  });

  next();
}
