import { Router, Request, Response } from 'express';

export const healthRouter = Router();

healthRouter.get('/', (req: Request, res: Response) => {
  res.status(200).json({
    status: 'healthy',
    service: 'vaultguard-devsecops',
    timestamp: new Date().toISOString(),
    securityMode: req.securityMode,
  });
});
