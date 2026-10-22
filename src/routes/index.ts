import { Router } from 'express';
import { invoiceRouter } from './invoice.routes';
import { webhookRouter } from './webhook.routes';
import { testSetupRouter } from './test-setup.routes';
import { healthRouter } from './health.routes';

export const apiRouter = Router();

apiRouter.use('/health', healthRouter);
apiRouter.use('/invoices', invoiceRouter);
apiRouter.use('/webhooks', webhookRouter);
apiRouter.use('/test-setup', testSetupRouter);
