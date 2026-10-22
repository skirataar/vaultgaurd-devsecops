import express, { Application } from 'express';
import cors from 'cors';
import { securityModeMiddleware } from './middleware/security-mode';
import { requestLogger } from './middleware/logger';
import { errorHandler } from './middleware/error-handler';
import { apiRouter } from './routes';

export function createApp(): Application {
  const app = express();

  // Core Middleware
  app.use(cors());
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Security Mode Toggle & Telemetry Middleware
  app.use(securityModeMiddleware);

  // Request Logging
  app.use(requestLogger);

  // Mount API Endpoints
  app.use('/api', apiRouter);

  // Global Error Handler
  app.use(errorHandler);

  return app;
}

export const app = createApp();
