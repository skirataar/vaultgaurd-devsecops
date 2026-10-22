import { app } from './app';
import { ENV } from './config/env';

const server = app.listen(ENV.PORT, () => {
  console.log(`=======================================================`);
  console.log(`🚀 VaultGuard DevSecOps Service Active on Port ${ENV.PORT}`);
  console.log(`🛡️  Active Default Security Mode: [${ENV.SECURITY_MODE}]`);
  console.log(`📡 Health Check: http://localhost:${ENV.PORT}/api/health`);
  console.log(`=======================================================`);
});

process.on('SIGTERM', () => {
  console.log('Received SIGTERM, closing gracefully...');
  server.close(() => {
    process.exit(0);
  });
});
