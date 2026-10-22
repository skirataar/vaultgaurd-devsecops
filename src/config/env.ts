import dotenv from 'dotenv';
import path from 'path';

dotenv.config({ path: path.resolve(__dirname, '../../.env') });

export const ENV = {
  PORT: parseInt(process.env.PORT || '4000', 10),
  NODE_ENV: process.env.NODE_ENV || 'development',
  SECURITY_MODE: (process.env.SECURITY_MODE?.toLowerCase() === 'secure' ? 'secure' : 'vulnerable') as 'vulnerable' | 'secure',
  DATABASE_URL: process.env.DATABASE_URL || 'file:./dev.db',
  JWT_SECRET: process.env.JWT_SECRET || 'vaultguard-devsecops-super-secure-secret-key-2026',
};
