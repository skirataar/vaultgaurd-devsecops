import { PrismaClient } from '@prisma/client';

declare global {
  // eslint-disable-next-line no-var
  var __prismaInstance: PrismaClient | undefined;
}

export const prisma =
  global.__prismaInstance ||
  new PrismaClient({
    log: process.env.NODE_ENV === 'test' ? [] : ['warn', 'error'],
  });

if (process.env.NODE_ENV !== 'production') {
  global.__prismaInstance = prisma;
}
