// types/prisma.d.ts
import { PrismaClient } from '@prisma/client';

declare module '@prisma/client' {
  interface PrismaClient {
    $on(event: 'beforeExit', callback: (arg: void) => Promise<void>): void;
  }
}
