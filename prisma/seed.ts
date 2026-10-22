import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

export const TEST_USERS = {
  alice: {
    id: 'user_alice',
    email: 'alice@corp.local',
    password: 'Password123!',
    name: 'Alice Henderson',
    role: 'MERCHANT',
    tenantId: 'tenant-alpha',
  },
  bob: {
    id: 'user_bob',
    email: 'bob@corp.local',
    password: 'Password123!',
    name: 'Bob Vance',
    role: 'MERCHANT',
    tenantId: 'tenant-beta',
  },
  admin: {
    id: 'user_admin',
    email: 'admin@corp.local',
    password: 'AdminPass2026!',
    name: 'System Administrator',
    role: 'ADMIN',
    tenantId: 'tenant-system',
  },
};

export const TEST_INVOICES = [
  {
    id: '101',
    amount: 1450.0,
    currency: 'USD',
    status: 'PAID',
    description: 'Acme Corp Q3 Enterprise Software License',
    taxId: 'US-TAX-ALICE-4491',
    ownerId: 'user_alice',
  },
  {
    id: '103',
    amount: 890.0,
    currency: 'USD',
    status: 'PAID',
    description: 'Stark Industries Cloud Retainer',
    taxId: 'US-TAX-BOB-9921',
    ownerId: 'user_bob',
  },
  {
    id: '104',
    amount: 2200.0,
    currency: 'USD',
    status: 'PENDING',
    description: 'Acme Corp Annual Security Audit Services',
    taxId: 'US-TAX-ALICE-8822',
    ownerId: 'user_alice',
  },
];

async function main() {
  console.log('[SEED] Resetting database tables...');
  await prisma.auditLog.deleteMany({});
  await prisma.invoice.deleteMany({});
  await prisma.user.deleteMany({});

  console.log('[SEED] Creating deterministic user personas...');
  const saltRounds = 10;

  for (const user of Object.values(TEST_USERS)) {
    const passwordHash = await bcrypt.hash(user.password, saltRounds);
    await prisma.user.create({
      data: {
        id: user.id,
        email: user.email,
        passwordHash,
        name: user.name,
        role: user.role,
        tenantId: user.tenantId,
      },
    });
    console.log(`  -> Created persona: ${user.name} (${user.email}) [Role: ${user.role}, Tenant: ${user.tenantId}]`);
  }

  console.log('[SEED] Populating test invoices for BOLA & SQLi verification...');
  for (const inv of TEST_INVOICES) {
    await prisma.invoice.create({
      data: inv,
    });
    console.log(`  -> Created invoice #${inv.id} for owner ${inv.ownerId} ($${inv.amount})`);
  }

  console.log('[SEED] Database seeding complete.');
}

main()
  .catch((e) => {
    console.error('[SEED ERROR]', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
