export const TEST_USERS = {
  alice: {
    id: 'user_alice',
    email: 'alice@corp.local',
    password: 'Password123!',
    name: 'Alice Henderson',
    role: 'MERCHANT' as const,
    tenantId: 'tenant-alpha',
  },
  bob: {
    id: 'user_bob',
    email: 'bob@corp.local',
    password: 'Password123!',
    name: 'Bob Vance',
    role: 'MERCHANT' as const,
    tenantId: 'tenant-beta',
  },
  admin: {
    id: 'user_admin',
    email: 'admin@corp.local',
    password: 'AdminPass2026!',
    name: 'System Administrator',
    role: 'ADMIN' as const,
    tenantId: 'tenant-system',
  },
};

export const TEST_INVOICES = {
  aliceInvoice101: {
    id: '101',
    amount: 1450.0,
    currency: 'USD',
    status: 'PAID',
    description: 'Acme Corp Q3 Enterprise Software License',
    taxId: 'US-TAX-ALICE-4491',
    ownerId: 'user_alice',
  },
  bobInvoice103: {
    id: '103',
    amount: 890.0,
    currency: 'USD',
    status: 'PAID',
    description: 'Stark Industries Cloud Retainer',
    taxId: 'US-TAX-BOB-9921',
    ownerId: 'user_bob',
  },
  aliceInvoice104: {
    id: '104',
    amount: 2200.0,
    currency: 'USD',
    status: 'PENDING',
    description: 'Acme Corp Annual Security Audit Services',
    taxId: 'US-TAX-ALICE-8822',
    ownerId: 'user_alice',
  },
};
