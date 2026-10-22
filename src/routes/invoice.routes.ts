import { Router, Request, Response } from 'express';
import { prisma } from '../lib/prisma';
import { authenticateToken } from '../middleware/auth';

export const invoiceRouter = Router();

/**
 * Endpoint 1: Invoice Search Endpoint
 * GET /api/invoices/search?client=
 * Demonstrates OWASP A03:2021 / CWE-89: SQL Injection (SQLi)
 *
 * Vulnerable mode: Direct string interpolation into raw query execution (`prisma.$queryRawUnsafe`)
 * Secure mode: Parameterized Prisma ORM query strictly scoped to caller's `ownerId`
 */
invoiceRouter.get('/search', authenticateToken, async (req: Request, res: Response) => {
  const client = (req.query.client as string) || '';
  const isVulnerable = req.securityMode === 'vulnerable';
  const ownerId = req.user!.sub;

  try {
    if (isVulnerable) {
      // VULNERABLE PATTERN (CWE-89):
      // Direct string interpolation into raw SQL query without parameterization or escaping.
      // Allows an attacker to break out of the string literal and execute arbitrary SQL syntax
      // (e.g. `client=' OR '1'='1` or UNION-based exfiltration), completely ignoring multi-tenant isolation.
      const rawQuery = `SELECT * FROM "Invoice" WHERE "description" LIKE '%${client}%'`;
      const invoices = await prisma.$queryRawUnsafe<any[]>(rawQuery);

      res.status(200).json({
        securityMode: 'vulnerable',
        queryExecuted: rawQuery,
        count: invoices.length,
        invoices,
        _securityTelemetry: {
          vulnerability: 'CWE-89: SQL Injection via prisma.$queryRawUnsafe string interpolation',
          tenantIsolationEnforced: false,
        },
      });
      return;
    }

    // SECURE PATTERN:
    // 1. AST-level parameterization via Prisma ORM query builder.
    // 2. Multi-tenant scoping: Strict WHERE clause pinning records to `ownerId = req.user.sub`.
    // The search parameter is treated purely as a scalar string datum by the SQLite engine.
    const invoices = await prisma.invoice.findMany({
      where: {
        ownerId,
        description: {
          contains: client,
        },
      },
    });

    res.status(200).json({
      securityMode: 'secure',
      count: invoices.length,
      invoices,
      _securityTelemetry: {
        vulnerabilityNeutralized: true,
        tenantIsolationEnforced: true,
        scopedOwnerId: ownerId,
      },
    });
  } catch (error: any) {
    res.status(500).json({
      error: 'Query execution error',
      details: isVulnerable ? error.message : undefined,
    });
  }
});

/**
 * Endpoint 2: Multi-Tenant Invoice Fetch
 * GET /api/invoices/:id
 * Demonstrates OWASP API1:2023 / CWE-639: Broken Object Level Authorization (BOLA / IDOR)
 *
 * Vulnerable mode: `prisma.invoice.findUnique({ where: { id } })` without checking `ownerId`
 * Secure mode: `prisma.invoice.findFirst({ where: { id, ownerId: req.user.sub } })`
 */
invoiceRouter.get('/:id', authenticateToken, async (req: Request, res: Response) => {
  const { id } = req.params;
  const isVulnerable = req.securityMode === 'vulnerable';
  const callerId = req.user!.sub;

  try {
    if (isVulnerable) {
      // VULNERABLE PATTERN (CWE-639 BOLA):
      // Queries the database by primary key alone. Disregards tenant ownership boundaries,
      // allowing any authenticated user to read sensitive financial documents of other merchants.
      const invoice = await prisma.invoice.findUnique({
        where: { id },
      });

      if (!invoice) {
        res.status(404).json({
          error: 'Invoice not found',
          code: 'NOT_FOUND',
        });
        return;
      }

      res.status(200).json({
        ...invoice,
        _securityTelemetry: {
          securityMode: 'vulnerable',
          authorizationChecked: false,
          warning: 'BOLA vulnerability present: taxId and invoice details exposed across tenant boundary.',
        },
      });
      return;
    }

    // SECURE PATTERN:
    // Object-level tenancy enforcement: `findFirst` strictly joins the requested `id`
    // with the authenticated identity `ownerId: req.user.sub`.
    const invoice = await prisma.invoice.findFirst({
      where: {
        id,
        ownerId: callerId,
      },
    });

    if (!invoice) {
      // Determine if object exists under another tenant to issue an explicit authorization denial
      const crossTenantCheck = await prisma.invoice.findUnique({
        where: { id },
      });

      if (crossTenantCheck) {
        res.status(403).json({
          error: 'Access Denied: Object-level authorization policy violation (CWE-639 BOLA blocked)',
          code: 'BOLA_BLOCKED',
          requestedResourceId: id,
          callerIdentity: callerId,
        });
        return;
      }

      res.status(404).json({
        error: 'Invoice not found',
        code: 'NOT_FOUND',
      });
      return;
    }

    // Explicit defense-in-depth security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'no-store');

    res.status(200).json(invoice);
  } catch (error: any) {
    res.status(500).json({
      error: 'Failed to retrieve invoice',
      details: isVulnerable ? error.message : undefined,
    });
  }
});

/**
 * List Invoices (Utility Endpoint)
 * GET /api/invoices
 */
invoiceRouter.get('/', authenticateToken, async (req: Request, res: Response) => {
  const isVulnerable = req.securityMode === 'vulnerable';
  const ownerId = req.user!.sub;

  try {
    const invoices = isVulnerable
      ? await prisma.invoice.findMany() // Leaks all tenants in vulnerable mode
      : await prisma.invoice.findMany({ where: { ownerId } }); // Scoped to tenant in secure mode

    res.status(200).json({
      securityMode: req.securityMode,
      count: invoices.length,
      invoices,
    });
  } catch (error: any) {
    res.status(500).json({
      error: 'Failed to list invoices',
      details: isVulnerable ? error.message : undefined,
    });
  }
});
