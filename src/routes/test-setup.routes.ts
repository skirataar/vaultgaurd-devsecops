import { Router, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { ENV } from '../config/env';
import { TEST_USERS } from '../config/constants';

export const testSetupRouter = Router();

/**
 * Endpoint: GET /api/test-setup/tokens & POST /api/test-setup/tokens
 * Issues deterministic JWT test credentials for compliance auditing and regression pipelines.
 */
const generateTestTokensHandler = (req: Request, res: Response) => {
  const alicePayload = {
    sub: TEST_USERS.alice.id,
    userId: TEST_USERS.alice.id,
    email: TEST_USERS.alice.email,
    role: TEST_USERS.alice.role,
    tenantId: TEST_USERS.alice.tenantId,
  };

  const bobPayload = {
    sub: TEST_USERS.bob.id,
    userId: TEST_USERS.bob.id,
    email: TEST_USERS.bob.email,
    role: TEST_USERS.bob.role,
    tenantId: TEST_USERS.bob.tenantId,
  };

  const adminPayload = {
    sub: TEST_USERS.admin.id,
    userId: TEST_USERS.admin.id,
    email: TEST_USERS.admin.email,
    role: TEST_USERS.admin.role,
    tenantId: TEST_USERS.admin.tenantId,
  };

  const aliceToken = jwt.sign(alicePayload, ENV.JWT_SECRET, { expiresIn: '2h' });
  const bobToken = jwt.sign(bobPayload, ENV.JWT_SECRET, { expiresIn: '2h' });
  const adminToken = jwt.sign(adminPayload, ENV.JWT_SECRET, { expiresIn: '2h' });

  res.status(200).json({
    status: 'success',
    securityMode: req.securityMode,
    tokens: {
      alice: aliceToken,
      bob: bobToken,
      admin: adminToken,
    },
    users: {
      alice: {
        id: TEST_USERS.alice.id,
        email: TEST_USERS.alice.email,
        role: TEST_USERS.alice.role,
        tenantId: TEST_USERS.alice.tenantId,
        ownedInvoices: ['101', '104'],
      },
      bob: {
        id: TEST_USERS.bob.id,
        email: TEST_USERS.bob.email,
        role: TEST_USERS.bob.role,
        tenantId: TEST_USERS.bob.tenantId,
        ownedInvoices: ['103'],
      },
      admin: {
        id: TEST_USERS.admin.id,
        email: TEST_USERS.admin.email,
        role: TEST_USERS.admin.role,
        tenantId: TEST_USERS.admin.tenantId,
      },
    },
  });
};

testSetupRouter.get('/tokens', generateTestTokensHandler);
testSetupRouter.post('/tokens', generateTestTokensHandler);
