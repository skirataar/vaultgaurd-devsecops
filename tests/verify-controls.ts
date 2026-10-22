import { AddressInfo } from 'node:net';
import jwt from 'jsonwebtoken';
import { app } from '../src/app';
import { ENV } from '../src/config/env';
import { TEST_USERS } from '../src/config/constants';
import { prisma } from '../src/lib/prisma';
import { validateUrlForSSRF } from '../src/security/ssrfGuard';

interface TestResult {
  suite: string;
  testName: string;
  passed: boolean;
  details: string;
}

const results: TestResult[] = [];

function record(suite: string, testName: string, passed: boolean, details: string) {
  results.push({ suite, testName, passed, details });
  const icon = passed ? '✅ PASS' : '❌ FAIL';
  console.log(`  ${icon} [${suite}] ${testName} - ${details}`);
}

async function runVerificationSuite() {
  console.log('======================================================================');
  console.log('🛡️  VaultGuard DevSecOps - Phase 3 Controls Verification Suite');
  console.log('    Validating CWE-639 (BOLA), CWE-89 (SQLi), and CWE-918 (SSRF)');
  console.log('======================================================================\n');

  // Step 1: Start ephemeral server on random available port
  const server = app.listen(0);
  const port = (server.address() as AddressInfo).port;
  const baseUrl = `http://127.0.0.1:${port}`;

  // Step 2: Mint deterministic test JWT tokens
  const aliceToken = jwt.sign(
    {
      sub: TEST_USERS.alice.id,
      userId: TEST_USERS.alice.id,
      email: TEST_USERS.alice.email,
      role: TEST_USERS.alice.role,
      tenantId: TEST_USERS.alice.tenantId,
    },
    ENV.JWT_SECRET,
    { expiresIn: '1h' }
  );

  const bobToken = jwt.sign(
    {
      sub: TEST_USERS.bob.id,
      userId: TEST_USERS.bob.id,
      email: TEST_USERS.bob.email,
      role: TEST_USERS.bob.role,
      tenantId: TEST_USERS.bob.tenantId,
    },
    ENV.JWT_SECRET,
    { expiresIn: '1h' }
  );

  try {
    // -------------------------------------------------------------------------
    // TEST SUITE 1: CWE-639 Broken Object Level Authorization (BOLA)
    // -------------------------------------------------------------------------
    console.log('--- [SUITE 1: CWE-639 BOLA / IDOR Verification] ---');

    // Scenario 1A: Vulnerable Mode - Alice attempts to access Bob's invoice (#103)
    const resBOLA_Vuln = await fetch(`${baseUrl}/api/invoices/103`, {
      headers: {
        'Authorization': `Bearer ${aliceToken}`,
        'x-security-mode': 'vulnerable',
      },
    });
    const dataBOLA_Vuln = (await resBOLA_Vuln.json()) as any;
    const vulnBOLAExposed = resBOLA_Vuln.status === 200 && dataBOLA_Vuln.ownerId === 'user_bob';
    record(
      'CWE-639 BOLA',
      'Vulnerable mode allows cross-tenant invoice access',
      vulnBOLAExposed,
      `Status: ${resBOLA_Vuln.status}, Leaked Invoice #103 Owner: ${dataBOLA_Vuln.ownerId}, TaxId: ${dataBOLA_Vuln.taxId}`
    );

    // Scenario 1B: Secure Mode - Alice attempts to access Bob's invoice (#103)
    const resBOLA_Sec = await fetch(`${baseUrl}/api/invoices/103`, {
      headers: {
        'Authorization': `Bearer ${aliceToken}`,
        'x-security-mode': 'secure',
      },
    });
    const dataBOLA_Sec = (await resBOLA_Sec.json()) as any;
    const secBOLABlocked = (resBOLA_Sec.status === 403 || resBOLA_Sec.status === 404) && dataBOLA_Sec.code === 'BOLA_BLOCKED';
    record(
      'CWE-639 BOLA',
      'Secure mode rejects cross-tenant invoice access',
      secBOLABlocked,
      `Status: ${resBOLA_Sec.status}, Code: ${dataBOLA_Sec.code}, Error: ${dataBOLA_Sec.error}`
    );

    // Scenario 1C: Secure Mode - Alice accesses Alice's legitimate invoice (#101)
    const resBOLA_Legit = await fetch(`${baseUrl}/api/invoices/101`, {
      headers: {
        'Authorization': `Bearer ${aliceToken}`,
        'x-security-mode': 'secure',
      },
    });
    const dataBOLA_Legit = (await resBOLA_Legit.json()) as any;
    const secLegitAllowed = resBOLA_Legit.status === 200 && dataBOLA_Legit.ownerId === 'user_alice';
    record(
      'CWE-639 BOLA',
      'Secure mode allows legitimate resource owner access',
      secLegitAllowed,
      `Status: ${resBOLA_Legit.status}, Invoice #101 Amount: $${dataBOLA_Legit.amount}`
    );

    console.log();

    // -------------------------------------------------------------------------
    // TEST SUITE 2: CWE-89 SQL Injection (SQLi)
    // -------------------------------------------------------------------------
    console.log('--- [SUITE 2: CWE-89 SQL Injection Verification] ---');

    // Injection payload: Breaks out of LIKE query and appends OR '1'='1
    const sqliPayload = "%' OR '1'='1";

    // Scenario 2A: Vulnerable Mode - Alice searches with SQLi payload
    const resSQLi_Vuln = await fetch(
      `${baseUrl}/api/invoices/search?client=${encodeURIComponent(sqliPayload)}`,
      {
        headers: {
          'Authorization': `Bearer ${aliceToken}`,
          'x-security-mode': 'vulnerable',
        },
      }
    );
    const dataSQLi_Vuln = (await resSQLi_Vuln.json()) as any;
    const hasBobInvoiceInVuln =
      dataSQLi_Vuln.invoices &&
      dataSQLi_Vuln.invoices.some((inv: any) => inv.ownerId === 'user_bob');
    record(
      'CWE-89 SQLi',
      'Vulnerable mode executes raw string interpolation and leaks cross-tenant records',
      resSQLi_Vuln.status === 200 && hasBobInvoiceInVuln,
      `Returned ${dataSQLi_Vuln.count} invoices across all tenants (Bob invoice leaked: ${hasBobInvoiceInVuln})`
    );

    // Scenario 2B: Secure Mode - Alice searches with the same SQLi payload
    const resSQLi_Sec = await fetch(
      `${baseUrl}/api/invoices/search?client=${encodeURIComponent(sqliPayload)}`,
      {
        headers: {
          'Authorization': `Bearer ${aliceToken}`,
          'x-security-mode': 'secure',
        },
      }
    );
    const dataSQLi_Sec = (await resSQLi_Sec.json()) as any;
    const bobLeakedInSec =
      dataSQLi_Sec.invoices &&
      dataSQLi_Sec.invoices.some((inv: any) => inv.ownerId === 'user_bob');
    const sqliNeutralized = resSQLi_Sec.status === 200 && !bobLeakedInSec;
    record(
      'CWE-89 SQLi',
      'Secure mode parameterizes query and enforces tenant isolation',
      sqliNeutralized,
      `Returned ${dataSQLi_Sec.count} invoices (Bob invoice leaked: ${bobLeakedInSec}). Payload treated as literal scalar.`
    );

    console.log();

    // -------------------------------------------------------------------------
    // TEST SUITE 3: CWE-918 Server-Side Request Forgery (SSRF)
    // -------------------------------------------------------------------------
    console.log('--- [SUITE 3: CWE-918 Server-Side Request Forgery Verification] ---');

    // Scenario 3A: Secure Mode - Blocks Insecure HTTP Scheme & Loopback (http://127.0.0.1)
    const resSSRF_Loopback = await fetch(`${baseUrl}/api/webhooks/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-security-mode': 'secure',
      },
      body: JSON.stringify({ targetUrl: 'http://127.0.0.1:4000/api/health' }),
    });
    const dataSSRF_Loopback = (await resSSRF_Loopback.json()) as any;
    const loopbackBlocked = resSSRF_Loopback.status === 400 && dataSSRF_Loopback.code === 'PROTOCOL_DISALLOWED';
    record(
      'CWE-918 SSRF',
      'Blocks insecure HTTP scheme and loopback (http://127.0.0.1)',
      loopbackBlocked,
      `Status: ${resSSRF_Loopback.status}, Code: ${dataSSRF_Loopback.code}, Reason: ${dataSSRF_Loopback.error}`
    );

    // Scenario 3B: Secure Mode - Blocks Cloud Metadata Service (169.254.169.254)
    const resSSRF_Metadata = await fetch(`${baseUrl}/api/webhooks/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-security-mode': 'secure',
      },
      body: JSON.stringify({ targetUrl: 'http://169.254.169.254/latest/meta-data/' }),
    });
    const dataSSRF_Metadata = (await resSSRF_Metadata.json()) as any;
    const metadataBlocked = resSSRF_Metadata.status === 400;
    record(
      'CWE-918 SSRF',
      'Blocks link-local cloud metadata service (169.254.169.254)',
      metadataBlocked,
      `Status: ${resSSRF_Metadata.status}, Code: ${dataSSRF_Metadata.code}`
    );

    // Scenario 3C: Secure Mode - Direct Unit Validation of RFC 1918 Private IP (https://10.0.0.1)
    const ssrfCheckRFC1918 = await validateUrlForSSRF('https://10.0.0.1/internal/admin');
    const rfc1918Blocked = !ssrfCheckRFC1918.valid && ssrfCheckRFC1918.code === 'SSRF_PROHIBITED_IP';
    record(
      'CWE-918 SSRF',
      'Blocks RFC 1918 Private IP address (10.0.0.1) via SSRF Guard',
      rfc1918Blocked,
      `Valid: ${ssrfCheckRFC1918.valid}, Code: ${ssrfCheckRFC1918.code}, Error: ${ssrfCheckRFC1918.error}`
    );

    // Scenario 3D: Secure Mode - Direct Unit Validation of IPv6 Loopback (https://[::1])
    const ssrfCheckIPv6 = await validateUrlForSSRF('https://[::1]/secret');
    const ipv6Blocked = !ssrfCheckIPv6.valid && ssrfCheckIPv6.code === 'SSRF_PROHIBITED_IP';
    record(
      'CWE-918 SSRF',
      'Blocks IPv6 Loopback address (::1) via SSRF Guard',
      ipv6Blocked,
      `Valid: ${ssrfCheckIPv6.valid}, Code: ${ssrfCheckIPv6.code}, Error: ${ssrfCheckIPv6.error}`
    );

    // Scenario 3E: Secure Mode - Legitimate Public Webhook Validation (https://example.com)
    const ssrfCheckPublic = await validateUrlForSSRF('https://example.com/webhook');
    record(
      'CWE-918 SSRF',
      'Permits legitimate public HTTPS webhook endpoint',
      ssrfCheckPublic.valid,
      `Valid: ${ssrfCheckPublic.valid}, Resolved IPs: ${ssrfCheckPublic.resolvedIps?.join(', ')}`
    );

    console.log();

    // -------------------------------------------------------------------------
    // SUMMARY
    // -------------------------------------------------------------------------
    const total = results.length;
    const passed = results.filter((r) => r.passed).length;
    const failed = total - passed;

    console.log('======================================================================');
    console.log(`📊 Verification Complete: ${passed}/${total} Checks Passed (${failed} Failures)`);
    console.log('======================================================================');

    if (failed > 0) {
      console.error('\n❌ Suite Failed with regressions.');
      process.exit(1);
    } else {
      console.log('\n✨ All security controls and regression tests passed successfully!');
    }
  } finally {
    server.close();
    await prisma.$disconnect();
  }
}

runVerificationSuite().catch((err) => {
  console.error('Fatal Suite Error:', err);
  process.exit(1);
});
